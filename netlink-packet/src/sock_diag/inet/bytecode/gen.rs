use std::mem;
use std::net::IpAddr;

use crate::sock_diag::inet::{
    bytecode::{
        ast::{CompOp, Dir, Expr, Expr::*, LogicalOp, UnaryOp},
        buffer::*,
    },
    raw::{byte_code::*, inet_diag_hostcond},
};
use crate::{
    constants::{AF_INET, AF_INET6},
    Emitable,
};

impl Emitable for Expr {
    fn buffer_len(&self) -> usize {
        match self {
            Auto => BC_OP_MIN_SIZE,
            IfIndex(_) => BC_OP_MIN_SIZE + mem::size_of::<u32>(),
            Mark(..) => BC_OP_MIN_SIZE + mem::size_of::<[u32; 2]>(),
            Port(..) => BC_OP_MIN_SIZE * 2,
            Addr(_, addr, _, _) => {
                BC_OP_MIN_SIZE
                    + mem::size_of::<inet_diag_hostcond>()
                    + match addr {
                        IpAddr::V4(_) => IPV4_ADDR_LEN,
                        IpAddr::V6(_) => IPV6_ADDR_LEN,
                    }
            }
            Unary(UnaryOp::Not, node) => node.buffer_len() + BC_OP_MIN_SIZE,
            Logical(lhs, LogicalOp::Or, rhs) => {
                lhs.buffer_len() + BC_OP_MIN_SIZE + rhs.buffer_len()
            }
            Logical(lhs, LogicalOp::And, rhs) => lhs.buffer_len() + rhs.buffer_len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        debug_assert!(buffer.len() >= self.buffer_len());

        let mut buf = ByteCodeBuffer::new(buffer);

        match self {
            Auto => {
                buf.set_code(INET_DIAG_BC_AUTO);
            }
            IfIndex(n) => {
                buf.set_code(INET_DIAG_BC_DEV_COND);
                buf.set_ifindex(*n);
            }
            Mark(mark, mask) => {
                buf.set_code(INET_DIAG_BC_MARK_COND);

                let mut cond = buf.mark_cond_mut();

                cond.set_mark(*mark);
                cond.set_mask(mask.unwrap_or(u32::max_value()));
            }
            Port(dir, op, port) => {
                buf.set_code(match (dir, op) {
                    (Dir::Src, CompOp::Eq) => INET_DIAG_BC_S_EQ,
                    (Dir::Src, CompOp::Ge) => INET_DIAG_BC_S_GE,
                    (Dir::Src, CompOp::Le) => INET_DIAG_BC_S_LE,
                    (Dir::Dst, CompOp::Eq) => INET_DIAG_BC_D_EQ,
                    (Dir::Dst, CompOp::Ge) => INET_DIAG_BC_D_GE,
                    (Dir::Dst, CompOp::Le) => INET_DIAG_BC_D_LE,
                });
                buf.set_port(*port);
            }
            Addr(dir, addr, prefix_len, port) => {
                buf.set_code(match dir {
                    Dir::Src => INET_DIAG_BC_S_COND,
                    Dir::Dst => INET_DIAG_BC_D_COND,
                });

                let mut host_cond = buf.host_cond_mut();

                match addr {
                    IpAddr::V4(_) => {
                        host_cond.set_family(AF_INET as u8);
                        host_cond.set_prefix_len(prefix_len.unwrap_or(IPV4_ADDR_LEN as u8 * 8));
                    }
                    IpAddr::V6(_) => {
                        host_cond.set_family(AF_INET6 as u8);
                        host_cond.set_prefix_len(prefix_len.unwrap_or(IPV6_ADDR_LEN as u8 * 8))
                    }
                }
                host_cond.set_port(port.unwrap_or(u16::max_value()));
                host_cond.set_addr(addr);
            }
            Unary(UnaryOp::Not, node) => {
                let buffer = buf.into_inner();

                let (left, right) = buffer.split_at_mut(node.buffer_len());

                node.emit(left);

                ByteCodeBuffer::new(right).set_jump(BC_OP_MIN_SIZE as u16);

                return;
            }
            Logical(lhs, LogicalOp::Or, rhs) => {
                let buffer = buf.into_inner();

                let (left, right) = buffer.split_at_mut(lhs.buffer_len());

                lhs.emit(left);

                let (left, right) = right.split_at_mut(BC_OP_MIN_SIZE);

                ByteCodeBuffer::new(left).set_jump(rhs.buffer_len() as u16);
                rhs.emit(right);

                return;
            }
            Logical(lhs, LogicalOp::And, rhs) => {
                let buffer = buf.into_inner();

                let lhs_len = lhs.buffer_len();
                let rhs_len = rhs.buffer_len();

                let (left, right) = buffer.split_at_mut(lhs_len);

                lhs.emit(left);
                rhs.emit(right);

                let mut buf = ByteCodeBuffer::new(left);
                let reloc = rhs_len as u16;

                // Relocate external jumps by reloc.
                while !buf.is_empty() {
                    if buf.no() as usize == lhs_len + BC_OP_MIN_SIZE {
                        buf.set_no(buf.no() + reloc)
                    }

                    let off = buf.yes() as usize;

                    if off > buf.len() {
                        break;
                    }

                    let (_, buffer) = buf.into_inner().split_at_mut(off);

                    buf = ByteCodeBuffer::new(buffer);
                }

                return;
            }
        }

        let len = self.buffer_len();

        buf.set_yes(len as u8);
        buf.set_no((len + BC_OP_MIN_SIZE) as u16);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::sock_diag::inet::{
        bytecode::{
            ast::{CompOp::*, Dir::*, Expr::*, LogicalOp::*, UnaryOp::*},
            buffer::*,
        },
        raw::{byte_code::*, inet_diag_bc_op},
    };
    use crate::{
        constants::{AF_INET, AF_INET6},
        Emitable,
    };

    trait Emitted {
        fn emitted(&self) -> ByteCodeBuffer<Vec<u8>>;
    }

    impl<T: Emitable> Emitted for T {
        fn emitted(&self) -> ByteCodeBuffer<Vec<u8>> {
            let mut buf = vec![0; self.buffer_len()];

            self.emit(buf.as_mut_slice());

            ByteCodeBuffer::new(buf)
        }
    }

    macro_rules! op {
        ($code:expr, $yes:expr, $no:expr) => {
            inet_diag_bc_op {
                code: $code as u8,
                yes: $yes,
                no: $no,
            }
        };
    }

    #[test]
    fn simple() {
        assert_eq!(Auto.buffer_len(), BC_OP_MIN_SIZE);
        assert_eq!(
            unsafe { *Auto.emitted().as_raw().as_ref() },
            op!(INET_DIAG_BC_AUTO, 4, 8)
        );
    }

    #[test]
    fn ifindex() {
        let dev = IfIndex(2);
        assert_eq!(dev.buffer_len(), BC_OP_MIN_SIZE + 4);

        let buf = dev.emitted();
        assert_eq!(buf.ifindex(), 2);
        assert_eq!(
            unsafe { *buf.as_raw().as_ref() },
            op!(INET_DIAG_BC_DEV_COND, 8, 12)
        );
    }

    #[test]
    fn mark() {
        let mark = Mark(7, Some(0xF));
        assert_eq!(mark.buffer_len(), BC_OP_MIN_SIZE + 8);

        let buf = mark.emitted();
        assert_eq!(buf.mark_cond().mark(), 7);
        assert_eq!(buf.mark_cond().mask(), 15);
        assert_eq!(
            unsafe { *buf.as_raw().as_ref() },
            op!(INET_DIAG_BC_MARK_COND, 12, 16)
        );
    }

    #[test]
    fn port() {
        let port = Port(Src, Eq, 80);
        assert_eq!(port.buffer_len(), BC_OP_MIN_SIZE * 2);

        let buf = port.emitted();
        assert_eq!(buf.port(), 80);
        assert_eq!(
            unsafe { *buf.as_raw().as_ref() },
            op!(INET_DIAG_BC_S_EQ, 8, 12)
        );
    }

    #[test]
    fn ipv4_addr() {
        let addr = Addr(Src, Ipv4Addr::LOCALHOST.into(), None, Some(80));
        assert_eq!(
            addr.buffer_len(),
            BC_OP_MIN_SIZE + HOSTCOND_SIZE + IPV4_ADDR_LEN
        );

        let buf = addr.emitted();
        assert_eq!(
            unsafe { *buf.as_raw().as_ref() },
            op!(INET_DIAG_BC_S_COND, 16, 20)
        );

        let host = buf.host_cond();
        assert_eq!(host.family(), AF_INET as u8);
        assert_eq!(host.prefix_len(), 32);
        assert_eq!(host.port(), 80);
        assert_eq!(host.addr(), Some(Ipv4Addr::LOCALHOST.into()));
    }

    #[test]
    fn ipv6_addr() {
        let addr = Addr(Src, Ipv6Addr::LOCALHOST.into(), None, Some(443));
        assert_eq!(
            addr.buffer_len(),
            BC_OP_MIN_SIZE + HOSTCOND_SIZE + IPV6_ADDR_LEN
        );

        let buf = addr.emitted();
        assert_eq!(
            unsafe { *buf.as_raw().as_ref() },
            op!(INET_DIAG_BC_S_COND, 28, 32)
        );

        let host = buf.host_cond();
        assert_eq!(host.family(), AF_INET6 as u8);
        assert_eq!(host.prefix_len(), 128);
        assert_eq!(host.port(), 443);
        assert_eq!(host.addr(), Some(Ipv6Addr::LOCALHOST.into()));
    }

    #[test]
    fn not() {
        let not = Unary(Not, Box::new(Port(Src, Eq, 80)));
        assert_eq!(not.buffer_len(), BC_OP_MIN_SIZE * 3);

        let buf = not.emitted();
        assert_eq!(buf.port(), 80);

        assert_eq!(
            ByteCodeIter::new(buf.as_slice())
                .map(|buf| unsafe { buf.as_raw().as_ptr().read() })
                .collect::<Vec<_>>(),
            vec![op!(INET_DIAG_BC_S_EQ, 8, 12), op!(INET_DIAG_BC_JMP, 4, 8)]
        );
    }

    #[test]
    fn or() {
        let or = Logical(
            Box::new(Port(Dst, Eq, 80)),
            Or,
            Box::new(Port(Dst, Eq, 443)),
        );
        assert_eq!(or.buffer_len(), BC_OP_MIN_SIZE * 5);

        let buf = or.emitted();

        assert_eq!(
            ByteCodeIter::new(buf.as_slice())
                .map(|buf| unsafe { buf.as_raw().as_ptr().read() })
                .collect::<Vec<_>>(),
            vec![
                op!(INET_DIAG_BC_D_EQ, 8, 12),
                op!(INET_DIAG_BC_JMP, 4, 12),
                op!(INET_DIAG_BC_D_EQ, 8, 12)
            ]
        );
    }

    #[test]
    fn and() {
        let and = Logical(
            Box::new(Port(Dst, Eq, 80)),
            And,
            Box::new(Port(Dst, Eq, 443)),
        );
        assert_eq!(and.buffer_len(), BC_OP_MIN_SIZE * 4);

        let buf = and.emitted();

        assert_eq!(
            ByteCodeIter::new(buf.as_slice())
                .map(|buf| unsafe { buf.as_raw().as_ptr().read() })
                .collect::<Vec<_>>(),
            vec![op!(INET_DIAG_BC_D_EQ, 8, 20), op!(INET_DIAG_BC_D_EQ, 8, 12)]
        );
    }
}

mod ast {
    use std::net::IpAddr;

    #[derive(Clone, Debug, PartialEq)]
    pub enum Node {
        Nop,
        Auto,
        Addr(Dir, IpAddr, Option<u8>, Option<u16>),
        Port(Dir, CompOp, u16),
        IfIndex(u32),
        Mark(u32, Option<u32>),
        Jump(u16),
        Unary(UnaryOp, Box<Node>),
        Logical(Box<Node>, LogicalOp, Box<Node>),
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Dir {
        Src,
        Dst,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum UnaryOp {
        Not,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum CompOp {
        Eq,
        Ge,
        Le,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum LogicalOp {
        And,
        Or,
    }
}

mod buffer {
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ops::Deref;
    use std::ptr::NonNull;

    use byteorder::{ByteOrder, NativeEndian};

    use crate::inet::raw::{
        byte_code, byte_code::*, inet_diag_bc_op, inet_diag_hostcond, inet_diag_markcond,
    };
    use crate::{
        constants::{AF_INET, AF_INET6},
        Field, Rest,
    };

    const BC_OP_CODE: usize = 0;
    const BC_OP_YES: usize = 1;
    const BC_OP_NO: Field = 2..4;
    const BC_OP_COND: Rest = BC_OP_NO.end..;
    pub const BC_OP_MIN_SIZE: usize = BC_OP_NO.end;

    const HOSTCOND_FAMILY: usize = 0;
    const HOSTCOND_PREFIX_LEN: usize = 1;
    const HOSTCOND_PORT: Field = 4..8;
    const HOSTCOND_ADDR: Rest = HOSTCOND_PORT.end..;
    pub const HOSTCOND_SIZE: usize = HOSTCOND_PORT.end;

    pub const IPV4_ADDR_LEN: usize = 4;
    pub const IPV6_ADDR_LEN: usize = 16;

    const MARKCOND_MARK: Field = 0..4;
    const MARKCOND_MASK: Field = 4..8;
    pub const MARKCOND_SIZE: usize = MARKCOND_MASK.end;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct ByteCodeBuffer<T> {
        buf: T,
    }

    impl<T> Deref for ByteCodeBuffer<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            &self.buf
        }
    }

    impl<T> ByteCodeBuffer<T> {
        pub fn new(buf: T) -> Self {
            Self { buf }
        }

        pub fn into_inner(self) -> T {
            self.buf
        }
    }

    impl<T: AsRef<[u8]>> ByteCodeBuffer<T> {
        pub fn as_raw(&self) -> NonNull<inet_diag_bc_op> {
            let data = self.buf.as_ref();
            debug_assert!(data.len() >= mem::size_of::<inet_diag_bc_op>());
            unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
        }

        pub fn code(&self) -> u8 {
            let data = self.buf.as_ref();
            data[BC_OP_CODE]
        }

        pub fn yes(&self) -> u8 {
            let data = self.buf.as_ref();
            data[BC_OP_YES]
        }

        pub fn no(&self) -> u16 {
            let data = self.buf.as_ref();
            NativeEndian::read_u16(&data[BC_OP_NO])
        }

        pub fn cond(&self) -> &[u8] {
            let data = self.buf.as_ref();
            &data[BC_OP_COND]
        }

        pub fn ifindex(&self) -> u32 {
            NativeEndian::read_u32(self.cond())
        }

        pub fn port(&self) -> u16 {
            ByteCodeBuffer::new(self.cond()).no()
        }

        pub fn host_cond(&self) -> HostCondBuffer<&[u8]> {
            HostCondBuffer { buf: self.cond() }
        }

        pub fn mark_cond(&self) -> MarkCondBuffer<&[u8]> {
            MarkCondBuffer { buf: self.cond() }
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> ByteCodeBuffer<T> {
        pub fn set_code(&mut self, code: byte_code) {
            let data = self.buf.as_mut();
            data[BC_OP_CODE] = code as u8;
        }

        pub fn set_yes(&mut self, yes: u8) {
            let data = self.buf.as_mut();
            data[BC_OP_YES] = yes;
        }

        pub fn set_no(&mut self, no: u16) {
            let data = self.buf.as_mut();
            NativeEndian::write_u16(&mut data[BC_OP_NO], no);
        }

        pub fn cond_mut(&mut self) -> &mut [u8] {
            let data = self.buf.as_mut();
            &mut data[BC_OP_COND]
        }

        pub fn set_ifindex(&mut self, ifindex: u32) {
            NativeEndian::write_u32(self.cond_mut(), ifindex);
        }

        pub fn set_port(&mut self, port: u16) {
            let mut buf = ByteCodeBuffer::new(self.cond_mut());
            buf.set_code(INET_DIAG_BC_NOP);
            buf.set_yes(0);
            buf.set_no(port);
        }

        pub fn host_cond_mut(&mut self) -> HostCondBuffer<&mut [u8]> {
            HostCondBuffer {
                buf: self.cond_mut(),
            }
        }

        pub fn mark_cond_mut(&mut self) -> MarkCondBuffer<&mut [u8]> {
            MarkCondBuffer {
                buf: self.cond_mut(),
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct HostCondBuffer<T> {
        buf: T,
    }

    impl<T: AsRef<[u8]>> HostCondBuffer<T> {
        pub fn as_raw(&self) -> NonNull<inet_diag_hostcond> {
            let data = self.buf.as_ref();
            debug_assert!(data.len() >= mem::size_of::<inet_diag_hostcond>());
            unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
        }

        pub fn family(&self) -> u8 {
            let data = self.buf.as_ref();
            data[HOSTCOND_FAMILY]
        }
        pub fn prefix_len(&self) -> u8 {
            let data = self.buf.as_ref();
            data[HOSTCOND_PREFIX_LEN]
        }
        pub fn port(&self) -> u32 {
            let data = self.buf.as_ref();
            NativeEndian::read_u32(&data[HOSTCOND_PORT])
        }
        pub fn addr(&self) -> Option<IpAddr> {
            let data = self.buf.as_ref();
            let data = &data[HOSTCOND_ADDR];

            match u16::from(self.family()) {
                AF_INET if data.len() >= IPV4_ADDR_LEN => {
                    let mut octets = [0; IPV4_ADDR_LEN];
                    octets.copy_from_slice(&data[..IPV4_ADDR_LEN]);
                    Some(Ipv4Addr::from(octets).into())
                }
                AF_INET6 if data.len() >= IPV6_ADDR_LEN => {
                    let mut octets = [0; IPV6_ADDR_LEN];
                    octets.copy_from_slice(&data[..IPV6_ADDR_LEN]);
                    Some(Ipv6Addr::from(octets).into())
                }
                _ => None,
            }
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> HostCondBuffer<T> {
        pub fn set_family(&mut self, family: u8) {
            let data = self.buf.as_mut();
            data[HOSTCOND_FAMILY] = family;
        }
        pub fn set_prefix_len(&mut self, prefix_len: u8) {
            let data = self.buf.as_mut();
            data[HOSTCOND_PREFIX_LEN] = prefix_len;
        }
        pub fn set_port(&mut self, port: u16) {
            let data = self.buf.as_mut();
            NativeEndian::write_u32(&mut data[HOSTCOND_PORT], u32::from(port));
        }
        pub fn set_addr(&mut self, addr: &IpAddr) {
            let data = self.buf.as_mut();
            let data = &mut data[HOSTCOND_ADDR];

            match addr {
                IpAddr::V4(addr) => {
                    let data = &mut data[..IPV4_ADDR_LEN];
                    data.copy_from_slice(&addr.octets()[..]);
                }
                IpAddr::V6(addr) => {
                    let data = &mut data[..IPV6_ADDR_LEN];
                    data.copy_from_slice(&addr.octets()[..]);
                }
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct MarkCondBuffer<T> {
        buf: T,
    }

    impl<T: AsRef<[u8]>> MarkCondBuffer<T> {
        pub fn as_raw(&self) -> NonNull<inet_diag_markcond> {
            let data = self.buf.as_ref();
            debug_assert!(data.len() >= mem::size_of::<inet_diag_markcond>());
            unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
        }

        pub fn mark(&self) -> u32 {
            let data = self.buf.as_ref();
            NativeEndian::read_u32(&data[MARKCOND_MARK])
        }
        pub fn mask(&self) -> u32 {
            let data = self.buf.as_ref();
            NativeEndian::read_u32(&data[MARKCOND_MASK])
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> MarkCondBuffer<T> {
        pub fn set_mark(&mut self, mark: u32) {
            let data = self.buf.as_mut();
            NativeEndian::write_u32(&mut data[MARKCOND_MARK], mark);
        }
        pub fn set_mask(&mut self, mask: u32) {
            let data = self.buf.as_mut();
            NativeEndian::write_u32(&mut data[MARKCOND_MASK], mask);
        }
    }
}

mod gen {
    use std::mem;
    use std::net::IpAddr;

    use crate::sock_diag::inet::{
        bytecode::{
            ast::{CompOp, Dir, LogicalOp, Node, Node::*, UnaryOp},
            buffer::*,
        },
        raw::{byte_code::*, inet_diag_hostcond},
    };
    use crate::{
        constants::{AF_INET, AF_INET6},
        Emitable,
    };

    impl Emitable for Node {
        fn buffer_len(&self) -> usize {
            match self {
                Nop | Auto => BC_OP_MIN_SIZE,
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
                Jump(_) => BC_OP_MIN_SIZE,

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
            let mut offset = BC_OP_MIN_SIZE as u16;

            match self {
                Nop => {
                    buf.set_code(INET_DIAG_BC_NOP);
                }
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
                    host_cond.set_port(port.unwrap_or_default());
                    host_cond.set_addr(addr);
                }
                Jump(off) => {
                    buf.set_code(INET_DIAG_BC_JMP);

                    offset = *off;
                }

                Unary(UnaryOp::Not, node) => {
                    let buffer = buf.into_inner();

                    let (left, right) = buffer.split_at_mut(node.buffer_len());

                    node.emit(left);
                    Jump(BC_OP_MIN_SIZE as u16).emit(right);

                    return;
                }
                Logical(lhs, LogicalOp::Or, rhs) => {
                    let buffer = buf.into_inner();

                    let (left, right) = buffer.split_at_mut(lhs.buffer_len());

                    lhs.emit(left);

                    let jmp = Jump(rhs.buffer_len() as u16);
                    let (left, right) = right.split_at_mut(jmp.buffer_len());

                    jmp.emit(left);
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
            buf.set_no(len as u16 + offset);
        }
    }

    #[cfg(test)]
    mod tests {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use crate::sock_diag::inet::{
            bytecode::{
                ast::{CompOp::*, Dir::*, Node::*},
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
            assert_eq!(Nop.buffer_len(), BC_OP_MIN_SIZE);
            assert_eq!(
                unsafe { *Nop.emitted().as_raw().as_ref() },
                op!(INET_DIAG_BC_NOP, 4, 8)
            );

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
    }
}

mod parse {
    use std::ffi::CStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ops::Deref;
    use std::ptr;
    use std::str::FromStr;

    use nom::{types::CompleteStr, *};

    use super::ast::{
        CompOp::*, Dir, Dir::*, LogicalOp, LogicalOp::*, Node, Node::*, UnaryOp, UnaryOp::*,
    };

    named!(expr<CompleteStr, Node>, call!(logical));

    named!(expr1<CompleteStr, Node>, alt_complete!(
        addr |
        port |
        nop |
        auto |
        ifindex |
        mark |
        parens |
        unary
    ));

    named!(parens<CompleteStr, Node>, delimited!(
        delimited!(multispace0, tag!("("), multispace0),
        expr,
        delimited!(multispace0, tag!(")"), multispace0)
    ));

    named!(unary<CompleteStr, Node>, do_parse!(
        op: unary_op >> multispace0 >>
        operand: expr >>
        (
            Unary(op, Box::new(operand))
        )
    ));

    named!(unary_op<CompleteStr, UnaryOp>, alt_complete!(not));
    named!(not<CompleteStr, UnaryOp>, map!(alt_complete!(tag!("!") | tag!("not")), |_| Not));

    named!(comp_op<CompleteStr, &str>, alt_complete!(eq | ne | ge | le | gt | lt));
    named!(eq<CompleteStr, &str>, map!(alt_complete!(tag!("==") | tag!("=") | tag!("eq")), |_| "=="));
    named!(ne<CompleteStr, &str>, map!(alt_complete!(tag!("!=") | tag!("ne") | tag!("neq")), |_| "!="));
    named!(ge<CompleteStr, &str>, map!(alt_complete!(tag!(">=") | tag!("ge") | tag!("geq")), |_| ">="));
    named!(le<CompleteStr, &str>, map!(alt_complete!(tag!("<=") | tag!("le") | tag!("leq")), |_| "<="));
    named!(gt<CompleteStr, &str>, map!(alt_complete!(tag!(">") | tag!("gt")), |_| ">"));
    named!(lt<CompleteStr, &str>, map!(alt_complete!(tag!("<") | tag!("lt")), |_| "<"));

    named!(logical<CompleteStr, Node>, do_parse!(
        initial: expr1 >>
        remainder: many0!(
            pair!(delimited!(multispace0, logical_op, multispace0), expr)
        ) >>
        (
            remainder.into_iter().fold(initial, |lhs, (op, rhs)| Logical(Box::new(lhs), op, Box::new(rhs)))
        )
    ));

    named!(logical_op<CompleteStr, LogicalOp>, alt_complete!(and | or));
    named!(and<CompleteStr, LogicalOp>, map!(alt_complete!(tag!("and") | tag!("&&") | tag!("&")), |_| And));
    named!(or<CompleteStr, LogicalOp>, map!(alt_complete!(tag!("or") | tag!("||") | tag!("|")), |_| Or));

    named!(addr<CompleteStr, Node>, do_parse!(
        dir: addr_dir >> multispace >>
        cidr: alt_complete!(
            delimited!(tag!("["), cidr, tag!("]")) |
            cidr
        ) >>
        port: opt!(map!(preceded!(tag!(":"), num), |n| n as u16)) >>
        (
            dir.map_or_else(|| {
                Logical(
                    Box::new(Node::Addr(Src, cidr.0, cidr.1, port)),
                    Or,
                    Box::new(Node::Addr(Dst, cidr.0, cidr.1, port)),
                )
            }, |dir|Node::Addr(dir, cidr.0, cidr.1, port))
        )
    ));
    named!(addr_dir<CompleteStr, Option<Dir>>, alt_complete!(
        tag!("addr")  => { |_| None } |
        tag!("saddr") => { |_| Some(Src) } |
        tag!("daddr") => { |_| Some(Dst) } |
        tag!("host")  => { |_| None } |
        tag!("net")   => { |_| None } |
        tuple!(tag!("src"), multispace, alt_complete!(tag!("host") | tag!("net"))) => { |_| Some(Src) } |
        tuple!(tag!("dst"), multispace, alt_complete!(tag!("host") | tag!("net"))) => { |_| Some(Dst) }
    ));
    named!(cidr<CompleteStr, (IpAddr, Option<u8>)>, pair!(
        ip_addr, opt!(map!(preceded!(tag!("/"), num), |n| n as u8))
    ));
    named!(ip_addr<CompleteStr, IpAddr>,
        alt_complete!(
            map!(ipv4_addr, IpAddr::V4) |
            map!(ipv6_addr, IpAddr::V6)
        )
    );
    named!(ipv4_addr<CompleteStr, Ipv4Addr>,
        map_res!(
            recognize!(tuple!(num, tag!("."), num, tag!("."), num, tag!("."), num)),
            |CompleteStr(s)| s.parse()
        )
    );
    named!(ipv6_addr<CompleteStr, Ipv6Addr>,
        map_res!(
            alt_complete!(
                recognize!(tuple!(
                    opt!(tag!("::")),
                    separated_nonempty_list_complete!(
                        alt_complete!(tag!("::") | tag!(":") | tag!(".")),
                        ipv6_addr_part
                    ),
                    opt!(tag!("::"))
                )) |
                recognize!(pair!(tag!("::"), ipv6_addr_part)) |
                recognize!(pair!(ipv6_addr_part, tag!("::"))) |
                tag!("::")
            ),
            |CompleteStr(s)| Ipv6Addr::from_str(s)
        )
    );
    named!(ipv6_addr_part<CompleteStr, CompleteStr>, take_while_m_n!(1, 4, |c: char| c.is_digit(16)));

    named!(port<CompleteStr, Node>, do_parse!(
        dir: port_dir >> multispace >>
        op: opt!(terminated!(comp_op, multispace)) >>
        port: alt_complete!(map!(num, |n| n as u16) | map_opt!(name, resolve_servname)) >>
        (
            dir.map_or_else(|| {
                Logical(
                    Box::new(port_with_op(Src, op, port)),
                    Or,
                    Box::new(port_with_op(Dst, op, port))
                )
            }, |dir| port_with_op(dir, op, port))
        )
    ));
    fn port_with_op(dir: Dir, op: Option<&str>, port: u16) -> Node {
        match op.unwrap_or("==") {
            "==" => Port(dir, Eq, port),
            ">=" => Port(dir, Ge, port),
            "<=" => Port(dir, Le, port),
            "!=" => Unary(Not, Box::new(Port(dir, Eq, port))),
            ">" => Unary(Not, Box::new(Port(dir, Le, port))),
            "<" => Unary(Not, Box::new(Port(dir, Ge, port))),
            _ => unreachable!(),
        }
    }
    fn resolve_servname<'a, T: Deref<Target = &'a str> + 'a>(name: T) -> Option<u16> {
        let mut buf = name.as_bytes().to_vec();
        buf.push(0);
        CStr::from_bytes_with_nul(&buf)
            .ok()
            .map(|s| unsafe { libc::getservbyname(s.as_ptr(), ptr::null()) })
            .and_then(ptr::NonNull::new)
            .map(|servent| unsafe { (servent.as_ref().s_port as u16).to_be() })
    }
    named!(port_dir<CompleteStr, Option<Dir>>, alt_complete!(
        tag!("port")  => { |_| None } |
        tag!("sport") => { |_| Some(Src) } |
        tag!("dport") => { |_| Some(Dst) } |
        tuple!(tag!("src"), multispace, tag!("port")) => { |_| Some(Src) } |
        tuple!(tag!("dst"), multispace, tag!("port")) => { |_| Some(Dst) }
    ));

    named!(auto<CompleteStr, Node>, map!(alt_complete!(tag!("autobound") | tag!("auto")), |_| Auto));
    named!(nop<CompleteStr, Node>, map!(alt_complete!(tag!("nop") | tag!("()")), |_| Nop));
    named!(ifindex<CompleteStr, Node>, map!(
        alt_complete!(
            do_parse!(tag!("ifindex") >> multispace >> n: num >> (n)) |
            do_parse!(tag!("ifname") >> multispace >> n: map_opt!(name, resolve_ifname) >> (n)) |
            do_parse!(tag!("dev") >> multispace >> n: alt_complete!(num | map_opt!(name, resolve_ifname) ) >> (n))
        ),
        IfIndex
    ));
    fn resolve_ifname<'a, T: Deref<Target = &'a str> + 'a>(name: T) -> Option<u32> {
        pnet_datalink::interfaces()
            .into_iter()
            .find(|intf| intf.name == *name)
            .map(|intf| intf.index)
    }
    named!(mark<CompleteStr, Node>, do_parse!(
        alt_complete!(tag!("fwmark") | tag!("mark")) >> multispace >>
        mark: num >>
        mask: opt!(complete!(preceded!(tuple!(multispace0, tag!("/"), multispace0), num))) >>
        (
            Mark(mark, mask)
        )
    ));
    named!(name<CompleteStr, CompleteStr>, take_while_s!(char::is_alphanumeric));
    named!(num<CompleteStr, u32>, alt_complete!(
        map_res!(preceded!(tag!("0b"), take_while_s!(|c: char| c.is_digit(2))), |CompleteStr(s)| u32::from_str_radix(s, 2))  |
        map_res!(preceded!(tag!("0o"), take_while_s!(|c: char| c.is_digit(8))), |CompleteStr(s)| u32::from_str_radix(s, 8))  |
        map_res!(preceded!(tag!("0x"), take_while_s!(|c: char| c.is_digit(16))), |CompleteStr(s)| u32::from_str_radix(s, 16))  |
        map_res!(take_while_s!(|c: char| c.is_digit(10)), |CompleteStr(s)| u32::from_str_radix(s, 10))
    ));

    #[cfg(test)]
    mod tests {
        use super::*;

        use matches::assert_matches;

        const EMPTY: CompleteStr = CompleteStr("");

        #[test]
        fn parse_num() {
            assert_eq!(num(CompleteStr("0b0101")), Ok((EMPTY, 0b0101)));
            assert_eq!(num(CompleteStr("0o777")), Ok((EMPTY, 0o777)));
            assert_eq!(num(CompleteStr("0x01FF")), Ok((EMPTY, 0x01FF)));
            assert_eq!(num(CompleteStr("123")), Ok((EMPTY, 123)));
        }

        #[test]
        fn parse_cond() {
            assert_eq!(auto(CompleteStr("autobound")), Ok((EMPTY, Auto)));
            assert_eq!(auto(CompleteStr("auto")), Ok((EMPTY, Auto)));

            assert_eq!(nop(CompleteStr("nop")), Ok((EMPTY, Nop)));
            assert_eq!(nop(CompleteStr("()")), Ok((EMPTY, Nop)));

            assert_eq!(ifindex(CompleteStr("ifindex 2")), Ok((EMPTY, IfIndex(2))));
            assert_matches!(ifindex(CompleteStr("ifname lo")), Ok((EMPTY, IfIndex(_))));
            assert_eq!(ifindex(CompleteStr("dev 2")), Ok((EMPTY, IfIndex(2))));
            assert_matches!(ifindex(CompleteStr("dev lo")), Ok((EMPTY, IfIndex(_))));

            assert_eq!(mark(CompleteStr("mark 7")), Ok((EMPTY, Mark(7, None))));
            assert_eq!(
                mark(CompleteStr("fwmark 7/0xF")),
                Ok((EMPTY, Mark(7, Some(0xF))))
            );
        }

        #[test]
        fn parse_addr() {
            for addr in vec![
                "127.0.0.1",
                "::",
                "::1",
                "FF01::",
                "FF01::101",
                "2001:db8::1",
                "2001:0db8::0001",
                "::ffff:c000:0280",
                "::ffff:192.0.2.128",
                "2001:DB8::8:800:200C:417A",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            ] {
                assert_eq!(
                    ip_addr(CompleteStr(addr)),
                    Ok((EMPTY, addr.parse().unwrap())),
                    "parse address: {}",
                    addr
                );
            }

            for (expr, node) in vec![
                (
                    "addr 192.168.0.0/24",
                    Logical(
                        Box::new(Addr(
                            Src,
                            Ipv4Addr::new(192, 168, 0, 0).into(),
                            Some(24),
                            None,
                        )),
                        Or,
                        Box::new(Addr(
                            Dst,
                            Ipv4Addr::new(192, 168, 0, 0).into(),
                            Some(24),
                            None,
                        )),
                    ),
                ),
                (
                    "saddr 127.0.0.1:8080",
                    Addr(Src, Ipv4Addr::LOCALHOST.into(), None, Some(8080)),
                ),
                (
                    "daddr ::ffff:0:0/96",
                    Addr(Dst, "::ffff:0:0".parse().unwrap(), Some(96), None),
                ),
                (
                    "src host 127.0.0.1:8080",
                    Addr(Src, Ipv4Addr::LOCALHOST.into(), None, Some(8080)),
                ),
                (
                    "dst net ::ffff:0:0/96",
                    Addr(Dst, "::ffff:0:0".parse().unwrap(), Some(96), None),
                ),
                (
                    "src host [2001:db8:85a3:8d3:1319:8a2e:370:7348]:443",
                    Addr(
                        Src,
                        "2001:db8:85a3:8d3:1319:8a2e:370:7348".parse().unwrap(),
                        None,
                        Some(443),
                    ),
                ),
            ] {
                assert_eq!(
                    addr(CompleteStr(expr)),
                    Ok((EMPTY, node)),
                    "parse expr: {}",
                    expr
                );
            }
        }

        #[test]
        fn parse_port() {
            assert_eq!(
                port(CompleteStr("port http")),
                Ok((
                    EMPTY,
                    Logical(Box::new(Port(Src, Eq, 80)), Or, Box::new(Port(Dst, Eq, 80)))
                ))
            );
            assert_eq!(
                port(CompleteStr("sport == 80")),
                Ok((EMPTY, Port(Src, Eq, 80)))
            );
            assert_eq!(
                port(CompleteStr("src port >= 443")),
                Ok((EMPTY, Port(Src, Ge, 443)))
            );
            assert_eq!(
                port(CompleteStr("dport <= 8080")),
                Ok((EMPTY, Port(Dst, Le, 8080)))
            );
            assert_eq!(
                port(CompleteStr("sport != 443")),
                Ok((EMPTY, Unary(Not, Box::new(Port(Src, Eq, 443)))))
            );
            assert_eq!(
                port(CompleteStr("dport > 1000")),
                Ok((EMPTY, Unary(Not, Box::new(Port(Dst, Le, 1000)))))
            );
            assert_eq!(
                port(CompleteStr("dst port < 1000")),
                Ok((EMPTY, Unary(Not, Box::new(Port(Dst, Ge, 1000)))))
            );
        }

        #[test]
        fn parse_expr() {
            for (s, node) in vec![
                ("sport 80", Port(Src, Eq, 80)),
                ("(dport http)", Port(Dst, Eq, 80)),
                ("!(src port 80)", Unary(Not, Box::new(Port(Src, Eq, 80)))),
                (
                    "not dst port https",
                    Unary(Not, Box::new(Port(Dst, Eq, 443))),
                ),
                ("not (src port 80)", Unary(Not, Box::new(Port(Src, Eq, 80)))),
                (
                    "(dport 80) && (dport 8080)",
                    Logical(
                        Box::new(Port(Dst, Eq, 80)),
                        And,
                        Box::new(Port(Dst, Eq, 8080)),
                    ),
                ),
                (
                    "dport 80 and dport 8080",
                    Logical(
                        Box::new(Port(Dst, Eq, 80)),
                        And,
                        Box::new(Port(Dst, Eq, 8080)),
                    ),
                ),
                (
                    "dport 80 || dport 8080 || dport 443",
                    Logical(
                        Box::new(Port(Dst, Eq, 80)),
                        Or,
                        Box::new(Logical(
                            Box::new(Port(Dst, Eq, 8080)),
                            Or,
                            Box::new(Port(Dst, Eq, 443)),
                        )),
                    ),
                ),
                (
                    "daddr 127.0.0.1 and (dport 80 or dport 8080)",
                    Logical(
                        Box::new(Addr(Dst, Ipv4Addr::LOCALHOST.into(), None, None)),
                        And,
                        Box::new(Logical(
                            Box::new(Port(Dst, Eq, 80)),
                            Or,
                            Box::new(Port(Dst, Eq, 8080)),
                        )),
                    ),
                ),
                (
                    "(saddr 127.0.0.0/24 or saddr 10.0.0.0/8) and (sport 80 or sport 8080)",
                    Logical(
                        Box::new(Logical(
                            Box::new(Addr(
                                Src,
                                Ipv4Addr::new(127, 0, 0, 0).into(),
                                Some(24),
                                None,
                            )),
                            Or,
                            Box::new(Addr(Src, Ipv4Addr::new(10, 0, 0, 0).into(), Some(8), None)),
                        )),
                        And,
                        Box::new(Logical(
                            Box::new(Port(Src, Eq, 80)),
                            Or,
                            Box::new(Port(Src, Eq, 8080)),
                        )),
                    ),
                ),
            ] {
                assert_eq!(expr(CompleteStr(s)), Ok((EMPTY, node)), "parse expr: {}", s);
            }
        }
    }
}

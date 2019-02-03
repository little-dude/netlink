use std::net::IpAddr;

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

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Nop,
    Auto,
    Addr(Dir, IpAddr, Option<u8>, Option<u16>),
    Port(Dir, CompOp, u16),
    IfIndex(u32),
    Mark(u32, Option<u32>),
    Jump(u16),
    Unary(UnaryOp, Box<Expr>),
    Logical(Box<Expr>, LogicalOp, Box<Expr>),
}

mod display {
    use std::fmt;
    use std::net::IpAddr;

    use super::*;

    impl fmt::Display for Dir {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use Dir::*;

            match self {
                Src => "src",
                Dst => "dst",
            }
            .fmt(f)
        }
    }

    impl fmt::Display for UnaryOp {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                UnaryOp::Not => "!",
            }
            .fmt(f)
        }
    }

    impl fmt::Display for CompOp {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use CompOp::*;

            match self {
                Eq => "==",
                Ge => ">=",
                Le => "<=",
            }
            .fmt(f)
        }
    }

    impl fmt::Display for LogicalOp {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use LogicalOp::*;

            match self {
                And => "&&",
                Or => "||",
            }
            .fmt(f)
        }
    }

    impl fmt::Display for Expr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use Expr::*;

            match self {
                Nop => "nop".fmt(f),
                Auto => "autobound".fmt(f),
                Addr(dir, addr, prefix_len, port) => {
                    let with_ipv6_addr_and_port = if let IpAddr::V6(_) = addr {
                        port.is_some()
                    } else {
                        false
                    };
                    write!(
                        f,
                        "{} {} ",
                        dir,
                        if prefix_len.is_some() { "net" } else { "host" }
                    )?;
                    if with_ipv6_addr_and_port {
                        "[".fmt(f)?;
                    }
                    addr.fmt(f)?;
                    if let Some(prefix_len) = prefix_len {
                        write!(f, "/{}", prefix_len)?;
                    }
                    if with_ipv6_addr_and_port {
                        "]".fmt(f)?;
                    }
                    if let Some(port) = port {
                        write!(f, ":{}", port)
                    } else {
                        Ok(())
                    }
                }
                Port(dir, op, port) => write!(f, "{} port {} {}", dir, op, port),
                IfIndex(no) => write!(f, "ifindex {}", no),
                Mark(mark, mask) => {
                    if let Some(mask) = mask {
                        write!(f, "fwmark {}/{}", mark, mask)
                    } else {
                        write!(f, "fwmark {}", mark)
                    }
                }
                Jump(off) => write!(f, "jump {}", off),
                Unary(op, expr) => write!(f, "{} ({})", op, expr),
                Logical(lhs, op, rhs) => write!(f, "{} {} {}", lhs, op, rhs),
            }
        }
    }
}

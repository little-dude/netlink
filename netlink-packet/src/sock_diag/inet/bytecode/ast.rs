use std::net::IpAddr;

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

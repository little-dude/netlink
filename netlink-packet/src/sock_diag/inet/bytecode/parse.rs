use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::ptr;
use std::str::FromStr;

use failure::{format_err, ResultExt};
use nom::{types::CompleteStr, *};

use super::ast::{
    CompOp::*, Dir, Dir::*, Expr, Expr::*, LogicalOp, LogicalOp::*, UnaryOp, UnaryOp::*,
};

use crate::DecodeError;

impl FromStr for Expr {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rest, node) = expr(CompleteStr(s))
            .map_err(|err| format_err!("{}", err))
            .context("invalid expression")?;

        if rest.is_empty() {
            Ok(node)
        } else {
            Err(format!("unexpected expression, {}", rest).into())
        }
    }
}

named!(expr<CompleteStr, Expr>, call!(logical));

named!(expr1<CompleteStr, Expr>, alt_complete!(
        addr |
        port |
        auto |
        ifindex |
        mark |
        parens |
        unary
    ));

named!(parens<CompleteStr, Expr>, delimited!(
        delimited!(multispace0, tag!("("), multispace0),
        expr,
        delimited!(multispace0, tag!(")"), multispace0)
    ));

named!(unary<CompleteStr, Expr>, do_parse!(
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

named!(logical<CompleteStr, Expr>, do_parse!(
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

named!(addr<CompleteStr, Expr>, do_parse!(
        dir: addr_dir >> multispace >>
        cidr: alt_complete!(
            delimited!(tag!("["), cidr, tag!("]")) |
            cidr
        ) >>
        port: opt!(map!(preceded!(tag!(":"), num), |n| n as u16)) >>
        (
            dir.map_or_else(|| {
                Logical(
                    Box::new(Expr::Addr(Src, cidr.0, cidr.1, port)),
                    Or,
                    Box::new(Expr::Addr(Dst, cidr.0, cidr.1, port)),
                )
            }, |dir|Expr::Addr(dir, cidr.0, cidr.1, port))
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

named!(port<CompleteStr, Expr>, do_parse!(
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
fn port_with_op(dir: Dir, op: Option<&str>, port: u16) -> Expr {
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

named!(auto<CompleteStr, Expr>, map!(alt_complete!(tag!("autobound") | tag!("auto")), |_| Auto));
named!(ifindex<CompleteStr, Expr>, map!(
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
named!(mark<CompleteStr, Expr>, do_parse!(
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

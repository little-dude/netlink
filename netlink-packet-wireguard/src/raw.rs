use libc::{in6_addr, in_addr, sockaddr, sockaddr_in, sockaddr_in6, timespec, AF_INET, AF_INET6};
use netlink_packet_utils::DecodeError;
use std::{
    mem::size_of,
    mem::size_of_val,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    slice::from_raw_parts,
    time::{Duration, SystemTime},
};

pub fn emit_in_addr(addr: &Ipv4Addr, buf: &mut [u8]) {
    let caddr = in_addr {
        s_addr: u32::from(*addr).to_be(),
    };

    copy_raw_slice(buf, &caddr);
}

pub fn parse_in_addr(buf: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    if buf.len() != size_of::<in_addr>() {
        return Err(DecodeError::from("Invalid buffer length"));
    }

    let caddr: &in_addr = unsafe { from_raw_slice(buf)? };
    Ok(Ipv4Addr::from(u32::from_be(caddr.s_addr)))
}

pub fn emit_in6_addr(addr: &Ipv6Addr, buf: &mut [u8]) {
    let caddr = in6_addr {
        s6_addr: addr.octets(),
    };

    copy_raw_slice(buf, &caddr);
}

pub fn parse_in6_addr(buf: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    if buf.len() != size_of::<in6_addr>() {
        return Err(DecodeError::from("Invalid buffer length"));
    }

    let caddr: &in6_addr = unsafe { from_raw_slice(buf)? };
    Ok(Ipv6Addr::from(caddr.s6_addr))
}

pub fn emit_sockaddr_in(addr: &SocketAddrV4, buf: &mut [u8]) {
    let csockaddr = sockaddr_in {
        sin_family: AF_INET as u16,
        sin_port: addr.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from(*addr.ip()).to_be(),
        },
        sin_zero: [0u8; 8],
    };

    copy_raw_slice(buf, &csockaddr);
}

fn parse_sockaddr_in(buf: &[u8]) -> Result<SocketAddrV4, DecodeError> {
    let csockaddr: &sockaddr_in = unsafe { from_raw_slice(buf)? };

    let ipaddr = Ipv4Addr::from(u32::from_be(csockaddr.sin_addr.s_addr));
    Ok(SocketAddrV4::new(ipaddr, u16::from_be(csockaddr.sin_port)))
}

pub fn emit_sockaddr_in6(addr: &SocketAddrV6, buf: &mut [u8]) {
    let csockaddr = sockaddr_in6 {
        sin6_family: AF_INET6 as u16,
        sin6_port: addr.port().to_be(),
        sin6_flowinfo: addr.flowinfo(),
        sin6_addr: in6_addr {
            s6_addr: addr.ip().octets(),
        },
        sin6_scope_id: addr.scope_id(),
    };

    copy_raw_slice(buf, &csockaddr);
}

fn parse_sockaddr_in6(buf: &[u8]) -> Result<SocketAddrV6, DecodeError> {
    let csockaddr: &sockaddr_in6 = unsafe { from_raw_slice(buf)? };

    let ipaddr = Ipv6Addr::from(csockaddr.sin6_addr.s6_addr);
    Ok(SocketAddrV6::new(
        ipaddr,
        u16::from_be(csockaddr.sin6_port),
        csockaddr.sin6_flowinfo,
        csockaddr.sin6_scope_id,
    ))
}

pub fn parse_sockaddr(buf: &[u8]) -> Result<SocketAddr, DecodeError> {
    let csockaddr: &sockaddr = unsafe { from_raw_slice(buf)? };

    if csockaddr.sa_family == AF_INET as u16 {
        Ok(SocketAddr::V4(parse_sockaddr_in(buf)?))
    } else if csockaddr.sa_family == AF_INET6 as u16 {
        Ok(SocketAddr::V6(parse_sockaddr_in6(buf)?))
    } else {
        Err(DecodeError::from("Unknown address family"))
    }
}

pub fn emit_timespec(time: &SystemTime, buf: &mut [u8]) {
    let epoch_elapsed = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let ctimespec = timespec {
        tv_sec: epoch_elapsed.as_secs() as i64,
        tv_nsec: epoch_elapsed.subsec_nanos() as i64,
    };

    copy_raw_slice(buf, &ctimespec);
}

pub fn parse_timespec(buf: &[u8]) -> Result<SystemTime, DecodeError> {
    if buf.len() != size_of::<timespec>() {
        return Err(DecodeError::from("Invalid buffer length"));
    }

    let ctimespec: &timespec = unsafe { from_raw_slice(buf)? };
    let epoch_elapsed_s = Duration::from_secs(ctimespec.tv_sec as u64);
    let epoch_elapsed_ns = Duration::from_nanos(ctimespec.tv_nsec as u64);
    Ok(SystemTime::UNIX_EPOCH + epoch_elapsed_s + epoch_elapsed_ns)
}

fn copy_raw_slice<T: Sized>(dst: &mut [u8], src: &T) {
    let src_slice = unsafe { as_raw_slice(src) };
    dst[..size_of_val(src)].copy_from_slice(src_slice);
}

#[allow(unused_unsafe)] // For nested unsafe
unsafe fn from_raw_slice<'a, T: Sized>(src: &'a [u8]) -> Result<&'a T, DecodeError> {
    if src.len() < size_of::<T>() {
        return Err(DecodeError::from("Buffer too small"));
    }
    let buf = &src[..size_of::<T>()];
    let ptr = buf.as_ptr() as *const T;

    let data: &'a T = unsafe { &*ptr };
    Ok(data)
}

unsafe fn as_raw_slice<T: Sized>(src: &T) -> &[u8] {
    from_raw_parts((src as *const T) as *const u8, size_of::<T>())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;

    const SOCKADDR_IN_BYTES_1: &[u8] =
        b"\x02\x00\x1c\x7a\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"; // 127.0.0.1:7290
    const SOCKADDR_IN_BYTES_2: &[u8] =
        b"\x02\x00\xca\x6c\xc0\xa8\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00"; // 192.168.1.1:51820
    const SOCKADDR_IN6_BYTES_1: &[u8] =
        b"\x0a\x00\xca\x6c\x10\x00\x00\x00\xfe\x80\x00\x00\x00\x00\x00\x00\xe4\x58\x8e\xad\x89\xbb\x8e\x25\x03\x00\x00\x00";
    // fe80::e458:8ead:89bb:8e25%3:51820 (flow 16)

    #[test]
    fn test_parse_sockaddr_in_1() {
        let ipaddr = parse_sockaddr(&SOCKADDR_IN_BYTES_1).unwrap();
        assert_eq!(ipaddr, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7290).into());
    }

    #[test]
    fn test_parse_sockaddr_in_2() {
        let ipaddr = parse_sockaddr(&SOCKADDR_IN_BYTES_2).unwrap();
        assert_eq!(
            ipaddr,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into()
        );
    }

    #[test]
    fn test_parse_sockaddr_in6_1() {
        let ipaddr = parse_sockaddr(&SOCKADDR_IN6_BYTES_1).unwrap();
        assert_eq!(
            ipaddr,
            SocketAddrV6::new(
                Ipv6Addr::from_str("fe80::e458:8ead:89bb:8e25").unwrap(),
                51820,
                16,
                3
            )
            .into()
        );
    }
}

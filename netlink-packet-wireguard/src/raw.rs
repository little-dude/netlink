use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::{Duration, SystemTime},
};

use byteorder::{BigEndian, ByteOrder, NativeEndian};
use netlink_packet_utils::DecodeError;

use crate::constants::{AF_INET, AF_INET6};

pub const IPV4_LEN: usize = 4;
pub const IPV6_LEN: usize = 16;
pub const SOCKET_ADDR_V4_LEN: usize = 16;
pub const SOCKET_ADDR_V6_LEN: usize = 28;
pub const TIMESPEC_LEN: usize = 16;

/// Parse an IPv6 socket address, defined as:
/// ```c
/// struct sockaddr_in6 {
///     sa_family_t     sin6_family;   /* AF_INET6 */
///     in_port_t       sin6_port;     /* port number */
///     uint32_t        sin6_flowinfo; /* IPv6 flow information */
///     struct in6_addr sin6_addr;     /* IPv6 address */
///     uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
/// };
/// struct in6_addr {
///     unsigned char   s6_addr[16];   /* IPv6 address */
/// };
/// ```
/// `sockaddr_in6` is 4 bytes aligned (28 bytes) so there's no padding.
fn parse_socket_addr_v6(payload: &[u8]) -> SocketAddrV6 {
    assert_eq!(payload.len(), SOCKET_ADDR_V6_LEN);
    // We don't need the address family to build a SocketAddrv6
    // let address_family = NativeEndian::read_u16(&payload[..2]);
    let port = BigEndian::read_u16(&payload[2..4]);
    let flow_info = NativeEndian::read_u32(&payload[4..8]);
    // We know we have exactly 16 bytes so this won't fail
    let ip_bytes = <[u8; 16]>::try_from(&payload[8..24]).unwrap();
    let ip = Ipv6Addr::from(ip_bytes);
    let scope_id = NativeEndian::read_u32(&payload[24..28]);
    SocketAddrV6::new(ip, port, flow_info, scope_id)
}

/// Parse an IPv4 socket address, defined as:
/// ```c
/// #if  __UAPI_DEF_SOCKADDR_IN
/// #define __SOCK_SIZE__ 16 /* sizeof(struct sockaddr) */
/// struct sockaddr_in {
///   __kernel_sa_family_t sin_family; /* Address family   */
///   __be16               sin_port;   /* Port number      */
///   struct in_addr       sin_addr;   /* Internet address */
///   /* Pad to size of `struct sockaddr'. */
///   unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
/// };
fn parse_socket_addr_v4(payload: &[u8]) -> SocketAddrV4 {
    assert_eq!(payload.len(), 16);
    // We don't need the address family to build a SocketAddr4v
    // let address_family = NativeEndian::read_u16(&payload[..2]);
    let port = BigEndian::read_u16(&payload[2..4]);
    // We know we have exactly 4 bytes so this won't fail
    let ip_bytes = <[u8; 4]>::try_from(&payload[4..8]).unwrap();
    let ip = Ipv4Addr::from(ip_bytes);
    SocketAddrV4::new(ip, port)
}

pub fn parse_ip(payload: &[u8]) -> Result<IpAddr, DecodeError> {
    match payload.len() {
        IPV4_LEN => {
            // This won't fail since we ensure the slice is 4 bytes long
            let ip_bytes = <[u8; IPV4_LEN]>::try_from(payload).unwrap();
            Ok(IpAddr::V4(Ipv4Addr::from(ip_bytes)))
        }
        IPV6_LEN => {
            // This won't fail since we ensure the slice is 16 bytes long
            let ip_bytes = <[u8; IPV6_LEN]>::try_from(payload).unwrap();
            Ok(IpAddr::V6(Ipv6Addr::from(ip_bytes)))
        }
        _ => Err(DecodeError::from(format!(
            "invalid IP address: {:x?}",
            payload
        ))),
    }
}

pub fn emit_ip(addr: &IpAddr, buf: &mut [u8]) {
    match addr {
        IpAddr::V4(ip) => {
            (&mut buf[..IPV4_LEN]).copy_from_slice(ip.octets().as_slice());
        }
        IpAddr::V6(ip) => {
            (&mut buf[..IPV6_LEN]).copy_from_slice(ip.octets().as_slice());
        }
    }
}

/// Emit an IPv4 socket address in the given buffer. An IPv4 socket
/// address is defined as:
/// ```c
/// #if  __UAPI_DEF_SOCKADDR_IN
/// #define __SOCK_SIZE__ 16 /* sizeof(struct sockaddr) */
/// struct sockaddr_in {
///   __kernel_sa_family_t sin_family; /* Address family   */
///   __be16               sin_port;   /* Port number      */
///   struct in_addr       sin_addr;   /* Internet address */
///   /* Pad to size of `struct sockaddr'. */
///   unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) - sizeof(unsigned short int) - sizeof(struct in_addr)];
/// };
/// ```
/// Note that this adds 8 bytes of padding so the buffer must be large
/// enough to account for them.
fn emit_socket_addr_v4(addr: &SocketAddrV4, buf: &mut [u8]) {
    NativeEndian::write_u16(&mut buf[..2], AF_INET);
    BigEndian::write_u16(&mut buf[2..4], addr.port());
    (&mut buf[4..8]).copy_from_slice(addr.ip().octets().as_slice());
    // padding
    (&mut buf[8..16]).copy_from_slice([0; 8].as_slice());
}

/// Emit an IPv6 socket address.
///
/// An IPv6 socket address is defined as:
/// ```c
/// struct sockaddr_in6 {
///     sa_family_t     sin6_family;   /* AF_INET6 */
///     in_port_t       sin6_port;     /* port number */
///     uint32_t        sin6_flowinfo; /* IPv6 flow information */
///     struct in6_addr sin6_addr;     /* IPv6 address */
///     uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
/// };
/// struct in6_addr {
///     unsigned char   s6_addr[16];   /* IPv6 address */
/// };
/// ```
/// `sockaddr_in6` is 4 bytes aligned (28 bytes) so there's no padding.
fn emit_socket_addr_v6(addr: &SocketAddrV6, buf: &mut [u8]) {
    NativeEndian::write_u16(&mut buf[..2], AF_INET6);
    BigEndian::write_u16(&mut buf[2..4], addr.port());
    NativeEndian::write_u32(&mut buf[4..8], addr.flowinfo());
    (&mut buf[8..24]).copy_from_slice(addr.ip().octets().as_slice());
    NativeEndian::write_u32(&mut buf[24..28], addr.scope_id());
}

pub fn emit_socket_addr(addr: &SocketAddr, buf: &mut [u8]) {
    match addr {
        SocketAddr::V4(v4) => emit_socket_addr_v4(v4, buf),
        SocketAddr::V6(v6) => emit_socket_addr_v6(v6, buf),
    }
}

pub fn parse_socket_addr(buf: &[u8]) -> Result<SocketAddr, DecodeError> {
    match buf.len() {
        SOCKET_ADDR_V4_LEN => Ok(SocketAddr::V4(parse_socket_addr_v4(buf))),
        SOCKET_ADDR_V6_LEN => Ok(SocketAddr::V6(parse_socket_addr_v6(buf))),
        _ => Err(format!(
            "invalid socket address (should be 16 or 28 bytes): {:x?}",
            buf
        )
        .into()),
    }
}

pub fn emit_timespec(time: &SystemTime, buf: &mut [u8]) {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(epoch_elapsed) => {
            NativeEndian::write_i64(&mut buf[..8], epoch_elapsed.as_secs() as i64);
            NativeEndian::write_i64(&mut buf[8..16], epoch_elapsed.subsec_nanos() as i64);
        }
        Err(e) => {
            // This method is supposed to not fail so just log an
            // error. If we want such errors to be handled by the
            // caller, we shouldn't use `SystemTime`.
            error!("error while emitting timespec: {:?}", e);
            NativeEndian::write_i64(&mut buf[..8], 0_i64);
            NativeEndian::write_i64(&mut buf[8..16], 0_i64);
        }
    }
}

pub fn parse_timespec(buf: &[u8]) -> Result<SystemTime, DecodeError> {
    if buf.len() != TIMESPEC_LEN {
        return Err(DecodeError::from(format!(
            "Invalid timespec buffer: {:x?}",
            buf
        )));
    }
    let epoch_elapsed_s = Duration::from_secs(NativeEndian::read_u64(&buf[..8]));
    let epoch_elapsed_ns = Duration::from_nanos(NativeEndian::read_u64(&buf[8..16]));
    Ok(SystemTime::UNIX_EPOCH + epoch_elapsed_s + epoch_elapsed_ns)
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
    fn test_parse_socket_addr_in_1() {
        let ipaddr = parse_socket_addr(&SOCKADDR_IN_BYTES_1).unwrap();
        assert_eq!(ipaddr, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 7290).into());
    }

    #[test]
    fn test_parse_socket_addr_in_2() {
        let ipaddr = parse_socket_addr(&SOCKADDR_IN_BYTES_2).unwrap();
        assert_eq!(
            ipaddr,
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 51820).into()
        );
    }

    #[test]
    fn test_parse_socket_addr_in6_1() {
        let ipaddr = parse_socket_addr(&SOCKADDR_IN6_BYTES_1).unwrap();
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

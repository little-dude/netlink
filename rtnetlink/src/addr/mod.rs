use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::errors::{Error, ErrorKind};

mod handle;
pub use self::handle::*;

mod add;
pub use self::add::*;

mod del;
pub use self::del::*;

mod get;
pub use self::get::*;

mod flush;
pub use self::flush::*;

fn bytes_to_ip_addr(bytes: &[u8]) -> Result<IpAddr, Error> {
    match bytes.len() {
        4 => {
            let mut array = [0; 4];
            array.copy_from_slice(bytes);
            Ok(Ipv4Addr::from(array).into())
        }
        16 => {
            let mut array = [0; 16];
            array.copy_from_slice(bytes);
            Ok(Ipv6Addr::from(array).into())
        }
        _ => Err(ErrorKind::InvalidIp(bytes.to_vec()).into()),
    }
}

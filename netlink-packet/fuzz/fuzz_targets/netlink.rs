#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate netlink_packet;

use netlink_packet::{NetlinkBuffer, NetlinkMessage, Parseable};

#[cfg(feature = "rtnetlink")]
#[rustfmt::skip]
fuzz_target!(|data: &[u8]| {
    if let Ok(buf) = NetlinkBuffer::new_checked(&data) {
        <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&buf);
    }
});

#[cfg(feature = "audit")]
#[rustfmt::skip]
fuzz_target!(|data: &[u8]| {
    if let Ok(buf) = NetlinkBuffer::new_checked(&data) {
        <NetlinkBuffer<_> as Parseable<NetlinkMessage>>::parse(&buf);
    }
});

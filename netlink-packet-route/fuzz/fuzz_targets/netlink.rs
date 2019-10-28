#![no_main]
use libfuzzer_sys::fuzz_target;
use netlink_packet_route::{RtnlMessage, NetlinkMessage};

fuzz_target!(|data: &[u8]| {
    let _ = NetlinkMessage::<RtnlMessage>::deserialize(&data);
});

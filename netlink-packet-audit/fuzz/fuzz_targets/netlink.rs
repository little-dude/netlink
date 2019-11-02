#![no_main]

use libfuzzer_sys::fuzz_target;
use netlink_packet_audit::{NetlinkMessage, AuditMessage};

fuzz_target!(|data: &[u8]| {
    let _ = NetlinkMessage::<AuditMessage>::deserialize(&data);
});

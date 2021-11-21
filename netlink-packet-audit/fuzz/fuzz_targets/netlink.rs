// SPDX-License-Identifier: MIT

#![no_main]

use libfuzzer_sys::fuzz_target;
use netlink_packet_audit::{AuditMessage, NetlinkMessage};

fuzz_target!(|data: &[u8]| {
    let _ = NetlinkMessage::<AuditMessage>::deserialize(data);
});

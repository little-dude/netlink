//! In this example, we create two rules which is equivalent to the following commands:
//!
//! auditctl -w /etc/passwd -p rwxa -k my_key
//! auditctl -a always,exit -F arch=b64 -S personality -F key=bypass
//!
use std::thread::spawn;

use futures::Future;
use tokio_core::reactor::Core;

use audit::new_connection;
use netlink_packet_audit::{
    archs::AUDIT_ARCH_X86_64,
    rules::{RuleAction, RuleField, RuleFieldFlags, RuleFlags, RuleMessage, RuleSyscalls},
};

fn main() {
    env_logger::init();

    // Open the netlink socket
    let (connection, mut handle, _) = new_connection().unwrap();

    // Create the event loop on which that is going to drive our netlink connection
    spawn(move || Core::new().unwrap().run(connection));

    // create the message for the first rule
    let etc_passwd_rule = RuleMessage {
        flags: RuleFlags::FilterExit,
        action: RuleAction::Always,
        fields: vec![
            (
                RuleField::Watch("/etc/passwd".into()),
                RuleFieldFlags::Equal,
            ),
            (RuleField::Perm(15), RuleFieldFlags::Equal),
            (RuleField::Filterkey("my_key".into()), RuleFieldFlags::Equal),
        ],
        syscalls: RuleSyscalls::new_maxed(),
    };

    // create the message for the second rule
    let mut syscalls = RuleSyscalls::new_zeroed();
    syscalls.set(135);
    let personality_syscall_rule = RuleMessage {
        flags: RuleFlags::FilterExit,
        action: RuleAction::Always,
        fields: vec![
            (RuleField::Arch(AUDIT_ARCH_X86_64), RuleFieldFlags::Equal),
            (RuleField::Filterkey("bypass".into()), RuleFieldFlags::Equal),
        ],
        syscalls,
    };

    // Create the rules
    handle.add_rule(etc_passwd_rule).wait().unwrap();
    handle.add_rule(personality_syscall_rule).wait().unwrap();
}

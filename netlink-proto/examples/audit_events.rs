// This example shows how to use `netlink-proto` with the tokio runtime to print audit events.
//
// This example shows how the netlink socket can be accessed
// `netlink_proto::Connection`, and configured (in this case to
// register to a multicast group).
//
// Compilation:
// ------------
//
// cargo build --example audit_events --features="workaround-audit-bug"
//
// Note that the audit protocol has a bug that we have to workaround,
// hence the custom --features flag for that protocol
//
// Usage:
// ------
//
// Find the example binary in the target directory, and run it *as
// root*. If you compiled in debug mode with the command above, the
// binary should be under:
// `<repo-root>/target/debug/examples/audit_events`. This example runs
// forever, you must hit ^C to kill it.

use failure::Fail;
use futures::{
    future::{lazy, Future},
    stream::Stream,
};
use netlink_packet_audit::{AuditMessage, StatusMessage};
use netlink_proto::{
    new_connection,
    packet::{
        header::flags::{NLM_F_ACK, NLM_F_REQUEST},
        NetlinkFlags, NetlinkMessage, NetlinkPayload,
    },
    sys::{Protocol, SocketAddr},
};
use std::process;

const AUDIT_STATUS_ENABLED: u32 = 1;
const AUDIT_STATUS_PID: u32 = 4;

fn main() {
    let (conn, mut handle, messages) =
        new_connection(Protocol::Audit).expect("Failed to create a new netlink connection");

    // We'll send unicast messages to the kernel.
    let kernel_unicast: SocketAddr = SocketAddr::new(0, 0);

    tokio::run(lazy(move || {
        // Spawn the `netlink_proto::Connection` so that it starts
        // polling the netlink socket.
        tokio::spawn(conn.map_err(|e| eprintln!("error in connection: {:?}", e)));

        // Use the `netlink_proto::ConnectionHandle` to send a request
        // to the kernel asking it to start multicasting audit event messages.
        tokio::spawn({
            // Craft the packet to enable audit events
            let mut status = StatusMessage::new();
            status.enabled = 1;
            status.pid = process::id();
            status.mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID;
            let payload = AuditMessage::SetStatus(status);
            let mut nl_msg = NetlinkMessage::from(payload);
            nl_msg.header.flags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK);

            // The ConnectionHandle::request() method returns a
            // Stream<Item=NetlinkMessage<AuditMessage>>, although
            // here we only expects one message in return: either an
            // ACK or an ERROR.
            handle
                .request(nl_msg, kernel_unicast)
                // For simplicity we'll use strings for errors in this
                // example. This netlink-proto uses the `failure`
                // crate, errors contain the whole chain of errors
                // that led to this error. `format_failure_error`
                // format them nicely
                .map_err(format_failure_error)
                .for_each(|message| {
                    if let NetlinkPayload::Error(err_message) = message.payload {
                        Err(format!("Received an error message: {:?}", err_message))
                    } else {
                        Ok(())
                    }
                })
                .map_err(|e| eprintln!("Request failed: {:?}", e))
        });

        println!("Starting to print audit events... press ^C to interrupt");

        // We print the audit event messages that the kernel multicasts.
        messages.for_each(|message| {
            println!("{:?}", message);
            Ok(())
        })
    }))
}

fn format_failure_error<E: Fail>(error: E) -> String {
    let mut error_string = String::new();
    for cause in Fail::iter_chain(&error) {
        error_string += &format!(": {}", cause);
    }
    error_string
}

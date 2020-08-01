use crate::new_connection;
use futures::stream::TryStreamExt;
use netlink_packet_route::{
    rtnl::tc::nlas::Nla::{HwOffload, Kind},
    TcMessage, AF_UNSPEC,
};
use std::process::Command;
use tokio::runtime::Runtime;

async fn _get_qdiscs() -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut qdiscs_iter = handle.qdisc().get().execute();
    let mut qdiscs = Vec::new();
    while let Some(nl_msg) = qdiscs_iter.try_next().await.unwrap() {
        qdiscs.push(nl_msg.clone());
    }
    qdiscs
}

#[test]
fn test_get_qdiscs() {
    let qdiscs = Runtime::new().unwrap().block_on(_get_qdiscs());
    let qdisc_of_loopback_nic = &qdiscs[0];
    assert_eq!(qdisc_of_loopback_nic.header.family, AF_UNSPEC as u8);
    assert_eq!(qdisc_of_loopback_nic.header.index, 1);
    assert_eq!(qdisc_of_loopback_nic.header.handle, 0);
    assert_eq!(qdisc_of_loopback_nic.header.parent, u32::MAX);
    assert_eq!(qdisc_of_loopback_nic.header.info, 2); // refcount
    assert_eq!(qdisc_of_loopback_nic.nlas[0], Kind("noqueue".to_string()));
    assert_eq!(qdisc_of_loopback_nic.nlas[1], HwOffload(0));
}

async fn _get_tclasses(ifindex: i32) -> Vec<TcMessage> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut tclasses_iter = handle.traffic_class(ifindex).get().execute();
    let mut tclasses = Vec::new();
    while let Some(nl_msg) = tclasses_iter.try_next().await.unwrap() {
        tclasses.push(nl_msg.clone());
    }
    tclasses
}

fn _add_test_tclass_to_lo() {
    let output = Command::new("tc")
        .args(&[
            "qdisc", "add", "dev", "lo", "root", "handle", "1:", "htb", "default", "6",
        ])
        .output()
        .expect("failed to run tc command");
    if !output.status.success() {
        eprintln!("Failed to add qdisc to lo: {:?}", output);
    }
    assert!(output.status.success());
    let output = Command::new("tc")
        .args(&[
            "class", "add", "dev", "lo", "parent", "1:", "classid", "1:1", "htb", "rate", "10mbit",
            "ceil", "10mbit",
        ])
        .output()
        .expect("failed to run tc command");
    if !output.status.success() {
        eprintln!("Failed to add traffic class to lo: {:?}", output);
    }
    assert!(output.status.success());
}

fn _remove_test_tclass_from_lo() {
    Command::new("tc")
        .args(&[
            "class", "del", "dev", "lo", "parent", "1:", "classid", "1:1",
        ])
        .status()
        .expect("failed to remove tclass from lo");
    Command::new("tc")
        .args(&["qdisc", "del", "dev", "lo", "root"])
        .status()
        .expect("failed to remove qdisc from lo");
}

#[test]
#[cfg_attr(not(feature = "test_as_root"), ignore)]
fn test_get_traffic_classes() {
    _add_test_tclass_to_lo();
    let tclasses = Runtime::new().unwrap().block_on(_get_tclasses(1));
    _remove_test_tclass_from_lo();
    assert_eq!(tclasses.len(), 1);
    let tclass_of_loopback_nic = &tclasses[0];
    assert_eq!(tclass_of_loopback_nic.header.family, AF_UNSPEC as u8);
    assert_eq!(tclass_of_loopback_nic.header.index, 1);
    assert_eq!(tclass_of_loopback_nic.header.parent, u32::MAX);
    assert_eq!(tclass_of_loopback_nic.nlas[0], Kind("htb".to_string()));
}

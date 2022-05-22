// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::process::Command;

use mptcp_pm::{MptcpPathManagerAttr, MptcpPathManagerLimitsAttr};

#[test]
fn test_mptcp_empty_addresses_and_limits() {
    Command::new("sysctl")
        .arg("-w")
        .arg("net.mptcp.enabled=1")
        .spawn()
        .unwrap();
    // OK to fail as Github CI has no ip-mptcp
    Command::new("ip")
        .arg("mptcp")
        .arg("endpoint")
        .arg("flush")
        .spawn()
        .ok();
    // OK to fail as Github CI has no ip-mptcp
    Command::new("ip")
        .arg("mptcp")
        .arg("limits")
        .arg("set")
        .arg("subflows")
        .arg("0")
        .arg("add_addr_accepted")
        .arg("0")
        .spawn()
        .ok();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(assert_empty_addresses_and_limits());
}

async fn assert_empty_addresses_and_limits() {
    let (connection, handle, _) = mptcp_pm::new_connection().unwrap();
    tokio::spawn(connection);

    let mut address_handle = handle.address().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = address_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert!(msgs.is_empty());
    let mut limits_handle = handle.limits().get().execute().await;

    let mut msgs = Vec::new();
    while let Some(msg) = limits_handle.try_next().await.unwrap() {
        msgs.push(msg);
    }
    assert_eq!(msgs.len(), 1);
    let mptcp_nlas = &msgs[0].payload.nlas;
    assert_eq!(
        mptcp_nlas[0],
        MptcpPathManagerAttr::Limits(MptcpPathManagerLimitsAttr::RcvAddAddrs(0))
    );
    assert_eq!(
        mptcp_nlas[1],
        MptcpPathManagerAttr::Limits(MptcpPathManagerLimitsAttr::Subflows(0))
    );
}

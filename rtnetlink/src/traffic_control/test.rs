use crate::new_connection;
use futures::stream::TryStreamExt;
use netlink_packet_route::{
    rtnl::tc::nlas::Nla::{HwOffload, Kind},
    TcMessage, AF_UNSPEC,
};
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

use netlink_generic::new_connection;
use tokio;

#[test]
#[ignore] // Github Action does not have ethtool-netlink enabled
fn test_genl_ctrl_resolve_ethtool() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    rt.block_on(genl_ctrl_resolve_ethtool());
}

async fn genl_ctrl_resolve_ethtool() {
    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let family_id = handle.resolve_family_name("ethtool").await.unwrap();
    println!("Family ID of ethtool is {}", family_id);
    assert!(family_id > 0);
}

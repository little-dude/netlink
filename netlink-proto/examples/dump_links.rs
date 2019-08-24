use futures::StreamExt;

use netlink_packet_route::{
    netlink::{
        header::flags::{NLM_F_DUMP, NLM_F_REQUEST},
        NetlinkFlags, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    },
    rtnl::{
        link::{LinkHeader, LinkMessage},
        RtnlMessage,
    },
};

use netlink_proto::{
    new_connection,
    sys::{Protocol, SocketAddr},
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Create the netlink socket. Here, we won't use the channel that
    // receives unsollicited messages.
    let (conn, mut handle, _) = new_connection(Protocol::Route)
        .map_err(|e| format!("Failed to create a new netlink connection: {}", e))?;

    // Spawn the `Connection` in the background
    tokio::spawn(conn);

    // Create the netlink message that requests the links to be dumped
    let payload: NetlinkPayload<RtnlMessage> =
        RtnlMessage::GetLink(LinkMessage::from_parts(LinkHeader::new(), vec![])).into();
    let mut header = NetlinkHeader::new();
    header.flags = NetlinkFlags::from(NLM_F_DUMP | NLM_F_REQUEST);

    // Send the request
    let mut response = handle
        .request(NetlinkMessage::new(header, payload), SocketAddr::new(0, 0))
        .map_err(|e| format!("Failed to send request: {}", e))?;

    // Print all the messages received in response
    loop {
        if let Some(packet) = response.next().await {
            println!("<<< {:?}", packet);
        } else {
            break;
        }
    }

    Ok(())
}

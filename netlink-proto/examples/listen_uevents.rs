use futures::StreamExt;
use netlink_proto::{new_connection, sys::{protocols::NETLINK_KOBJECT_UEVENT, SocketAddr}};

use netlink_packet_core::{NetlinkDeserializable, NetlinkHeader, NetlinkSerializable};

#[derive(Debug, PartialEq, Eq, Clone)]
enum UEvent {
    Add,
}

impl NetlinkSerializable<UEvent> for UEvent {
    fn message_type(&self) -> u16 {
        todo!()
    }

    fn buffer_len(&self) -> usize {
        todo!()
    }

    fn serialize(&self, buffer: &mut [u8]) {
        todo!()
    }
}

impl NetlinkDeserializable<UEvent> for UEvent {
    type Error = std::io::Error;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        let s = String::from_utf8_lossy(payload);
        println!("{}", s);

        Ok(UEvent::Add)
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
        env_logger::init();
    // Create the netlink socket.
    let (mut conn, mut _handle, mut messages) = new_connection::<UEvent>(NETLINK_KOBJECT_UEVENT)
        .map_err(|e| format!("Failed to create a new netlink connection: {}", e))?;

    let sa = SocketAddr::new(std::process::id(), 1);

    conn.socket_mut().bind(&sa).unwrap();

    // Spawn the `Connection` in the background
    tokio::spawn(conn);

    // Print all the messages received in response
    loop {
        if let Some(packet) = messages.next().await {
            println!("<<< {:?}", packet);
        } else {
            break;
        }
    }

    Ok(())
}

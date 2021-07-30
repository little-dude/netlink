use anyhow::{bail, Error};
use futures::{channel::mpsc::UnboundedReceiver, lock::Mutex, StreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
use netlink_packet_generic::{
    ctrl::{nlas::GenlCtrlAttrs, GenlCtrl, GenlCtrlCmd},
    GenlFamily, GenlHeader, GenlMessage,
};
use netlink_packet_utils::Emitable;
use netlink_packet_wireguard::{
    nlas::{WgAllowedIpAttrs, WgDeviceAttrs, WgPeerAttrs},
    Wireguard, WireguardCmd,
};
use netlink_proto::{
    sys::{protocols::NETLINK_GENERIC, SocketAddr},
    Connection, ConnectionHandle,
};
use once_cell::sync::Lazy;
use std::{
    env::args,
    io,
    sync::{Arc, RwLock},
};
use genetlink::new_connection;

static CACHE: Lazy<Arc<RwLock<u16>>> = Lazy::new(|| Arc::new(RwLock::new(0)));

#[tokio::main]
async fn main() {
    env_logger::init();

    let argv: Vec<String> = args().collect();
    if argv.len() < 2 {
        eprintln!("Usage: get_wireguard_info <ifname>");
        return;
    }

    let (connection, mut handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    let mut genlmsg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::GetDevice,
        nlas: vec![WgDeviceAttrs::IfName(argv[1].clone())],
    });
    let mut nlmsg = NetlinkMessage::from(genlmsg);
    nlmsg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

    let mut res = handle.request(nlmsg).await.unwrap();

    while let Some(result) = res.next().await {
        let rx_packet = result.unwrap();
        match rx_packet.payload {
            NetlinkPayload::InnerMessage(genlmsg) => {
                print_wg_payload(genlmsg.payload);
            }
            NetlinkPayload::Error(e) => {
                eprintln!("Error: {:?}", e.to_io());
            }
            _ => (),
        };
    }
}

fn print_wg_payload(wg: Wireguard) {
    for nla in &wg.nlas {
        match nla {
            WgDeviceAttrs::IfIndex(v) => println!("IfIndex: {}", v),
            WgDeviceAttrs::IfName(v) => println!("IfName: {}", v),
            WgDeviceAttrs::PrivateKey(_) => println!("PrivateKey: (hidden)"),
            WgDeviceAttrs::PublicKey(v) => println!("PublicKey: {}", base64::encode(v)),
            WgDeviceAttrs::ListenPort(v) => println!("ListenPort: {}", v),
            WgDeviceAttrs::Fwmark(v) => println!("Fwmark: {}", v),
            WgDeviceAttrs::Peers(nlas) => {
                for peer in nlas {
                    println!("Peer: ");
                    print_wg_peer(peer);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_peer(nlas: &[WgPeerAttrs]) {
    for nla in nlas {
        match nla {
            WgPeerAttrs::PublicKey(v) => println!("  PublicKey: {}", base64::encode(v)),
            WgPeerAttrs::PresharedKey(_) => println!("  PresharedKey: (hidden)"),
            WgPeerAttrs::Endpoint(v) => println!("  Endpoint: {}", v),
            WgPeerAttrs::PersistentKeepalive(v) => println!("  PersistentKeepalive: {}", v),
            WgPeerAttrs::LastHandshake(v) => println!("  LastHandshake: {:?}", v),
            WgPeerAttrs::RxBytes(v) => println!("  RxBytes: {}", v),
            WgPeerAttrs::TxBytes(v) => println!("  TxBytes: {}", v),
            WgPeerAttrs::AllowedIps(nlas) => {
                for ip in nlas {
                    print_wg_allowedip(ip);
                }
            }
            _ => (),
        }
    }
}

fn print_wg_allowedip(nlas: &[WgAllowedIpAttrs]) -> Option<()> {
    let ipaddr = nlas.iter().find_map(|nla| {
        if let WgAllowedIpAttrs::IpAddr(ipaddr) = nla {
            Some(*ipaddr)
        } else {
            None
        }
    })?;
    let cidr = nlas.iter().find_map(|nla| {
        if let WgAllowedIpAttrs::Cidr(cidr) = nla {
            Some(*cidr)
        } else {
            None
        }
    })?;
    println!("  AllowedIp: {}/{}", ipaddr, cidr);
    Some(())
}

//! This example is meant to show some of the limitations of the current design.
//!
//! Assuming with already have a network namespace "netlink-example" created with `ip netns add
//! netlink-example`, the goal is to:
//!
//! 1. create a bridge and a veth pair
//! 2. attach on of the veth to the bridge, and give it the address 10.0.0.1/24
//! 3. send the other veth to the "netlink-example" namespace
//!
//! Ideally there should be a 4th step "set the ip 10.0.0.2/24 to the second veth", but that
//! means re-opening a netlink connection in another namespace, or changing the namespace of
//! the thread in which the existing netlink connection is running, and I didn't even get that far.
//!
//! Currently this example fails at step 3 because to set the namespace for the veth-rs-2
//! interface, we use an IFLA_NET_NS_FD netlink attribute populated with the file descriptor of
//! `/var/run/netns/netlink-example`. The issue is that the netlink connection (ie the future that
//! sends and receive message through the netlink socket), and the future in which we open
//! `/var/run/netns/netlink-example` to get a file descriptor, are spawned separately (they are
//! different "tasks", in Future/Tokio jargon). As a result, there is no guarantee they'll run in
//! the same thread, and in fact, with the default runtime, they run in two different threads. As a
//! result, when the kernel received the RTM_SETLINK message from the thread where the netlink
//! connection runs, it finds out that the thread does not have the file descriptor advertised in
//! the IFLA_NET_NS_FD attribute, and return -EBADF...
//!
//! Apart for this major issue, we can see that the code is particularly verbose and ugly (we have
//! to clone the `nl_handle` all the time, there's too much method chaining, and having to add
//! execute() everywhere is annoying)
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::io::AsRawFd;

use futures::{future, future::FutureResult, Future, Stream};
use tokio::fs::File;
use tokio::runtime::Runtime;

use rtnetlink::{new_connection, packet::LinkNla};

fn main() {
    // Create a netlink connection, and a handle to send requests via this connection
    let (connection, nl_handle) = new_connection().unwrap();

    // Start the Tokio runtime
    let mut rt = Runtime::new().unwrap();

    // Spawn the netlink connection future. This task will likely run in its own thread, which
    // causes problems for network namespace manipulations
    rt.spawn(connection.map_err(|_| ()));

    // Create a future for the bridge creation
    let bridge_future = nl_handle
        .link()
        .add()
        .bridge("bridge-rs".into())
        .execute() //
        .map_err(|e| format!("failed to create bridge: {:?}", e))
        .map(|()| println!("bridge created!"));

    // Create a future for the veth pair creation
    let veth_future = nl_handle
        .link()
        .add()
        .veth("veth-rs-1".into(), "veth-rs-2".into())
        .execute()
        .map_err(|e| format!("failed to veth pair: {:?}", e))
        .map(|()| println!("veth pair created!"));

    // Ugly clone to satisfy the borrow checker
    let nl_handle_clone = nl_handle.clone();

    // Join the bridge and veth creation futures
    let main = Future::join(bridge_future, veth_future)
        // Collect the indices of the three links that were created
        .and_then(move |_| {
            nl_handle_clone
                .link()
                .get()
                .execute()
                .map_err(|e| format!("failed to retrieve the interfaces: {:?}", e))
                .fold((None, None, None), |mut acc, msg| {
                    for nla in &msg.nlas {
                        if let LinkNla::IfName(ref name) = nla {
                            if name == "veth-rs-1" {
                                acc.0 = Some(msg.header.index);
                            } else if name == "veth-rs-2" {
                                acc.1 = Some(msg.header.index);
                            } else if name == "bridge-rs" {
                                acc.2 = Some(msg.header.index);
                            }
                            return future::ok(acc) as FutureResult<_, String>;
                        }
                    }
                    return future::ok(acc) as FutureResult<_, String>;
                })
        })
        .and_then(|indices| {
            Ok((
                indices
                    .0
                    .ok_or_else(|| "veth-rs-1 index not found".to_string())?,
                indices
                    .1
                    .ok_or_else(|| "veth-rs-2 index not found".to_string())?,
                indices
                    .2
                    .ok_or_else(|| "bridge-rs index not found".to_string())?,
            ))
        })
        .and_then(move |(veth1_idx, veth2_idx, br_idx)| {
            // Set veth-rs-1 up, and attach it to the bridge
            let veth1_link_future = nl_handle
                .clone()
                .link()
                .set(veth1_idx)
                .master(br_idx)
                .up()
                .execute()
                .map_err(|e| format!("failed to attach veth-rs-1 to bridge-rs: {:?}", e))
                .map(|_| println!("veth-rs-1 up and attached to the brige"));

            // Add the 10.0.0.1/24 address to veth-rs-1
            let veth1_addr_future = nl_handle
                .clone()
                .address()
                .add(veth1_idx, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24)
                .execute()
                .map_err(|e| format!("failed add 10.0.0.1/24 address to veth-rs-1: {:?}", e))
                .map(|_| println!("veth-rs-1 address set to 10.0.0.1/24"));

            // Another ugly clone to satisfy the borrow checker
            let nl_handle_clone = nl_handle.clone();

            // This is where the failure occurs. This future is supposed to:
            // - open /var/run/netns/netlink-example
            // - send a RTM_SETLINK message with an IFLA_NET_NS_FD attribute populated with the fd
            //   of /var/run/netns/netlink-example
            //
            // But the message itself, is actually sent by the netlink connection we spawned
            // earlier, and which runs in a different thread than this future. Hence, the kernel
            // returns -EBADF.
            let veth2_link_future = File::open("/var/run/netns/netlink-example")
                .map_err(|e| format!("failed to open /var/run/netns/netlink-example: {:?}", e))
                .and_then(move |file| {
                    nl_handle_clone
                        .link()
                        .set(veth2_idx)
                        .up()
                        .setns_by_fd(file.into_std().as_raw_fd())
                        .execute()
                        .map_err(|e| {
                            format!(
                                "failed to set veth-rs-2 to namespace netlink-example: {:?}",
                                e
                            )
                        })
                        .map(|_| println!("veth-rs-2 set in namespace netlink-example"))
                });
            Future::join3(veth1_link_future, veth1_addr_future, veth2_link_future)
        });

    rt.block_on(main.map_err(|e| eprintln!("{:?}", e)).map(|_| ()));
}

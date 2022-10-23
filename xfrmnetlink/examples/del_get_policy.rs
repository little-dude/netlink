// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{policy_del_get_parse_args, PolicyDelGetCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 3 {
        usage();
        std::process::exit(1);
    }

    let cli_args = match policy_del_get_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            std::process::exit(1);
        }
    };

    //println!("{:?}", cli_args);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if cli_args.get {
        if let Err(e) = get_policy(handle.clone(), &cli_args).await {
            eprintln!("{}", e);
        }
    } else {
        if let Err(e) = del_policy(handle.clone(), &cli_args).await {
            eprintln!("{}", e);
        }
    }
    Ok(())
}

async fn get_policy(handle: Handle, ca: &PolicyDelGetCliArgs) -> Result<(), Error> {
    let mut req = if ca.index.is_some() {
        handle.policy().get_index(ca.index.unwrap(), ca.direction)
    } else {
        handle.policy().get(
            ca.src_addr.addr(),
            ca.src_addr.prefix_len(),
            ca.dst_addr.addr(),
            ca.dst_addr.prefix_len(),
            ca.direction,
        )
    };

    if let Some(pt) = ca.ptype {
        req = req.ptype(pt);
    }
    if let Some(secctx) = &ca.secctx {
        req = req.security_context(secctx);
    }
    if let Some(ifid) = ca.ifid {
        req = req.ifid(ifid);
    }
    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }
    if let Some(dev_id) = ca.dev_id {
        req = req.selector_dev_id(dev_id);
    }
    if let Some(proto_num) = ca.proto_num {
        req = req.selector_protocol(proto_num);

        if let Some(proto_src_port) = ca.proto_src_port {
            req = req.selector_protocol_src_port(proto_src_port);
        }
        if let Some(proto_dst_port) = ca.proto_dst_port {
            req = req.selector_protocol_dst_port(proto_dst_port);
        }
        if let Some(proto_type) = ca.proto_type {
            req = req.selector_protocol_type(proto_type);
        }
        if let Some(proto_code) = ca.proto_code {
            req = req.selector_protocol_code(proto_code);
        }
        if let Some(gre_key) = ca.gre_key {
            req = req.selector_protocol_gre_key(gre_key);
        }
    }

    let mut policy = req.execute();
    let msg = if let Some(msg) = policy.try_next().await? {
        msg
    } else {
        eprintln!("no policy found");
        return Ok(());
    };
    // We should have received only one message
    assert!(policy.try_next().await?.is_none());
    println!("Result: {:?}", msg);

    Ok(())
}

async fn del_policy(handle: Handle, ca: &PolicyDelGetCliArgs) -> Result<(), Error> {
    let mut req = if ca.index.is_some() {
        handle
            .policy()
            .delete_index(ca.index.unwrap(), ca.direction)
    } else {
        handle.policy().delete(
            ca.src_addr.addr(),
            ca.src_addr.prefix_len(),
            ca.dst_addr.addr(),
            ca.dst_addr.prefix_len(),
            ca.direction,
        )
    };

    if let Some(pt) = ca.ptype {
        req = req.ptype(pt);
    }
    if let Some(secctx) = &ca.secctx {
        req = req.security_context(secctx);
    }
    if let Some(ifid) = ca.ifid {
        req = req.ifid(ifid);
    }
    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }
    if let Some(dev_id) = ca.dev_id {
        req = req.selector_dev_id(dev_id);
    }
    if let Some(proto_num) = ca.proto_num {
        req = req.selector_protocol(proto_num);

        if let Some(proto_src_port) = ca.proto_src_port {
            req = req.selector_protocol_src_port(proto_src_port);
        }
        if let Some(proto_dst_port) = ca.proto_dst_port {
            req = req.selector_protocol_dst_port(proto_dst_port);
        }
        if let Some(proto_type) = ca.proto_type {
            req = req.selector_protocol_type(proto_type);
        }
        if let Some(proto_code) = ca.proto_code {
            req = req.selector_protocol_code(proto_code);
        }
        if let Some(gre_key) = ca.gre_key {
            req = req.selector_protocol_gre_key(gre_key);
        }
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example del_get_policy -- {{ delete | get }} {{ SELECTOR | index INDEX }} dir DIR
        [ ctx CTX ] [ mark MARK [ mask MASK ] ] [ ptype PTYPE ]
        [ if_id IF_ID ]

SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]
UPSPEC := proto {{ {{ tcp | udp | sctp | dccp }} [ sport PORT ] [ dport PORT ] |
                  {{ icmp | ipv6-icmp | mobility-header }} [ type NUMBER ] [ code NUMBER ] |
                  gre [ key {{ DOTTED-QUAD | NUMBER }} ] | PROTO }}
DIR := in | out | fwd
PTYPE := main | sub

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example del_get_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./del_get_policy {{ delete | get }} ..."
    );
}

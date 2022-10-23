// SPDX-License-Identifier: MIT

use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{policy_add_upd_parse_args, PolicyAddUpdCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 3 {
        usage();
        std::process::exit(1);
    }

    let cli_args = match policy_add_upd_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            std::process::exit(1);
        }
    };

    //println!("{:?}", cli_args);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = add_upd_policy(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn add_upd_policy(handle: Handle, ca: &PolicyAddUpdCliArgs) -> Result<(), Error> {
    let mut req = if ca.update {
        handle.policy().update(
            ca.src_addr.addr(),
            ca.src_addr.prefix_len(),
            ca.dst_addr.addr(),
            ca.dst_addr.prefix_len(),
            ca.direction,
            ca.action,
        )
    } else {
        handle.policy().add(
            ca.src_addr.addr(),
            ca.src_addr.prefix_len(),
            ca.dst_addr.addr(),
            ca.dst_addr.prefix_len(),
            ca.direction,
            ca.action,
        )
    };

    if let Some(pt) = ca.ptype {
        req = req.ptype(pt);
    }
    if let Some(secctx) = &ca.secctx {
        req = req.security_context(secctx);
    }
    if let Some(index) = ca.index {
        req = req.index(index);
    }
    if let Some(priority) = ca.priority {
        req = req.priority(priority);
    }
    if let Some(ifid) = ca.ifid {
        req = req.ifid(ifid);
    }
    if let Some(flags) = ca.flags {
        req = req.flags(flags);
    }
    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }
    if let Some(time_limits) = ca.time_limits {
        req = req.time_limit(time_limits.0, time_limits.1);
    }
    if let Some(time_use_limits) = ca.time_use_limits {
        req = req.time_use_limit(time_use_limits.0, time_use_limits.1);
    }
    if let Some(byte_limits) = ca.byte_limits {
        req = req.byte_limit(byte_limits.0, byte_limits.1);
    }
    if let Some(packet_limits) = ca.packet_limits {
        req = req.packet_limit(packet_limits.0, packet_limits.1);
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

    let mut tmpls = ca.templates.iter();
    while let Some(tmpl) = tmpls.next() {
        req = req.add_template(
            tmpl.src_addr.addr(),
            tmpl.dst_addr.addr(),
            tmpl.proto,
            tmpl.mode,
            tmpl.spi,
            tmpl.optional,
            tmpl.reqid,
        );
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example add_upd_policy -- {{ add | update }} SELECTOR dir DIR [ ctx CTX ]
        [ mark MARK [ mask MASK ] ] [ index INDEX ] [ ptype PTYPE ]
        [ action ACTION ] [ priority PRIORITY ] [ flag FLAG-LIST ]
        [ if_id IF_ID ] [ LIMIT-LIST ] [ TMPL-LIST ]

SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]
UPSPEC := proto {{ {{ tcp | udp | sctp | dccp }} [ sport PORT ] [ dport PORT ] |
                  {{ icmp | ipv6-icmp | mobility-header }} [ type NUMBER ] [ code NUMBER ] |
                  gre [ key {{ DOTTED-QUAD | NUMBER }} ] | PROTO }}
DIR := in | out | fwd
PTYPE := main | sub
ACTION := allow | block
FLAG-LIST := [ FLAG-LIST ] FLAG
FLAG := localok | icmp
LIMIT-LIST := [ LIMIT-LIST ] limit LIMIT
LIMIT := {{ time-soft | time-hard | time-use-soft | time-use-hard }} SECONDS |
         {{ byte-soft | byte-hard }} SIZE | {{ packet-soft | packet-hard }} COUNT
TMPL-LIST := [ TMPL-LIST ] tmpl TMPL
TMPL := ID [ mode MODE ] [ reqid REQID ] [ level LEVEL ]
ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
XFRM-PROTO := esp | ah | comp | route2 | hao
MODE := transport | tunnel | beet | ro | in_trigger
LEVEL := required | use

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example add_upd_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./add_upd_policy {{ add | update }} ..."
    );
}

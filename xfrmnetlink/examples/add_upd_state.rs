// SPDX-License-Identifier: MIT

use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{state_add_upd_parse_args, StateAddUpdCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 3 {
        usage();
        std::process::exit(1);
    }

    let cli_args = match state_add_upd_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            std::process::exit(1);
        }
    };

    //println!("{:?}", cli_args);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = add_upd_state(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn add_upd_state(handle: Handle, ca: &StateAddUpdCliArgs) -> Result<(), Error> {
    // A lot of options can't be updated once added.
    // Limits, if_id, encapsulation srcport/dstport/ipaddr, output-mark/mask,
    // coaddr can be updated. Possibly selector (if not using spi, so not
    // relevant for IPsec).
    let mut req = if ca.update {
        handle.state().update(
            ca.src_addr.addr(),
            ca.dst_addr.addr(),
            ca.xfrm_proto,
            ca.spi,
        )
    } else {
        handle.state().add(
            ca.src_addr.addr(),
            ca.dst_addr.addr(),
            ca.xfrm_proto,
            ca.spi,
        )
    };

    if ca.enc_alg_name.is_some() {
        if ca.enc_alg_key.len() > 0 {
            req = req.encryption(ca.enc_alg_name.as_ref().unwrap(), &ca.enc_alg_key)?;
        }
        if ca.auth_alg_name.is_some() && ca.auth_alg_key.len() > 0 {
            req = req.authentication(ca.auth_alg_name.as_ref().unwrap(), &ca.auth_alg_key)?;
        } else if ca.auth_trunc_alg_name.is_some() && ca.auth_trunc_alg_key.len() > 0 {
            req = req.authentication_trunc(
                ca.auth_trunc_alg_name.as_ref().unwrap(),
                &ca.auth_trunc_alg_key,
                ca.auth_trunc_len,
            )?;
        }
    } else if ca.aead_alg_name.is_some() && ca.aead_alg_key.len() > 0 {
        req = req.encryption_aead(
            ca.aead_alg_name.as_ref().unwrap(),
            &ca.aead_alg_key,
            ca.aead_icv_len,
        )?;
    } else if ca.comp_alg_name.is_some() {
        req = req.compression(ca.comp_alg_name.as_ref().unwrap())?;
    }

    if let Some(m) = ca.mode {
        req = req.mode(m);
    }
    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }
    if let Some((mark, mask)) = ca.output_mark_and_mask {
        req = req.output_mark(mark, mask);
    }
    if let Some(r) = ca.reqid {
        req = req.reqid(r);
    }
    if let Some(s) = ca.seq {
        req = req.seq(s);
    }
    if let Some(rw) = ca.replay_window {
        let seq = ca.replay_seq.unwrap_or(0);
        let seq_hi = ca.replay_seq_hi.unwrap_or(0);
        let oseq = ca.replay_oseq.unwrap_or(0);
        let oseq_hi = ca.replay_oseq_hi.unwrap_or(0);
        req = req.replay_window(rw, seq, seq_hi, oseq, oseq_hi);
    }
    if let Some(flags) = ca.flags {
        req = req.flags(flags);
    }
    if let Some(extra_flags) = ca.extra_flags {
        req = req.extra_flags(extra_flags);
    }

    if let Some(selector_src) = ca.selector_src_addr {
        if let Some(selector_dst) = ca.selector_dst_addr {
            req = req.selector_addresses(
                selector_src.addr(),
                selector_src.prefix_len(),
                selector_dst.addr(),
                selector_dst.prefix_len(),
            );
        }
    }
    if let Some(selector_dev) = ca.selector_dev_id {
        req = req.selector_dev_id(selector_dev);
    }
    if let Some(selector_proto) = ca.selector_proto_num {
        req = req.selector_protocol(selector_proto);

        if let Some(proto_src_port) = ca.selector_proto_src_port {
            req = req.selector_protocol_src_port(proto_src_port);
        }
        if let Some(proto_dst_port) = ca.selector_proto_dst_port {
            req = req.selector_protocol_dst_port(proto_dst_port);
        }
        if let Some(proto_type) = ca.selector_proto_type {
            req = req.selector_protocol_type(proto_type);
        }
        if let Some(proto_code) = ca.selector_proto_code {
            req = req.selector_protocol_code(proto_code);
        }
        if let Some(gre_key) = ca.selector_gre_key {
            req = req.selector_protocol_gre_key(gre_key);
        }
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

    if let Some(encap_proto) = ca.encap_type {
        if ca.encap_sport.is_some() && ca.encap_dport.is_some() && ca.encap_oa.is_some() {
            req = req.encapsulation(
                encap_proto,
                ca.encap_sport.unwrap(),
                ca.encap_dport.unwrap(),
                ca.encap_oa.unwrap().addr(),
            );
        }
    }

    // only for route protocol
    if let Some(coa) = ca.care_of_addr {
        req = req.care_of_address(coa.addr());
    }

    if let Some(secctx) = &ca.secctx {
        req = req.security_context(secctx);
    }
    if let Some(offload_dev) = ca.offload_dev {
        if let Some(offload_dir) = ca.offload_dir {
            req = req.offload_device(offload_dev, offload_dir);
        }
    }
    if let Some(ifid) = ca.ifid {
        req = req.ifid(ifid);
    }
    if let Some(tfc) = ca.tfcpad {
        req = req.tfc_pad_length(tfc);
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example add_upd_state -- {{ add | update }} ID [ ALGO-LIST ] [ mode MODE ]
        [ mark MARK [ mask MASK ] ] [ reqid REQID ] [ seq SEQ ]
        [ replay-window SIZE ] [ replay-seq SEQ ] [ replay-oseq SEQ ]
        [ replay-seq-hi SEQ ] [ replay-oseq-hi SEQ ]
        [ flag FLAG-LIST ] [ sel SELECTOR ] [ LIMIT-LIST ] [ encap ENCAP ]
        [ coa ADDR[/PLEN] ] [ ctx CTX ] [ extra-flag EXTRA-FLAG-LIST ]
        [ offload [dev DEV] dir DIR ]
        [ output-mark OUTPUT-MARK [ mask MASK ] ]
        [ if_id IF_ID ] [ tfcpad LENGTH ]
ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
XFRM-PROTO := esp | ah | comp | route2 | hao
ALGO-LIST := [ ALGO-LIST ] ALGO
ALGO := {{ enc | auth }} ALGO-NAME ALGO-KEYMAT |
        auth-trunc ALGO-NAME ALGO-KEYMAT ALGO-TRUNC-LEN |
        aead ALGO-NAME ALGO-KEYMAT ALGO-ICV-LEN |
        comp ALGO-NAME
MODE := transport | tunnel | beet | ro | in_trigger
FLAG-LIST := [ FLAG-LIST ] FLAG
FLAG := noecn | decap-dscp | nopmtudisc | wildrecv | icmp | af-unspec | align4 | esn
EXTRA-FLAG-LIST := [ EXTRA-FLAG-LIST ] EXTRA-FLAG
EXTRA-FLAG := dont-encap-dscp | oseq-may-wrap
SELECTOR := [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ] [ dev DEV ] [ UPSPEC ]
UPSPEC := proto {{ {{ tcp | udp | sctp | dccp }} [ sport PORT ] [ dport PORT ] |
                  {{ icmp | ipv6-icmp | mobility-header }} [ type NUMBER ] [ code NUMBER ] |
                  gre [ key {{ DOTTED-QUAD | NUMBER }} ] | PROTO }}
LIMIT-LIST := [ LIMIT-LIST ] limit LIMIT
LIMIT := {{ time-soft | time-hard | time-use-soft | time-use-hard }} SECONDS |
         {{ byte-soft | byte-hard }} SIZE | {{ packet-soft | packet-hard }} COUNT
ENCAP := {{ espinudp | espinudp-nonike | espintcp }} SPORT DPORT OADDR
DIR := in | out

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example add_upd_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./add_upd_state {{ add | update }} ..."
    );
}

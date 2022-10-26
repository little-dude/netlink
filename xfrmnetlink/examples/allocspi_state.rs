// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{state_alloc_spi_parse_args, StateAllocSpiCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    let cli_args = match state_alloc_spi_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            usage();
            std::process::exit(1);
        }
    };

    //println!("{:?}", cli_args);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = alloc_spi_state(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }

    Ok(())
}

async fn alloc_spi_state(handle: Handle, ca: &StateAllocSpiCliArgs) -> Result<(), Error> {
    let mut req = handle
        .state()
        .alloc_spi(ca.src_addr.addr(), ca.dst_addr.addr(), ca.protocol);

    if let Some(spi_min) = ca.spi_min {
        if let Some(spi_max) = ca.spi_max {
            if spi_min < spi_max {
                req = req.spi_range(spi_min, spi_max);
            }
        }
    }

    if let Some(m) = ca.mode {
        req = req.mode(m);
    }
    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }
    if let Some(r) = ca.reqid {
        req = req.reqid(r);
    }
    if let Some(s) = ca.seq {
        req = req.seq(s);
    }
    if let Some(ifid) = ca.ifid {
        req = req.ifid(ifid);
    }

    let mut state = req.execute();
    let msg = if let Some(msg) = state.try_next().await? {
        msg
    } else {
        eprintln!("no state found");
        return Ok(());
    };
    // We should have received only one message
    assert!(state.try_next().await?.is_none());
    println!("Result: {:?}", msg);

    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example allocspi_state -- proto XFRM-PROTO [ src ADDR ] [ dst ADDR ]
    [ mode MODE ] [ mark MARK [ mask MASK ] ] [ reqid REQID ] [ seq SEQ ] [ if_id IF_ID ]
    [ min SPI max SPI ]

XFRM-PROTO := esp | ah | comp
MODE := transport | tunnel | beet | ro | in_trigger

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example del_get_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./del_get_state {{ delete | get }} ..."
    );
}

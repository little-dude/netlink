// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{state_del_get_parse_args, StateDelGetCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 3 {
        usage();
        std::process::exit(1);
    }

    let cli_args = match state_del_get_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            std::process::exit(1);
        }
    };

    //println!("{:?}", cli_args);

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if cli_args.delete {
        if let Err(e) = del_state(handle.clone(), &cli_args).await {
            eprintln!("{}", e);
        }
    } else {
        if let Err(e) = get_state(handle.clone(), &cli_args).await {
            eprintln!("{}", e);
        }
    }
    Ok(())
}

async fn get_state(handle: Handle, ca: &StateDelGetCliArgs) -> Result<(), Error> {
    let mut req = handle.state().get(
        ca.src_addr.addr(),
        ca.dst_addr.addr(),
        ca.xfrm_proto,
        ca.spi,
    );

    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
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

async fn del_state(handle: Handle, ca: &StateDelGetCliArgs) -> Result<(), Error> {
    let mut req = handle.state().delete(
        ca.src_addr.addr(),
        ca.dst_addr.addr(),
        ca.xfrm_proto,
        ca.spi,
    );

    if let Some((mark, mask)) = ca.mark_and_mask {
        req = req.mark(mark, mask);
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example del_get_state -- {{ delete | get }} ID [ mark MARK [ mask MASK ] ]

ID := [ src ADDR ] [ dst ADDR ] [ proto XFRM-PROTO ] [ spi SPI ]
XFRM-PROTO := esp | ah | comp | route2 | hao

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example del_get_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./del_get_state {{ delete | get }} ..."
    );
}

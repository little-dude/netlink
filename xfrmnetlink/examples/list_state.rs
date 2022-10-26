// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{state_dump_parse_args, StateDumpCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    let cli_args = match state_dump_parse_args(&args) {
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

    if let Err(e) = dump_states(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }

    Ok(())
}

async fn dump_states(handle: Handle, ca: &StateDumpCliArgs) -> Result<(), Error> {
    let mut req = handle.state().get_dump();

    if !ca.src_addr.addr().is_unspecified() || !ca.dst_addr.addr().is_unspecified() {
        req = req.address_filter(
            ca.src_addr.addr(),
            ca.src_addr.prefix_len(),
            ca.dst_addr.addr(),
            ca.dst_addr.prefix_len(),
        );
    }

    let mut state = req.execute();
    while let Some(msg) = state.try_next().await? {
        println!("{:?}", msg);
    }

    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example list_state -- [ src ADDR[/PLEN] ] [ dst ADDR[/PLEN] ]

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example list_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./list_state ..."
    );
}

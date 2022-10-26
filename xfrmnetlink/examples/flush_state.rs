// SPDX-License-Identifier: MIT

use std::env;

mod cli_parse;
use cli_parse::{state_flush_parse_args, StateFlushCliArgs};

use xfrmnetlink::{new_connection, Error, Handle};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().collect();

    let cli_args = match state_flush_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            usage();
            std::process::exit(1);
        }
    };

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = flush_state(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn flush_state(handle: Handle, ca: &StateFlushCliArgs) -> Result<(), Error> {
    let mut req = handle.state().flush();

    if let Some(proto) = ca.protocol {
        req = req.protocol(proto);
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example flush_state -- [ proto XFRM-PROTO ]

XFRM-PROTO := esp | ah | comp | route2 | hao

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example flush_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./flush_state"
    );
}

// SPDX-License-Identifier: MIT

use futures::stream::TryStreamExt;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        usage();
        std::process::exit(1);
    }

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = dump_policies(handle.clone()).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn dump_policies(handle: Handle) -> Result<(), Error> {
    let mut req = handle.policy().get_dump().execute();

    while let Some(msg) = req.try_next().await? {
        println!("{:?}", msg);
    }

    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example list_policy --

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example list_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./list_policy"
    );
}

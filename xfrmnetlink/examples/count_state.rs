// SPDX-License-Identifier: MIT

use std::env;

use xfrmnetlink::{new_connection, Error, Handle};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        usage();
        std::process::exit(1);
    }

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = get_sad_counts(handle.clone()).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn get_sad_counts(handle: Handle) -> Result<(), Error> {
    let sadinfo = handle.state().get_sadinfo().execute().await?;
    println!("{:?}", sadinfo);
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example count_state

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example count_state

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./count_state"
    );
}

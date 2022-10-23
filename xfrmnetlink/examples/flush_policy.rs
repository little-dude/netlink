// SPDX-License-Identifier: MIT

use std::env;

mod cli_parse;
use cli_parse::{policy_flush_parse_args, PolicyFlushCliArgs};

use xfrmnetlink::{new_connection, Error, Handle};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().collect();

    let cli_args = match policy_flush_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            usage();
            std::process::exit(1);
        }
    };

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = flush_policies(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn flush_policies(handle: Handle, ca: &PolicyFlushCliArgs) -> Result<(), Error> {
    let mut req = handle.policy().flush();

    if let Some(pt) = ca.ptype {
        req = req.ptype(pt);
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example flush_policy -- [ ptype PTYPE ]

PTYPE := main | sub

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example flush_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./flush_policy"
    );
}

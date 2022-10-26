// SPDX-License-Identifier: MIT

use std::env;

use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{policy_spd_parse_args, PolicySpdCliArgs};

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args: Vec<String> = env::args().collect();

    let cli_args = match policy_spd_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            usage();
            std::process::exit(1);
        }
    };

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if let Err(e) = set_spd_thresholds(handle.clone(), &cli_args).await {
        eprintln!("{}", e);
    }
    Ok(())
}

async fn set_spd_thresholds(handle: Handle, ca: &PolicySpdCliArgs) -> Result<(), Error> {
    let mut req = handle.policy().set_spdinfo();

    if let Some((lbits, rbits)) = ca.hthresh4 {
        req = req.hthresh4(lbits, rbits);
    }
    if let Some((lbits, rbits)) = ca.hthresh6 {
        req = req.hthresh6(lbits, rbits);
    }

    req.execute().await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example spd_policy [ hthresh4 LBITS RBITS ] [ hthresh6 LBITS RBITS ]

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example spd_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./spd_policy"
    );
}

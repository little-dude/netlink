// SPDX-License-Identifier: MIT

use netlink_packet_xfrm::constants::XFRM_USERPOLICY_UNSPEC;
use std::env;
use xfrmnetlink::{new_connection, Error, Handle};

mod cli_parse;
use cli_parse::{policy_action_parse_args, PolicyActionCliArgs};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        usage();
        std::process::exit(1);
    }

    let cli_args = match policy_action_parse_args(&args) {
        Ok(parsed_args) => parsed_args,
        Err(e) => {
            eprintln!("{}", e.to_string());
            usage();
            std::process::exit(1);
        }
    };

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);

    if cli_args.set_action {
        if let Err(e) = set_default_policy_action(handle.clone(), &cli_args).await {
            eprintln!("{}", e);
        }
    } else {
        if let Err(e) = get_default_policy_action(handle.clone()).await {
            eprintln!("{}", e);
        }
    }
    Ok(())
}

async fn get_default_policy_action(handle: Handle) -> Result<(), Error> {
    let actions = handle.policy().get_default_action().execute().await?;
    println!("{:?}", actions);
    Ok(())
}

async fn set_default_policy_action(handle: Handle, ca: &PolicyActionCliArgs) -> Result<(), Error> {
    let in_act = ca.in_action.unwrap_or(XFRM_USERPOLICY_UNSPEC);
    let fwd_act = ca.fwd_action.unwrap_or(XFRM_USERPOLICY_UNSPEC);
    let out_act = ca.out_action.unwrap_or(XFRM_USERPOLICY_UNSPEC);

    let _req = handle
        .policy()
        .set_default_action(in_act, fwd_act, out_act)
        .execute()
        .await?;
    Ok(())
}

fn usage() {
    eprintln!(
        "usage:
    cargo run --example action_policy -- {{ get }} | {{ set DIR ACTION [DIR ACTION] [DIR ACTION] }}

DIR := in | out | fwd
ACTION := allow | block

Note that you need to run this program as root. Instead of running cargo as root,
build the example normally:

    cd xfrmnetlink ; cargo build --example action_policy

Then find the binary in the target directory:

    cd ../target/debug/example ; sudo ./action_policy {{ get | set }} ..."
    );
}

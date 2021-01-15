/*
 * This example shows the mimimal manual tokio initialization required to be able
 * to use netlink.
 */

use netlink_sys::{protocols::NETLINK_AUDIT, TokioSocket};

fn main() -> Result<(), String> {
    let rt = tokio::runtime::Builder::new().enable_all().build().unwrap();

    let future = async {
        let _socket = TokioSocket::new(NETLINK_AUDIT).unwrap();
    };
    rt.handle().block_on(future);
    return Ok(());
}

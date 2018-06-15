use netlink_sys::packet::rtnl::{LinkNla};

pub struct Link {
    index: u32,
    attributes: Vec<LinkNla>,
}

// impl Link {
//     fn new
// }

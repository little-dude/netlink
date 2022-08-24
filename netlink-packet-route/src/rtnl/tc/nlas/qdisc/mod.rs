// SPDX-License-Identifier: MIT

pub mod ingress {
    pub const KIND: &str = "ingress";
}

pub mod Htb {
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct HtbGlob {
        pub version: u32,
        pub rate2quatum: u32,
        pub defcls: u32,
        pub debug: u32,
        pub direct_pkts: u32,
    }
}

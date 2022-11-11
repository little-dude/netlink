// SPDX-License-Identifier: MIT

pub mod ingress {
    pub const KIND: &str = "ingress";
}

pub mod htb {
    use crate::DecodeError;

    pub const KIND: &str = "htb";

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct HtbGlob {
        pub version: u32,
        pub rate2quatum: u32,
        pub defcls: u32,
        pub debug: u32,
        pub direct_pkts: u32,
    }

    impl HtbGlob {
        pub fn new() -> Self {
            HtbGlob {
                version: 3,
                rate2quatum: 10,
                defcls: 0,
                debug: 0,
                direct_pkts: 0,
            }
        }
    }

    pub const HTB_GLOB_LEN: usize = 20;

    buffer!(HtbGlobBuffer(HTB_GLOB_LEN) {
        version: (u32, 0..4),
        rate2quatum: (u32, 4..8),
        defcls: (u32, 8..12),
        debug: (u32, 12..16),
        direct_pkts: (u32, 16..20),
    });
}

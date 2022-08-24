pub mod TcHtb {
    use std::sync::Once;

    use netlink_packet_utils::Emitable;

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TcRateSpec {
        pub cell_log: u8,
        pub linklayer: u8,
        pub overhead: u16,
        pub cell_align: i16,
        pub mpu: u16,
        pub rate: u32,
    }

    impl TcRateSpec {
        pub fn new() -> Self {
            TcRateSpec {
                cell_log: 0,
                linklayer: 0,
                overhead: 0,
                cell_align: 0,
                mpu: 0,
                rate: 0,
            }
        }
    }

    impl Emitable for TcRateSpec {
        fn buffer_len(&self) -> usize {
            12
        }

        fn emit(&self, buffer: &mut [u8]) {
            todo!()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct TcHtbOpt {
        pub rate: TcRateSpec,
        pub ceil: TcRateSpec,
        pub buffer: u32,
        pub cbuffer: u32,
        pub quantum: u32,
        pub level: u32,
        pub prio: u32,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct TcCore {
        pub clock_factor: f64,
        pub tick_in_usec: f64,
        pub hz: f64,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum LinkLayer {
        LinklayerUnspec,
        LinklayerEthernet,
        LinklayerAtm,
    }
}

pub mod tc_htb {
    use crate::DecodeError;
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

    const TC_RATE_SPEC_LEN: usize = 12;
    buffer!(TcRateSpecBuffer(TC_RATE_SPEC_LEN) {
        cell_log: (u8, 0),
        linklayer: (u8, 1),
        overhead: (u16, 2..4),
        cell_align: (i16, 4..6),
        mpu: (u16, 6..8),
        rate: (u32, 8..12),
    });

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
            TC_RATE_SPEC_LEN
        }

        fn emit(&self, buffer: &mut [u8]) {
            let mut buf = TcRateSpecBuffer::new(buffer);
            buf.set_cell_log(self.cell_log);
            buf.set_linklayer(self.linklayer);
            buf.set_overhead(self.overhead);
            buf.set_cell_align(self.cell_align);
            buf.set_mpu(self.mpu);
            buf.set_rate(self.rate);
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

    const TC_HTB_OPT_LEN: usize = TC_RATE_SPEC_LEN * 2 + 20;

    buffer!(TcHtbOptBuffer(TC_HTB_OPT_LEN) {
        rate: (slice, 0..TC_RATE_SPEC_LEN),
        ceil: (slice,TC_RATE_SPEC_LEN..2*TC_RATE_SPEC_LEN),
        buffer: (u32, 2*TC_RATE_SPEC_LEN..2*TC_RATE_SPEC_LEN+4),
        cbuffer: (u32, 2*TC_RATE_SPEC_LEN+4..2*TC_RATE_SPEC_LEN+8),
        quantum: (u32, 2*TC_RATE_SPEC_LEN+8..2*TC_RATE_SPEC_LEN+12),
        level: (u32,2*TC_RATE_SPEC_LEN+12..2*TC_RATE_SPEC_LEN+16),
        prio: (u32,2*TC_RATE_SPEC_LEN+16..2*TC_RATE_SPEC_LEN+20),
    });

    impl Emitable for TcHtbOpt {
        fn buffer_len(&self) -> usize {
            TC_RATE_SPEC_LEN * 2 + 20
        }

        fn emit(&self, buffer: &mut [u8]) {
            let mut buf = TcHtbOptBuffer::new(buffer);
            self.rate.emit(buf.rate_mut());
            self.ceil.emit(buf.ceil_mut());
            buf.set_buffer(self.buffer);
            buf.set_cbuffer(self.cbuffer);
            buf.set_quantum(self.quantum);
            buf.set_level(self.level);
            buf.set_prio(self.prio);
        }
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

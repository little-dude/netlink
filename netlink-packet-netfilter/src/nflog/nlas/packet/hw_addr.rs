// SPDX-License-Identifier: MIT

use crate::{constants::NFULA_HWADDR, nla::Nla, traits::Parseable, utils::buffer, DecodeError};

const HW_ADDR_LEN: usize = 12;

buffer!(HwAddrBuffer(HW_ADDR_LEN) {
    hw_addr_len: (u16, 0..2),
    hw_addr_0: (u8, 4),
    hw_addr_1: (u8, 5),
    hw_addr_2: (u8, 6),
    hw_addr_3: (u8, 7),
    hw_addr_4: (u8, 8),
    hw_addr_5: (u8, 9),
    hw_addr_6: (u8, 10),
    hw_addr_7: (u8, 11),
});

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HwAddr {
    len: u16,
    address: [u8; 8],
}

impl Nla for HwAddr {
    fn value_len(&self) -> usize {
        HW_ADDR_LEN
    }

    fn kind(&self) -> u16 {
        NFULA_HWADDR
    }

    fn emit_value(&self, buf: &mut [u8]) {
        let mut buf = HwAddrBuffer::new(buf);
        buf.set_hw_addr_len(self.len.to_be());
        buf.set_hw_addr_0(self.address[0]);
        buf.set_hw_addr_1(self.address[1]);
        buf.set_hw_addr_2(self.address[2]);
        buf.set_hw_addr_3(self.address[3]);
        buf.set_hw_addr_4(self.address[4]);
        buf.set_hw_addr_5(self.address[5]);
        buf.set_hw_addr_6(self.address[6]);
        buf.set_hw_addr_7(self.address[7]);
    }
}

impl<T: AsRef<[u8]>> Parseable<HwAddrBuffer<T>> for HwAddr {
    fn parse(buf: &HwAddrBuffer<T>) -> Result<Self, DecodeError> {
        Ok(HwAddr {
            len: u16::from_be(buf.hw_addr_len()),
            address: [
                buf.hw_addr_0(),
                buf.hw_addr_1(),
                buf.hw_addr_2(),
                buf.hw_addr_3(),
                buf.hw_addr_4(),
                buf.hw_addr_5(),
                buf.hw_addr_6(),
                buf.hw_addr_7(),
            ],
        })
    }
}

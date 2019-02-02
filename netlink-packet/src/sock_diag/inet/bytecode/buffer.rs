use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::ptr::NonNull;

use byteorder::{ByteOrder, NativeEndian};

use crate::inet::raw::{
    byte_code, byte_code::*, inet_diag_bc_op, inet_diag_hostcond, inet_diag_markcond,
};
use crate::{
    constants::{AF_INET, AF_INET6},
    Field, Rest,
};

const BC_OP_CODE: usize = 0;
const BC_OP_YES: usize = 1;
const BC_OP_NO: Field = 2..4;
const BC_OP_COND: Rest = BC_OP_NO.end..;
pub const BC_OP_MIN_SIZE: usize = BC_OP_NO.end;

const HOSTCOND_FAMILY: usize = 0;
const HOSTCOND_PREFIX_LEN: usize = 1;
const HOSTCOND_PORT: Field = 4..8;
const HOSTCOND_ADDR: Rest = HOSTCOND_PORT.end..;
pub const HOSTCOND_SIZE: usize = HOSTCOND_PORT.end;

pub const IPV4_ADDR_LEN: usize = 4;
pub const IPV6_ADDR_LEN: usize = 16;

const MARKCOND_MARK: Field = 0..4;
const MARKCOND_MASK: Field = 4..8;
pub const MARKCOND_SIZE: usize = MARKCOND_MASK.end;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ByteCodeBuffer<T> {
    buf: T,
}

impl<T> Deref for ByteCodeBuffer<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<T> ByteCodeBuffer<T> {
    pub fn new(buf: T) -> Self {
        Self { buf }
    }

    pub fn into_inner(self) -> T {
        self.buf
    }
}

impl<T: AsRef<[u8]>> ByteCodeBuffer<T> {
    pub fn as_raw(&self) -> NonNull<inet_diag_bc_op> {
        let data = self.buf.as_ref();
        debug_assert!(data.len() >= mem::size_of::<inet_diag_bc_op>());
        unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
    }

    pub fn code(&self) -> u8 {
        let data = self.buf.as_ref();
        data[BC_OP_CODE]
    }

    pub fn yes(&self) -> u8 {
        let data = self.buf.as_ref();
        data[BC_OP_YES]
    }

    pub fn no(&self) -> u16 {
        let data = self.buf.as_ref();
        NativeEndian::read_u16(&data[BC_OP_NO])
    }

    pub fn cond(&self) -> &[u8] {
        let data = self.buf.as_ref();
        &data[BC_OP_COND]
    }

    pub fn ifindex(&self) -> u32 {
        NativeEndian::read_u32(self.cond())
    }

    pub fn port(&self) -> u16 {
        ByteCodeBuffer::new(self.cond()).no()
    }

    pub fn host_cond(&self) -> HostCondBuffer<&[u8]> {
        HostCondBuffer { buf: self.cond() }
    }

    pub fn mark_cond(&self) -> MarkCondBuffer<&[u8]> {
        MarkCondBuffer { buf: self.cond() }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ByteCodeBuffer<T> {
    pub fn set_code(&mut self, code: byte_code) {
        let data = self.buf.as_mut();
        data[BC_OP_CODE] = code as u8;
    }

    pub fn set_yes(&mut self, yes: u8) {
        let data = self.buf.as_mut();
        data[BC_OP_YES] = yes;
    }

    pub fn set_no(&mut self, no: u16) {
        let data = self.buf.as_mut();
        NativeEndian::write_u16(&mut data[BC_OP_NO], no);
    }

    pub fn cond_mut(&mut self) -> &mut [u8] {
        let data = self.buf.as_mut();
        &mut data[BC_OP_COND]
    }

    pub fn set_ifindex(&mut self, ifindex: u32) {
        NativeEndian::write_u32(self.cond_mut(), ifindex);
    }

    pub fn set_port(&mut self, port: u16) {
        let mut buf = ByteCodeBuffer::new(self.cond_mut());
        buf.set_code(INET_DIAG_BC_NOP);
        buf.set_yes(0);
        buf.set_no(port);
    }

    pub fn host_cond_mut(&mut self) -> HostCondBuffer<&mut [u8]> {
        HostCondBuffer {
            buf: self.cond_mut(),
        }
    }

    pub fn mark_cond_mut(&mut self) -> MarkCondBuffer<&mut [u8]> {
        MarkCondBuffer {
            buf: self.cond_mut(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HostCondBuffer<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> HostCondBuffer<T> {
    pub fn as_raw(&self) -> NonNull<inet_diag_hostcond> {
        let data = self.buf.as_ref();
        debug_assert!(data.len() >= mem::size_of::<inet_diag_hostcond>());
        unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
    }

    pub fn family(&self) -> u8 {
        let data = self.buf.as_ref();
        data[HOSTCOND_FAMILY]
    }
    pub fn prefix_len(&self) -> u8 {
        let data = self.buf.as_ref();
        data[HOSTCOND_PREFIX_LEN]
    }
    pub fn port(&self) -> u32 {
        let data = self.buf.as_ref();
        NativeEndian::read_u32(&data[HOSTCOND_PORT])
    }
    pub fn addr(&self) -> Option<IpAddr> {
        let data = self.buf.as_ref();
        let data = &data[HOSTCOND_ADDR];

        match u16::from(self.family()) {
            AF_INET if data.len() >= IPV4_ADDR_LEN => {
                let mut octets = [0; IPV4_ADDR_LEN];
                octets.copy_from_slice(&data[..IPV4_ADDR_LEN]);
                Some(Ipv4Addr::from(octets).into())
            }
            AF_INET6 if data.len() >= IPV6_ADDR_LEN => {
                let mut octets = [0; IPV6_ADDR_LEN];
                octets.copy_from_slice(&data[..IPV6_ADDR_LEN]);
                Some(Ipv6Addr::from(octets).into())
            }
            _ => None,
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HostCondBuffer<T> {
    pub fn set_family(&mut self, family: u8) {
        let data = self.buf.as_mut();
        data[HOSTCOND_FAMILY] = family;
    }
    pub fn set_prefix_len(&mut self, prefix_len: u8) {
        let data = self.buf.as_mut();
        data[HOSTCOND_PREFIX_LEN] = prefix_len;
    }
    pub fn set_port(&mut self, port: u16) {
        let data = self.buf.as_mut();
        NativeEndian::write_u32(&mut data[HOSTCOND_PORT], u32::from(port));
    }
    pub fn set_addr(&mut self, addr: &IpAddr) {
        let data = self.buf.as_mut();
        let data = &mut data[HOSTCOND_ADDR];

        match addr {
            IpAddr::V4(addr) => {
                let data = &mut data[..IPV4_ADDR_LEN];
                data.copy_from_slice(&addr.octets()[..]);
            }
            IpAddr::V6(addr) => {
                let data = &mut data[..IPV6_ADDR_LEN];
                data.copy_from_slice(&addr.octets()[..]);
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MarkCondBuffer<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> MarkCondBuffer<T> {
    pub fn as_raw(&self) -> NonNull<inet_diag_markcond> {
        let data = self.buf.as_ref();
        debug_assert!(data.len() >= mem::size_of::<inet_diag_markcond>());
        unsafe { NonNull::new_unchecked(data.as_ptr() as *mut u8) }.cast()
    }

    pub fn mark(&self) -> u32 {
        let data = self.buf.as_ref();
        NativeEndian::read_u32(&data[MARKCOND_MARK])
    }
    pub fn mask(&self) -> u32 {
        let data = self.buf.as_ref();
        NativeEndian::read_u32(&data[MARKCOND_MASK])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> MarkCondBuffer<T> {
    pub fn set_mark(&mut self, mark: u32) {
        let data = self.buf.as_mut();
        NativeEndian::write_u32(&mut data[MARKCOND_MARK], mark);
    }
    pub fn set_mask(&mut self, mask: u32) {
        let data = self.buf.as_mut();
        NativeEndian::write_u32(&mut data[MARKCOND_MASK], mask);
    }
}

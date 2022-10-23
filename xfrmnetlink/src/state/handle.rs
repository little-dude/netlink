// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use super::{
    StateAllocSpiRequest, StateDeleteRequest, StateFlushRequest, StateGetDumpRequest,
    StateGetRequest, StateGetSadInfoRequest, StateModifyRequest,
};
use crate::Handle;

pub struct StateHandle(Handle);

impl StateHandle {
    pub fn new(handle: Handle) -> Self {
        StateHandle(handle)
    }

    /// Add xfrm state (equivalent to `ip xfrm state add`)
    pub fn add(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> StateModifyRequest {
        StateModifyRequest::new(self.0.clone(), false, src_addr, dst_addr, protocol, spi)
    }

    /// Ask kernel to reserve a SPI for xfrm state (equivalent to `ip xfrm state allocspi`)
    pub fn alloc_spi(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
    ) -> StateAllocSpiRequest {
        StateAllocSpiRequest::new(self.0.clone(), src_addr, dst_addr, protocol)
    }

    /// Delete xfrm state (equivalent to `ip xfrm state delete`)
    pub fn delete(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> StateDeleteRequest {
        StateDeleteRequest::new(self.0.clone(), src_addr, dst_addr, protocol, spi)
    }

    /// Flush xfrm state (equivalent to `ip xfrm state flush`)
    pub fn flush(&self) -> StateFlushRequest {
        StateFlushRequest::new(self.0.clone())
    }

    /// Get xfrm state (equivalent to `ip xfrm state get`)
    pub fn get(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> StateGetRequest {
        StateGetRequest::new(self.0.clone(), src_addr, dst_addr, protocol, spi)
    }

    /// Get (dump) all xfrm states (equivalent to `ip xfrm state list`)
    pub fn get_dump(&self) -> StateGetDumpRequest {
        StateGetDumpRequest::new(self.0.clone())
    }

    /// Get xfrm sad statistics (equivalent to `ip xfrm state count`)
    pub fn get_sadinfo(&self) -> StateGetSadInfoRequest {
        StateGetSadInfoRequest::new(self.0.clone())
    }

    /// Update xfrm state (equivalent to `ip xfrm state update`)
    pub fn update(
        &self,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> StateModifyRequest {
        StateModifyRequest::new(self.0.clone(), true, src_addr, dst_addr, protocol, spi)
    }
}

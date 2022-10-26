// SPDX-License-Identifier: MIT

use std::net::IpAddr;

use super::{
    PolicyDeleteRequest, PolicyFlushRequest, PolicyGetDefaultRequest, PolicyGetRequest,
    PolicyGetSpdInfoRequest, PolicyModifyRequest, PolicySetDefaultRequest, PolicySetSpdInfoRequest,
};
use crate::Handle;

pub struct PolicyHandle(Handle);

impl PolicyHandle {
    pub fn new(handle: Handle) -> Self {
        PolicyHandle(handle)
    }

    /// Add xfrm policy (equivalent to `ip xfrm policy add`)
    pub fn add(
        &self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
        direction: u8,
        action: u8,
    ) -> PolicyModifyRequest {
        PolicyModifyRequest::new(
            self.0.clone(),
            false,
            src_addr,
            src_prefix_len,
            dst_addr,
            dst_prefix_len,
            direction,
            action,
        )
    }

    /// Delete xfrm policy specifying selector parameters (equivalent to `ip xfrm policy delete <selector>`)
    pub fn delete(
        &self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
        direction: u8,
    ) -> PolicyDeleteRequest {
        PolicyDeleteRequest::new(
            self.0.clone(),
            src_addr,
            src_prefix_len,
            dst_addr,
            dst_prefix_len,
            direction,
        )
    }

    /// Delete xfrm policy specifying the index (equivalent to `ip xfrm policy delete index`)
    pub fn delete_index(&self, index: u32, direction: u8) -> PolicyDeleteRequest {
        PolicyDeleteRequest::new_index(self.0.clone(), index, direction)
    }

    /// Flush xfrm policies (equivalent to `ip xfrm policy flush`)
    pub fn flush(&self) -> PolicyFlushRequest {
        PolicyFlushRequest::new(self.0.clone())
    }

    /// Get xfrm policy (equivalent to `ip xfrm policy get <selector>`)
    pub fn get(
        &self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
        direction: u8,
    ) -> PolicyGetRequest {
        PolicyGetRequest::new(
            self.0.clone(),
            src_addr,
            src_prefix_len,
            dst_addr,
            dst_prefix_len,
            direction,
        )
    }

    /// Get the default xfrm action for input, output, forward policies (equivalent to `ip xfrm policy getdefault`)
    pub fn get_default_action(&self) -> PolicyGetDefaultRequest {
        PolicyGetDefaultRequest::new(self.0.clone())
    }

    /// Get (dump) all xfrm policies (equivalent to `ip xfrm policy list`)
    pub fn get_dump(&self) -> PolicyGetRequest {
        PolicyGetRequest::new_dump(self.0.clone())
    }

    /// Get xfrm policy specifying the index (equivalent to `ip xfrm policy get index`)
    pub fn get_index(&self, index: u32, direction: u8) -> PolicyGetRequest {
        PolicyGetRequest::new_index(self.0.clone(), index, direction)
    }

    /// Get xfrm spd statistics (equivalent to `ip xfrm policy count`)
    pub fn get_spdinfo(&self) -> PolicyGetSpdInfoRequest {
        PolicyGetSpdInfoRequest::new(self.0.clone())
    }

    /// Set the default xfrm action for input, output, forward policies (equivalent to `ip xfrm policy setdefault`)
    pub fn set_default_action(
        &self,
        in_act: u8,
        fwd_act: u8,
        out_act: u8,
    ) -> PolicySetDefaultRequest {
        PolicySetDefaultRequest::new(self.0.clone(), in_act, fwd_act, out_act)
    }

    /// Set xfrm spd statistics (equivalent to `ip xfrm policy set`)
    pub fn set_spdinfo(&self) -> PolicySetSpdInfoRequest {
        PolicySetSpdInfoRequest::new(self.0.clone())
    }

    /// Update xfrm policy (equivalent to `ip xfrm policy update`)
    pub fn update(
        &self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
        direction: u8,
        action: u8,
    ) -> PolicyModifyRequest {
        PolicyModifyRequest::new(
            self.0.clone(),
            true,
            src_addr,
            src_prefix_len,
            dst_addr,
            dst_prefix_len,
            direction,
            action,
        )
    }
}

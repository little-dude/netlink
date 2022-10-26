// SPDX-License-Identifier: MIT

use futures::stream::StreamExt;
use std::ffi::CString;
use std::net::IpAddr;

use netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};

use netlink_packet_xfrm::{
    constants::*, state::ModifyMessage, Address, Alg, AlgAead, AlgAuth, EncapTmpl, Mark, Replay,
    ReplayEsn, SecurityCtx, UserOffloadDev, XfrmAttrs, XfrmMessage, XFRM_ALG_AEAD_NAME_LEN,
    XFRM_ALG_AUTH_NAME_LEN, XFRM_ALG_NAME_LEN,
};

use crate::{try_nl, Error, Handle};

/// A request to add or update xfrm state. This is equivalent to the `ip xfrm state add|update` commands.
pub struct StateModifyRequest {
    handle: Handle,
    message: ModifyMessage,
    update: bool,
}

impl StateModifyRequest {
    pub(crate) fn new(
        handle: Handle,
        update: bool,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        protocol: u8,
        spi: u32,
    ) -> Self {
        let mut message = ModifyMessage::default();

        match src_addr {
            IpAddr::V4(ipv4) => {
                message.user_sa_info.saddr = Address::from_ipv4(&ipv4);
                message.user_sa_info.family = AF_INET;
            }
            IpAddr::V6(ipv6) => {
                message.user_sa_info.saddr = Address::from_ipv6(&ipv6);
                message.user_sa_info.family = AF_INET6;
            }
        }

        match dst_addr {
            IpAddr::V4(ipv4) => {
                message.user_sa_info.id.daddr = Address::from_ipv4(&ipv4);
            }
            IpAddr::V6(ipv6) => {
                message.user_sa_info.id.daddr = Address::from_ipv6(&ipv6);
            }
        }

        message.user_sa_info.id.proto = protocol;
        message.user_sa_info.id.spi = spi;

        StateModifyRequest {
            handle,
            message,
            update,
        }
    }

    pub fn authentication(mut self, alg_name: &str, key: &Vec<u8>) -> Result<Self, Error> {
        let mut auth_name: [u8; XFRM_ALG_NAME_LEN] = [0; XFRM_ALG_NAME_LEN];
        let mut c_auth_name = CString::new(alg_name)
            .map_err(|_| Error::AlgName(alg_name.to_string()))?
            .into_bytes_with_nul();

        if c_auth_name.len() > XFRM_ALG_NAME_LEN {
            c_auth_name.truncate(XFRM_ALG_NAME_LEN);
            c_auth_name[XFRM_ALG_NAME_LEN - 1] = 0;
        }
        auth_name[0..c_auth_name.len()].copy_from_slice(c_auth_name.as_slice());

        let alg_auth = Alg {
            alg_name: auth_name,
            alg_key_len: (key.len() * 8) as u32,
            alg_key: key.clone(),
        };

        self.message
            .nlas
            .push(XfrmAttrs::AuthenticationAlg(alg_auth));
        Ok(self)
    }

    pub fn authentication_trunc(
        mut self,
        alg_name: &str,
        key: &Vec<u8>,
        trunc_len: u32,
    ) -> Result<Self, Error> {
        let mut auth_name: [u8; XFRM_ALG_AUTH_NAME_LEN] = [0; XFRM_ALG_AUTH_NAME_LEN];
        let mut c_auth_name = CString::new(alg_name)
            .map_err(|_| Error::AlgName(alg_name.to_string()))?
            .into_bytes_with_nul();

        if c_auth_name.len() > XFRM_ALG_AUTH_NAME_LEN {
            c_auth_name.truncate(XFRM_ALG_AUTH_NAME_LEN);
            c_auth_name[XFRM_ALG_AUTH_NAME_LEN - 1] = 0;
        }
        auth_name[0..c_auth_name.len()].copy_from_slice(c_auth_name.as_slice());

        let alg_auth = AlgAuth {
            alg_name: auth_name,
            alg_key_len: (key.len() * 8) as u32,
            alg_trunc_len: trunc_len,
            alg_key: key.clone(),
        };

        self.message
            .nlas
            .push(XfrmAttrs::AuthenticationAlgTrunc(alg_auth));
        Ok(self)
    }

    pub fn compression(mut self, alg_name: &str) -> Result<Self, Error> {
        let mut comp_name: [u8; XFRM_ALG_NAME_LEN] = [0; XFRM_ALG_NAME_LEN];
        let mut c_comp_name = CString::new(alg_name)
            .map_err(|_| Error::AlgName(alg_name.to_string()))?
            .into_bytes_with_nul();

        if c_comp_name.len() > XFRM_ALG_NAME_LEN {
            c_comp_name.truncate(XFRM_ALG_NAME_LEN);
            c_comp_name[XFRM_ALG_NAME_LEN - 1] = 0;
        }
        comp_name[0..c_comp_name.len()].copy_from_slice(c_comp_name.as_slice());

        let alg_comp = Alg {
            alg_name: comp_name,
            alg_key_len: 0,
            alg_key: Default::default(),
        };

        self.message.nlas.push(XfrmAttrs::CompressionAlg(alg_comp));
        Ok(self)
    }

    pub fn encryption(mut self, alg_name: &str, key: &Vec<u8>) -> Result<Self, Error> {
        let mut enc_name: [u8; XFRM_ALG_NAME_LEN] = [0; XFRM_ALG_NAME_LEN];
        let mut c_enc_name = CString::new(alg_name)
            .map_err(|_| Error::AlgName(alg_name.to_string()))?
            .into_bytes_with_nul();

        if c_enc_name.len() > XFRM_ALG_NAME_LEN {
            c_enc_name.truncate(XFRM_ALG_NAME_LEN);
            c_enc_name[XFRM_ALG_NAME_LEN - 1] = 0;
        }
        enc_name[0..c_enc_name.len()].copy_from_slice(c_enc_name.as_slice());

        let alg_enc = Alg {
            alg_name: enc_name,
            alg_key_len: (key.len() * 8) as u32,
            alg_key: key.clone(),
        };

        self.message.nlas.push(XfrmAttrs::EncryptionAlg(alg_enc));
        Ok(self)
    }

    // icv_len should be in bits
    pub fn encryption_aead(
        mut self,
        alg_name: &str,
        key: &Vec<u8>,
        icv_len: u32,
    ) -> Result<Self, Error> {
        let mut enc_name: [u8; XFRM_ALG_AEAD_NAME_LEN] = [0; XFRM_ALG_AEAD_NAME_LEN];
        let mut c_enc_name = CString::new(alg_name)
            .map_err(|_| Error::AlgName(alg_name.to_string()))?
            .into_bytes_with_nul();

        if c_enc_name.len() > XFRM_ALG_AEAD_NAME_LEN {
            c_enc_name.truncate(XFRM_ALG_AEAD_NAME_LEN);
            c_enc_name[XFRM_ALG_AEAD_NAME_LEN - 1] = 0;
        }
        enc_name[0..c_enc_name.len()].copy_from_slice(c_enc_name.as_slice());

        let alg_enc = AlgAead {
            alg_name: enc_name,
            alg_key_len: (key.len() * 8) as u32,
            alg_icv_len: icv_len,
            alg_key: key.clone(),
        };

        self.message
            .nlas
            .push(XfrmAttrs::EncryptionAlgAead(alg_enc));
        Ok(self)
    }

    pub fn mode(mut self, mode: u8) -> Self {
        self.message.user_sa_info.mode = mode;
        self
    }
    pub fn reqid(mut self, reqid: u32) -> Self {
        self.message.user_sa_info.reqid = reqid;
        self
    }
    // iproute2 may be handling this incorrectly, either by
    // treating it as big-endian or by displaying it as hex instead of dec,
    // or some combination of the two. More investigation needed.
    pub fn seq(mut self, seq: u32) -> Self {
        self.message.user_sa_info.seq = seq;
        self
    }
    pub fn flags(mut self, flags: u8) -> Self {
        self.message.user_sa_info.flags = flags;
        self
    }
    pub fn extra_flags(mut self, flags: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::ExtraFlags(flags));
        self
    }
    pub fn security_context(mut self, secctx: &Vec<u8>) -> Self {
        let mut sc = SecurityCtx::default();

        sc.context(secctx);
        self.message.nlas.push(XfrmAttrs::SecurityContext(sc));
        self
    }
    pub fn ifid(mut self, ifid: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::IfId(ifid));
        self
    }
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::Mark(Mark { value: mark, mask }));
        self
    }
    pub fn output_mark(mut self, mark: u32, mask: u32) -> Self {
        if mark > 0 {
            self.message.nlas.push(XfrmAttrs::MarkVal(mark));
        }
        if mask > 0 {
            self.message.nlas.push(XfrmAttrs::MarkMask(mask));
        }
        self
    }
    // Traffic Flow Confidentiality padding
    pub fn tfc_pad_length(mut self, len: u32) -> Self {
        self.message.nlas.push(XfrmAttrs::TfcPadding(len));
        self
    }

    pub fn replay_window(
        mut self,
        size: u32,
        seq: u32,
        seq_hi: u32,
        offload_seq: u32,
        offload_seq_hi: u32,
    ) -> Self {
        if (size > u32::BITS)
            || (self.message.user_sa_info.flags & XFRM_STATE_ESN) == XFRM_STATE_ESN
        {
            let bmp_len: u32 = (size + u32::BITS - 1) / u32::BITS;
            let replay_esn = ReplayEsn {
                bmp_len,
                oseq: offload_seq,
                seq,
                oseq_hi: offload_seq_hi,
                seq_hi,
                replay_window: size,
                bmp: Vec::default(),
            };
            self.message
                .nlas
                .push(XfrmAttrs::ReplayStateEsn(replay_esn));
        } else {
            if seq != 0 || offload_seq != 0 {
                let replay = Replay {
                    seq,
                    oseq: offload_seq,
                    bitmap: 0,
                };
                self.message.nlas.push(XfrmAttrs::ReplayState(replay));
            }
            self.message.user_sa_info.replay_window = size as u8;
        }
        self
    }

    pub fn time_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message
            .user_sa_info
            .lifetime_cfg
            .soft_add_expires_seconds = soft;
        self.message
            .user_sa_info
            .lifetime_cfg
            .hard_add_expires_seconds = hard;
        self
    }
    pub fn time_use_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message
            .user_sa_info
            .lifetime_cfg
            .soft_use_expires_seconds = soft;
        self.message
            .user_sa_info
            .lifetime_cfg
            .hard_use_expires_seconds = hard;
        self
    }
    pub fn byte_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message.user_sa_info.lifetime_cfg.soft_byte_limit = soft;
        self.message.user_sa_info.lifetime_cfg.hard_byte_limit = hard;
        self
    }
    pub fn packet_limit(mut self, soft: u64, hard: u64) -> Self {
        self.message.user_sa_info.lifetime_cfg.soft_packet_limit = soft;
        self.message.user_sa_info.lifetime_cfg.hard_packet_limit = hard;
        self
    }
    pub fn selector_addresses(
        mut self,
        src_addr: IpAddr,
        src_prefix_len: u8,
        dst_addr: IpAddr,
        dst_prefix_len: u8,
    ) -> Self {
        match src_addr {
            IpAddr::V4(ipv4) => {
                self.message.user_sa_info.selector.saddr = Address::from_ipv4(&ipv4);
                if ipv4.is_unspecified() {
                    self.message.user_sa_info.selector.prefixlen_s = 0;
                } else {
                    self.message.user_sa_info.selector.prefixlen_s = src_prefix_len;
                }
                self.message.user_sa_info.selector.family = AF_INET;
            }
            IpAddr::V6(ipv6) => {
                self.message.user_sa_info.selector.saddr = Address::from_ipv6(&ipv6);
                if ipv6.is_unspecified() {
                    self.message.user_sa_info.selector.prefixlen_s = 0;
                } else {
                    self.message.user_sa_info.selector.prefixlen_s = src_prefix_len;
                }
                self.message.user_sa_info.selector.family = AF_INET6;
            }
        }

        match dst_addr {
            IpAddr::V4(ipv4) => {
                self.message.user_sa_info.selector.daddr = Address::from_ipv4(&ipv4);
                if ipv4.is_unspecified() {
                    self.message.user_sa_info.selector.prefixlen_d = 0;
                } else {
                    self.message.user_sa_info.selector.prefixlen_d = dst_prefix_len;
                }
            }
            IpAddr::V6(ipv6) => {
                self.message.user_sa_info.selector.daddr = Address::from_ipv6(&ipv6);
                if ipv6.is_unspecified() {
                    self.message.user_sa_info.selector.prefixlen_d = 0;
                } else {
                    self.message.user_sa_info.selector.prefixlen_d = dst_prefix_len;
                }
            }
        }

        self
    }
    pub fn selector_protocol(mut self, proto: u8) -> Self {
        self.message.user_sa_info.selector.proto = proto;
        self
    }
    pub fn selector_protocol_src_port(mut self, port: u16) -> Self {
        self.message.user_sa_info.selector.sport = port;
        self.message.user_sa_info.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_dst_port(mut self, port: u16) -> Self {
        self.message.user_sa_info.selector.dport = port;
        self.message.user_sa_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_type(mut self, proto_type: u8) -> Self {
        self.message.user_sa_info.selector.sport = proto_type as u16;
        self.message.user_sa_info.selector.sport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_code(mut self, proto_code: u8) -> Self {
        self.message.user_sa_info.selector.dport = proto_code as u16;
        self.message.user_sa_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_protocol_gre_key(mut self, gre_key: u32) -> Self {
        self.message.user_sa_info.selector.sport = (gre_key >> 16) as u16;
        self.message.user_sa_info.selector.sport_mask = u16::MAX;
        self.message.user_sa_info.selector.dport = (gre_key & 0xffff) as u16;
        self.message.user_sa_info.selector.dport_mask = u16::MAX;
        self
    }
    pub fn selector_dev_id(mut self, id: u32) -> Self {
        self.message.user_sa_info.selector.ifindex = id as i32;
        self
    }

    pub fn encapsulation(
        mut self,
        encap_type: u16,
        src_port: u16,
        dst_port: u16,
        outside_addr: IpAddr,
    ) -> Self {
        let mut encap_tmpl = EncapTmpl {
            encap_type,
            encap_sport: src_port,
            encap_dport: dst_port,
            encap_oa: Address::default(),
        };

        match outside_addr {
            IpAddr::V4(ipv4) => {
                encap_tmpl.encap_oa = Address::from_ipv4(&ipv4);
            }
            IpAddr::V6(ipv6) => {
                encap_tmpl.encap_oa = Address::from_ipv6(&ipv6);
            }
        }

        self.message
            .nlas
            .push(XfrmAttrs::EncapsulationTemplate(encap_tmpl));
        self
    }

    // only used for routing protocols (xfrm proto route2 & hao)
    pub fn care_of_address(mut self, co_addr: IpAddr) -> Self {
        match co_addr {
            IpAddr::V4(ipv4) => {
                self.message
                    .nlas
                    .push(XfrmAttrs::CareOfAddr(Address::from_ipv4(&ipv4)));
            }
            IpAddr::V6(ipv6) => {
                self.message
                    .nlas
                    .push(XfrmAttrs::CareOfAddr(Address::from_ipv6(&ipv6)));
            }
        }
        self
    }

    // flags can be XFRM_OFFLOAD_IPV6 or XFRM_OFFLOAD_INBOUND
    pub fn offload_device(mut self, id: u32, flags: u8) -> Self {
        self.message
            .nlas
            .push(XfrmAttrs::OffloadDevice(UserOffloadDev {
                ifindex: id as i32,
                flags,
            }));
        self
    }

    /// Execute the request.
    pub async fn execute(self) -> Result<(), Error> {
        let StateModifyRequest {
            mut handle,
            message,
            update,
        } = self;

        let mut req = if update {
            NetlinkMessage::from(XfrmMessage::UpdateSa(message))
        } else {
            NetlinkMessage::from(XfrmMessage::AddSa(message))
        };
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        let mut response = handle.request(req)?;

        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    /// Execute the request without waiting for an ACK response.
    pub fn execute_noack(self) -> Result<(), Error> {
        let StateModifyRequest {
            mut handle,
            message,
            update,
        } = self;

        let mut req = if update {
            NetlinkMessage::from(XfrmMessage::UpdateSa(message))
        } else {
            NetlinkMessage::from(XfrmMessage::AddSa(message))
        };
        req.header.flags = NLM_F_REQUEST;

        let mut _response = handle.request(req)?;

        Ok(())
    }

    /// Return a mutable reference to the request message.
    pub fn message_mut(&mut self) -> &mut ModifyMessage {
        &mut self.message
    }
}

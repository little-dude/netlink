// SPDX-License-Identifier: MIT

// ==========================================
// XFRM message types
// ==========================================
pub const XFRM_MSG_BASE: u16 = 0x10;
pub const XFRM_MSG_NEWSA: u16 = 0x10;
pub const XFRM_MSG_DELSA: u16 = 0x11;
pub const XFRM_MSG_GETSA: u16 = 0x12;
pub const XFRM_MSG_NEWPOLICY: u16 = 0x13;
pub const XFRM_MSG_DELPOLICY: u16 = 0x14;
pub const XFRM_MSG_GETPOLICY: u16 = 0x15;
pub const XFRM_MSG_ALLOCSPI: u16 = 0x16;
pub const XFRM_MSG_ACQUIRE: u16 = 0x17;
pub const XFRM_MSG_EXPIRE: u16 = 0x18;
pub const XFRM_MSG_UPDPOLICY: u16 = 0x19;
pub const XFRM_MSG_UPDSA: u16 = 0x1a;
pub const XFRM_MSG_POLEXPIRE: u16 = 0x1b;
pub const XFRM_MSG_FLUSHSA: u16 = 0x1c;
pub const XFRM_MSG_FLUSHPOLICY: u16 = 0x1d;
pub const XFRM_MSG_NEWAE: u16 = 0x1e;
pub const XFRM_MSG_GETAE: u16 = 0x1f;
pub const XFRM_MSG_REPORT: u16 = 0x20;
pub const XFRM_MSG_MIGRATE: u16 = 0x21;
pub const XFRM_MSG_NEWSADINFO: u16 = 0x22;
pub const XFRM_MSG_GETSADINFO: u16 = 0x23;
pub const XFRM_MSG_NEWSPDINFO: u16 = 0x24;
pub const XFRM_MSG_GETSPDINFO: u16 = 0x25;
pub const XFRM_MSG_MAPPING: u16 = 0x26;
pub const XFRM_MSG_SETDEFAULT: u16 = 0x27;
pub const XFRM_MSG_GETDEFAULT: u16 = 0x28;

// ==========================================
// XFRM message attributes
// ==========================================
pub const XFRMA_UNSPEC: u16 = 0;
pub const XFRMA_ALG_AUTH: u16 = 1; /* struct xfrm_algo */
pub const XFRMA_ALG_CRYPT: u16 = 2; /* struct xfrm_algo */
pub const XFRMA_ALG_COMP: u16 = 3; /* struct xfrm_algo */
pub const XFRMA_ENCAP: u16 = 4; /* struct xfrm_algo + struct xfrm_encap_tmpl */
pub const XFRMA_TMPL: u16 = 5; /* 1 or more struct xfrm_user_tmpl */
pub const XFRMA_SA: u16 = 6; /* struct xfrm_usersa_info  */
pub const XFRMA_POLICY: u16 = 7; /* struct xfrm_userpolicy_info */
pub const XFRMA_SEC_CTX: u16 = 8; /* struct xfrm_sec_ctx */
pub const XFRMA_LTIME_VAL: u16 = 9; /* struct xfrm_lifetime_cur */
pub const XFRMA_REPLAY_VAL: u16 = 10; /* struct xfrm_replay_state */
pub const XFRMA_REPLAY_THRESH: u16 = 11; /* __u32 */
pub const XFRMA_ETIMER_THRESH: u16 = 12; /* __u32 */
pub const XFRMA_SRCADDR: u16 = 13; /* xfrm_address_t */
pub const XFRMA_COADDR: u16 = 14; /* xfrm_address_t */
pub const XFRMA_LASTUSED: u16 = 15; /* unsigned long  */
pub const XFRMA_POLICY_TYPE: u16 = 16; /* struct xfrm_userpolicy_type */
pub const XFRMA_MIGRATE: u16 = 17; /* struct xfrm_user_migrate */
pub const XFRMA_ALG_AEAD: u16 = 18; /* struct xfrm_algo_aead */
pub const XFRMA_KMADDRESS: u16 = 19; /* struct xfrm_user_kmaddress */
pub const XFRMA_ALG_AUTH_TRUNC: u16 = 20; /* struct xfrm_algo_auth */
pub const XFRMA_MARK: u16 = 21; /* struct xfrm_mark */
pub const XFRMA_TFCPAD: u16 = 22; /* __u32 */
pub const XFRMA_REPLAY_ESN_VAL: u16 = 23; /* struct xfrm_replay_state_esn */
pub const XFRMA_SA_EXTRA_FLAGS: u16 = 24; /* __u32 */
pub const XFRMA_PROTO: u16 = 25; /* __u8 */
pub const XFRMA_ADDRESS_FILTER: u16 = 26; /* struct xfrm_address_filter */
pub const XFRMA_PAD: u16 = 27;
pub const XFRMA_OFFLOAD_DEV: u16 = 28; /* struct xfrm_user_offload */
pub const XFRMA_SET_MARK: u16 = 29; /* __u32 */
pub const XFRMA_SET_MARK_MASK: u16 = 30; /* __u32 */
pub const XFRMA_IF_ID: u16 = 31; /* __u32 */
pub const XFRMA_MTIMER_THRESH: u16 = 32; /* __u32 in seconds for input SA */

// ==========================================
// XFRMA_POLICY_TYPE attribute options
// ==========================================

pub const XFRM_POLICY_TYPE_MAIN: u8 = 0;
pub const XFRM_POLICY_TYPE_SUB: u8 = 1;
pub const XFRM_POLICY_TYPE_MAX: u8 = 2;
pub const XFRM_POLICY_TYPE_ANY: u8 = 255;

// ==========================================
// XFRM Policy Direction
// ==========================================
pub const XFRM_POLICY_IN: u8 = 0;
pub const XFRM_POLICY_OUT: u8 = 1;
pub const XFRM_POLICY_FWD: u8 = 2;
pub const XFRM_POLICY_MASK: u8 = 3;
pub const XFRM_POLICY_MAX: u8 = 3;

// ==========================================
// XFRM Policy Action
// ==========================================
pub const XFRM_POLICY_ALLOW: u8 = 0;
pub const XFRM_POLICY_BLOCK: u8 = 1;

// ==========================================
// XFRM Policy Flags
// ==========================================
pub const XFRM_POLICY_LOCALOK: u8 = 1;
pub const XFRM_POLICY_ICMP: u8 = 2;

// ==========================================
// XFRM Policy Share
// ==========================================
pub const XFRM_SHARE_ANY: u8 = 0; /* No limitations */
pub const XFRM_SHARE_SESSION: u8 = 1; /* For this session only */
pub const XFRM_SHARE_USER: u8 = 2; /* For this user only */
pub const XFRM_SHARE_UNIQUE: u8 = 3;

// ==========================================
// Common Address Families
// ==========================================
pub const AF_UNSPEC: u16 = libc::AF_UNSPEC as u16; //  0
pub const AF_INET: u16 = libc::AF_INET as u16; //  2
pub const AF_BRIDGE: u16 = libc::AF_BRIDGE as u16; //  7
pub const AF_INET6: u16 = libc::AF_INET6 as u16; // 10
pub const AF_PACKET: u16 = libc::AF_PACKET as u16; // 17
pub const AF_MPLS: u16 = libc::AF_MPLS as u16; // 28

// ==========================================
// Selector Protocols
// ==========================================
pub const IPPROTO_ICMP: u8 = libc::IPPROTO_ICMP as u8; //   1
pub const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8; //   6
pub const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8; //  17
pub const IPPROTO_DCCP: u8 = libc::IPPROTO_DCCP as u8; //  33
pub const IPPROTO_GRE: u8 = libc::IPPROTO_GRE as u8; //  47
pub const IPPROTO_ICMPV6: u8 = libc::IPPROTO_ICMPV6 as u8; //  58
pub const IPPROTO_SCTP: u8 = libc::IPPROTO_SCTP as u8; // 132
pub const IPPROTO_MH: u8 = libc::IPPROTO_MH as u8; // 135

// ==========================================
// XFRM Protocols
// ==========================================
pub const IPPROTO_ROUTING: u8 = libc::IPPROTO_ROUTING as u8; //  43
pub const IPPROTO_ESP: u8 = libc::IPPROTO_ESP as u8; //  50
pub const IPPROTO_AH: u8 = libc::IPPROTO_AH as u8; //  51
pub const IPPROTO_DSTOPTS: u8 = libc::IPPROTO_DSTOPTS as u8; //  60
pub const IPPROTO_COMP: u8 = libc::IPPROTO_COMP as u8; // 108
pub const IPSEC_PROTO_ANY: u8 = 255 as u8;

// ==========================================
// XFRM Mode
// ==========================================
pub const XFRM_MODE_TRANSPORT: u8 = 0;
pub const XFRM_MODE_TUNNEL: u8 = 1;
pub const XFRM_MODE_ROUTEOPTIMIZATION: u8 = 2;
pub const XFRM_MODE_IN_TRIGGER: u8 = 3;
pub const XFRM_MODE_BEET: u8 = 4;
pub const XFRM_MODE_MAX: u8 = 5;

// ==========================================
// XFRM Policy SPD Info message attributes
// ==========================================
pub const XFRMA_SPD_UNSPEC: u16 = 0;
pub const XFRMA_SPD_INFO: u16 = 1;
pub const XFRMA_SPD_HINFO: u16 = 2;
pub const XFRMA_SPD_IPV4_HTHRESH: u16 = 3;
pub const XFRMA_SPD_IPV6_HTHRESH: u16 = 4;

// ==========================================
// XFRM Policy Default action
// ==========================================
pub const XFRM_USERPOLICY_UNSPEC: u8 = 0;
pub const XFRM_USERPOLICY_BLOCK: u8 = 1;
pub const XFRM_USERPOLICY_ACCEPT: u8 = 2;

// ==========================================
// XFRM State SAD Info message attributes
// ==========================================
pub const XFRMA_SAD_UNSPEC: u16 = 0;
pub const XFRMA_SAD_CNT: u16 = 1;
pub const XFRMA_SAD_HINFO: u16 = 2;

// ==========================================
// XFRM Security Context Domains of Interpretation
// ==========================================
pub const XFRM_SC_DOI_RESERVED: u8 = 0;
pub const XFRM_SC_DOI_LSM: u8 = 1;

// ==========================================
// XFRM Security Context Algorithms
// ==========================================
pub const XFRM_SC_ALG_RESERVED: u8 = 0;
pub const XFRM_SC_ALG_SELINUX: u8 = 1;

// ==========================================
// Async Event flags
// ==========================================
pub const XFRM_AE_UNSPEC: u32 = 0;
pub const XFRM_AE_RTHR: u32 = 1; /* replay threshold*/
pub const XFRM_AE_RVAL: u32 = 2; /* replay value */
pub const XFRM_AE_LVAL: u32 = 4; /* lifetime value */
pub const XFRM_AE_ETHR: u32 = 8; /* expiry timer threshold */
pub const XFRM_AE_CR: u32 = 16; /* Event cause is replay update */
pub const XFRM_AE_CE: u32 = 32; /* Event cause is timer expiry */
pub const XFRM_AE_CU: u32 = 64; /* Event cause is policy update */

// ==========================================
// SA Info flags
// ==========================================
pub const XFRM_STATE_NOECN: u8 = 1;
pub const XFRM_STATE_DECAP_DSCP: u8 = 2;
pub const XFRM_STATE_NOPMTUDISC: u8 = 4;
pub const XFRM_STATE_WILDRECV: u8 = 8;
pub const XFRM_STATE_ICMP: u8 = 16;
pub const XFRM_STATE_AF_UNSPEC: u8 = 32;
pub const XFRM_STATE_ALIGN4: u8 = 64;
pub const XFRM_STATE_ESN: u8 = 128;

// ==========================================
// SA Extra flags (XFRMA_SA_EXTRA_FLAGS)
// ==========================================
pub const XFRM_SA_XFLAG_DONT_ENCAP_DSCP: u32 = 1;
pub const XFRM_SA_XFLAG_OSEQ_MAY_WRAP: u32 = 2;

// ==========================================
// Offload flags (XFRMA_OFFLOAD_DEV)
// ==========================================
pub const XFRM_OFFLOAD_IPV6: u8 = 1;
pub const XFRM_OFFLOAD_INBOUND: u8 = 2;

// ==========================================
// Netlink XFRM event groups
// ==========================================
pub const XFRMNLGRP_NONE: u32 = 0;
pub const XFRMNLGRP_ACQUIRE: u32 = 1;
pub const XFRMNLGRP_EXPIRE: u32 = 2;
pub const XFRMNLGRP_SA: u32 = 3;
pub const XFRMNLGRP_POLICY: u32 = 4;
pub const XFRMNLGRP_AEVENTS: u32 = 5;
pub const XFRMNLGRP_REPORT: u32 = 6;
pub const XFRMNLGRP_MIGRATE: u32 = 7;
pub const XFRMNLGRP_MAPPING: u32 = 8;

// ==========================================
// XFRM infinity value for lifetime
// ==========================================
pub const XFRM_INF: u64 = !0;

// ==========================================
// Replay window max bitmap length
// ==========================================
pub const XFRMA_REPLAY_ESN_MAX: usize = 4096;

// ==========================================
// XFRM State ESP encapsulation types
// ==========================================
pub const UDP_ENCAP_ESPINUDP_NON_IKE: u16 = 1;
pub const UDP_ENCAP_ESPINUDP: u16 = 2;
pub const TCP_ENCAP_ESPINTCP: u16 = 7;

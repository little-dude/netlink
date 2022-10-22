// SPDX-License-Identifier: MIT

pub mod address_filter;
pub use address_filter::*;

pub mod alg;
pub use alg::*;

pub mod alg_aead;
pub use alg_aead::*;

pub mod alg_auth;
pub use alg_auth::*;

pub mod encap_tmpl;
pub use encap_tmpl::*;

pub mod mark;
pub use mark::*;

pub mod replay;
pub use replay::*;

pub mod replay_esn;
pub use replay_esn::*;

pub mod security_ctx;
pub use security_ctx::*;

pub mod user_kmaddress;
pub use user_kmaddress::*;

pub mod user_migrate;
pub use user_migrate::*;

pub mod user_offload;
pub use user_offload::*;

pub mod user_template;
pub use user_template::*;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use std::mem::size_of;

use crate::{
    constants::*,
    Address,
    AddressBuffer,
    Lifetime,
    LifetimeBuffer,
    UserPolicyInfo,
    UserPolicyInfoBuffer,
    UserPolicyType,
    UserPolicyTypeBuffer,
    UserSaInfo,
    UserSaInfoBuffer,
};

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::*,
    traits::*,
    DecodeError,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum XfrmAttrs {
    AddressFilter(address_filter::AddressFilter),
    AuthenticationAlg(Alg),
    AuthenticationAlgTrunc(AlgAuth),
    CareOfAddr(Address),
    CompressionAlg(Alg),
    EncapsulationTemplate(EncapTmpl),
    EncryptionAlg(Alg),
    EncryptionAlgAead(AlgAead),
    EventTimeThreshold(u32), // replay event timer threshold (rate limit in ms)
    ExtraFlags(u32),
    IfId(u32),
    KmAddress(UserKmAddress),
    LastUsed(u64),
    LifetimeBytes(Lifetime), // byte lifetime value
    MappingTimeThreshold(u32),
    Mark(mark::Mark),
    MarkMask(u32),
    MarkVal(u32),
    Migrate(UserMigrate),
    OffloadDevice(UserOffloadDev),
    Pad(),
    PolicyInfo(UserPolicyInfo),
    PolicyType(UserPolicyType),
    Proto(u8),
    ReplayState(Replay), // replay window sequence number state
    ReplayStateEsn(ReplayEsn), // replay window extended sequence number state
    ReplayThreshold(u32), // kernel replay event threshold
    SaInfo(UserSaInfo),
    SecurityContext(SecurityCtx),
    SrcAddr(Address),
    Template(Vec<UserTemplate>),
    TfcPadding(u32),
    Unspec(Vec<u8>),

    Other(DefaultNla),
}

impl Nla for XfrmAttrs {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::XfrmAttrs::*;
        match *self {
            AddressFilter(ref v) => v.buffer_len(),
            AuthenticationAlg(ref v) => v.buffer_len(),
            AuthenticationAlgTrunc(ref v) => v.buffer_len(),
            CareOfAddr(ref v) => v.buffer_len(),
            CompressionAlg(ref v) => v.buffer_len(),
            EncapsulationTemplate(ref v) => v.buffer_len(),
            EncryptionAlg(ref v) => v.buffer_len(),
            EncryptionAlgAead(ref v) => v.buffer_len(),
            EventTimeThreshold(_) => size_of::<u32>(),
            ExtraFlags(_) => size_of::<u32>(),
            IfId(_) => size_of::<u32>(),
            KmAddress(ref v) => v.buffer_len(),
            LastUsed(_) => size_of::<u64>(),
            LifetimeBytes(ref v) => v.buffer_len(),
            MappingTimeThreshold(_) => size_of::<u32>(),
            Mark(ref v) => v.buffer_len(),
            MarkMask(_) => size_of::<u32>(),
            MarkVal(_) => size_of::<u32>(),
            Migrate(ref v) => v.buffer_len(),
            OffloadDevice(ref v) => v.buffer_len(),
            Pad() => 0,
            PolicyInfo(ref v) => v.buffer_len(),
            PolicyType(ref v) => v.buffer_len(),
            Proto(_) => size_of::<u8>(),
            ReplayState(ref v) => v.buffer_len(),
            ReplayStateEsn(ref v) => v.buffer_len(),
            ReplayThreshold(_) => size_of::<u32>(),
            SaInfo(ref v) => v.buffer_len(),
            SecurityContext(ref v) => v.buffer_len(),
            SrcAddr(ref v) => v.buffer_len(),
            Template(ref v) => v.len() * XFRM_USER_TEMPLATE_LEN,
            TfcPadding(_) => size_of::<u32>(),
            Unspec(ref bytes) => bytes.len(),

            Other(ref attr)  => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::XfrmAttrs::*;
        match *self {
            AddressFilter(ref v) => v.emit(buffer),
            AuthenticationAlg(ref v) => v.emit(buffer),
            AuthenticationAlgTrunc(ref v) => v.emit(buffer),
            CareOfAddr(ref v) => v.emit(buffer),
            CompressionAlg(ref v) => v.emit(buffer),
            EncapsulationTemplate(ref v) => v.emit(buffer),
            EncryptionAlg(ref v) => v.emit(buffer),
            EncryptionAlgAead(ref v) => v.emit(buffer),
            EventTimeThreshold(ref v) => NativeEndian::write_u32(buffer, *v),
            ExtraFlags(ref v) => NativeEndian::write_u32(buffer, *v),
            IfId(ref v) => NativeEndian::write_u32(buffer, *v),
            KmAddress(ref v) => v.emit(buffer),
            LastUsed(ref v) => NativeEndian::write_u64(buffer, *v),
            LifetimeBytes(ref v) => v.emit(buffer),
            MappingTimeThreshold(ref v) => NativeEndian::write_u32(buffer, *v),
            Mark(ref v) => v.emit(buffer),
            MarkMask(ref v) => NativeEndian::write_u32(buffer, *v),
            MarkVal(ref v) => NativeEndian::write_u32(buffer, *v),
            Migrate(ref v) => v.emit(buffer),
            OffloadDevice(ref v) => v.emit(buffer),
            Pad() => /*ignore*/return,
            PolicyInfo(ref v) => v.emit(buffer),
            PolicyType(ref v) => v.emit(buffer),
            Proto(ref v) => buffer[0] = *v,
            ReplayState(ref v) => v.emit(buffer),
            ReplayStateEsn(ref v) => v.emit(buffer),
            ReplayThreshold(ref v) => NativeEndian::write_u32(buffer, *v),
            SaInfo(ref v) => v.emit(buffer),
            SecurityContext(ref v) => v.emit(buffer),
            SrcAddr(ref v) => v.emit(buffer),
            Template(ref v) => {
                let mut it_tmpl = v.iter();
                let mut it_buf = buffer.chunks_exact_mut(XFRM_USER_TEMPLATE_LEN);

                loop {
                    if let Some(tmpl) = it_tmpl.next() {
                        if let Some(buf) = it_buf.next() {
                            tmpl.emit(buf);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
            },
            TfcPadding(ref v) => NativeEndian::write_u32(buffer, *v),
            Unspec(ref bytes) => buffer.copy_from_slice(bytes.as_slice()),

            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::XfrmAttrs::*;
        match *self {
            AddressFilter(_) => XFRMA_ADDRESS_FILTER,
            AuthenticationAlg(_) => XFRMA_ALG_AUTH,
            AuthenticationAlgTrunc(_) => XFRMA_ALG_AUTH_TRUNC,
            CareOfAddr(_) => XFRMA_COADDR,
            CompressionAlg(_) => XFRMA_ALG_COMP,
            EncapsulationTemplate(_) => XFRMA_ENCAP,
            EncryptionAlg(_) => XFRMA_ALG_CRYPT,
            EncryptionAlgAead(_) => XFRMA_ALG_AEAD,
            EventTimeThreshold(_) => XFRMA_ETIMER_THRESH,
            ExtraFlags(_) => XFRMA_SA_EXTRA_FLAGS,
            IfId(_) => XFRMA_IF_ID,
            KmAddress(_) => XFRMA_KMADDRESS,
            LastUsed(_) => XFRMA_LASTUSED,
            LifetimeBytes(_) => XFRMA_LTIME_VAL,
            MappingTimeThreshold(_) => XFRMA_MTIMER_THRESH,
            Mark(_) => XFRMA_MARK,
            MarkMask(_) => XFRMA_SET_MARK_MASK,
            MarkVal(_) => XFRMA_SET_MARK,
            Migrate(_) => XFRMA_MIGRATE,
            OffloadDevice(_) => XFRMA_OFFLOAD_DEV,
            Pad() => XFRMA_PAD,
            PolicyInfo(_) => XFRMA_POLICY,
            PolicyType(_) => XFRMA_POLICY_TYPE,
            Proto(_) => XFRMA_PROTO,
            ReplayState(_) => XFRMA_REPLAY_VAL,
            ReplayStateEsn(_) => XFRMA_REPLAY_ESN_VAL,
            ReplayThreshold(_) => XFRMA_REPLAY_THRESH,
            SaInfo(_) => XFRMA_SA,
            SecurityContext(_) => XFRMA_SEC_CTX,
            SrcAddr(_) => XFRMA_SRCADDR,
            Template(_) => XFRMA_TMPL,
            TfcPadding(_) => XFRMA_TFCPAD,
            Unspec(_) => XFRMA_UNSPEC,

            Other(ref nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for XfrmAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::XfrmAttrs::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            XFRMA_ADDRESS_FILTER => AddressFilter(address_filter::AddressFilter::parse(&AddressFilterBuffer::new(payload)).context("invalid XFRMA_ADDRESS_FILTER")?),
            XFRMA_ALG_AUTH => AuthenticationAlg(Alg::parse(&AlgBuffer::new(payload)).context("invalid XFRMA_ALG_AUTH")?),
            XFRMA_ALG_AUTH_TRUNC => AuthenticationAlgTrunc(AlgAuth::parse(&AlgAuthBuffer::new(payload)).context("invalid XFRMA_ALG_AUTH_TRUNC")?),
            XFRMA_COADDR => CareOfAddr(Address::parse(&AddressBuffer::new(payload)).context("invalid XFRMA_COADDR")?),
            XFRMA_ALG_COMP => CompressionAlg(Alg::parse(&AlgBuffer::new(payload)).context("invalid XFRMA_ALG_COMP")?),
            XFRMA_ENCAP => EncapsulationTemplate(EncapTmpl::parse(&EncapTmplBuffer::new(payload)).context("invalid XFRMA_ENCAP")?),
            XFRMA_ALG_CRYPT => EncryptionAlg(Alg::parse(&AlgBuffer::new(payload)).context("invalid XFRMA_ALG_CRYPT")?),
            XFRMA_ALG_AEAD => EncryptionAlgAead(AlgAead::parse(&AlgAeadBuffer::new(payload)).context("invalid XFRMA_ALG_AEAD")?),
            XFRMA_ETIMER_THRESH => EventTimeThreshold(parse_u32(payload).context("invalid XFRMA_ETIMER_THRESH")?),
            XFRMA_SA_EXTRA_FLAGS => ExtraFlags(parse_u32(payload).context("invalid XFRMA_SA_EXTRA_FLAGS")?),
            XFRMA_IF_ID => IfId(parse_u32(payload).context("invalid XFRMA_IF_ID")?),
            XFRMA_KMADDRESS => KmAddress(UserKmAddress::parse(&UserKmAddressBuffer::new(payload)).context("invalid XFRMA_KMADDRESS")?),
            XFRMA_LASTUSED => LastUsed(parse_u64(payload).context("invalid XFRMA_LASTUSED")?),
            XFRMA_LTIME_VAL => LifetimeBytes(Lifetime::parse(&LifetimeBuffer::new(payload)).context("invalid XFRMA_LTIME_VAL")?),
            XFRMA_MTIMER_THRESH => MappingTimeThreshold(parse_u32(payload).context("invalid XFRMA_MTIMER_THRESH")?),
            XFRMA_MARK => Mark(mark::Mark::parse(&MarkBuffer::new(payload)).context("invalid XFRMA_MARK")?),
            XFRMA_SET_MARK_MASK => MarkMask(parse_u32(payload).context("invalid XFRMA_SET_MARK_MASK")?),
            XFRMA_SET_MARK => MarkVal(parse_u32(payload).context("invalid XFRMA_SET_MARK")?),
            XFRMA_MIGRATE => Migrate(UserMigrate::parse(&UserMigrateBuffer::new(payload)).context("invalid XFRMA_MIGRATE")?),
            XFRMA_OFFLOAD_DEV => OffloadDevice(UserOffloadDev::parse(&UserOffloadDevBuffer::new(payload)).context("invalid XFRMA_OFFLOAD_DEV")?),
            XFRMA_PAD => Pad(),
            XFRMA_POLICY => PolicyInfo(UserPolicyInfo::parse(&UserPolicyInfoBuffer::new(payload)).context("invalid XFRMA_POLICY")?),
            XFRMA_POLICY_TYPE => PolicyType(UserPolicyType::parse(&UserPolicyTypeBuffer::new(payload)).context("invalid XFRMA_POLICY_TYPE")?),
            XFRMA_PROTO => Proto(parse_u8(payload).context("invalid XFRMA_PROTO")?),
            XFRMA_REPLAY_VAL => ReplayState(Replay::parse(&ReplayBuffer::new(payload)).context("invalid XFRMA_REPLAY_VAL")?),
            XFRMA_REPLAY_ESN_VAL => ReplayStateEsn(ReplayEsn::parse(&ReplayEsnBuffer::new(payload)).context("invalid XFRMA_REPLAY_ESN_VAL")?),
            XFRMA_REPLAY_THRESH => ReplayThreshold(parse_u32(payload).context("invalid XFRMA_REPLAY_THRESH")?),
            XFRMA_SA => SaInfo(UserSaInfo::parse(&UserSaInfoBuffer::new(payload)).context("invalid XFRMA_SA")?),
            XFRMA_SEC_CTX => SecurityContext(SecurityCtx::parse(&SecurityCtxBuffer::new(payload)).context("invalid XFRMA_SEC_CTX")?),
            XFRMA_SRCADDR => SrcAddr(Address::parse(&AddressBuffer::new(payload)).context("invalid XFRMA_COADDR")?),
            XFRMA_TMPL => {
                let mut tmpls: Vec<UserTemplate> = vec![];
                let mut it = payload.chunks_exact(XFRM_USER_TEMPLATE_LEN);

                while let Some(t) = it.next() {
                    let tmpl = UserTemplate::parse(&UserTemplateBuffer::new(&t)).context("invalid XFRMA_TMPL")?;
                    tmpls.push(tmpl);
                }
                Template(tmpls)
            },
            XFRMA_TFCPAD => TfcPadding(parse_u32(payload).context("invalid XFRMA_TFCPAD")?),
            XFRMA_UNSPEC => Unspec(payload.to_vec()),

            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}

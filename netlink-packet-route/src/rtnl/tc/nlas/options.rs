use std::mem::size_of;

// SPDX-License-Identifier: MIT
use crate::{
    nlas::{self, tc::htb::HtbGlobBuffer, DefaultNla, NlaBuffer},
    tc::{bpf, ingress, u32},
    traits::{Parseable, ParseableParametrized},
    utils::Emitable,
    DecodeError,
    TCA_HTB_CEIL64,
    TCA_HTB_CTAB,
    TCA_HTB_INIT,
    TCA_HTB_PARMS,
    TCA_HTB_RATE64,
    TCA_HTB_RTAB,
};
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use libc::{c_void, memcmp};

use super::{
    htb::{self, HtbGlob, HTB_GLOB_LEN},
    tc_htb::{TcHtbOpt, TcHtbOptBuffer, TcRateSpec, TcRateSpecBuffer},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TcOpt {
    // Qdisc specific options
    Ingress,
    // Filter specific options
    U32(u32::Nla),
    Bpf(bpf::Nla),
    TcRate(u64),
    TcCeil(u64),
    HtbOpt(HtbGlob),
    TcHtbOpt(TcHtbOpt),
    TcHtbRtab([u32; 256]),
    TcHtbCtab([u32; 256]),
    // Other options
    Other(DefaultNla),
}

impl nlas::Nla for TcOpt {
    fn value_len(&self) -> usize {
        match self {
            Self::Ingress => 0,
            Self::U32(u) => u.value_len(),
            Self::Bpf(u) => u.value_len(),
            Self::Other(o) => o.value_len(),
            Self::HtbOpt(_) => HTB_GLOB_LEN,
            Self::TcHtbOpt(ref opt) => opt.rate.buffer_len() + opt.ceil.buffer_len() + 4 * 5,
            Self::TcHtbRtab(_) => 1024,
            Self::TcHtbCtab(_) => 1024,
            Self::TcRate(_) | Self::TcCeil(_) => 8,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        fn emit_u32_slice(slice: &[u32], buffer: &mut [u8]) {
            unsafe {
                memcmp(
                    slice.as_ptr() as *const c_void,
                    buffer.as_mut_ptr() as *mut c_void,
                    slice.len() * size_of::<u32>(),
                );
            }
        }
        match self {
            Self::Ingress => unreachable!(),
            Self::U32(u) => u.emit_value(buffer),
            Self::Bpf(u) => u.emit_value(buffer),
            Self::Other(o) => o.emit_value(buffer),
            Self::TcHtbOpt(o) => o.emit(buffer),
            Self::TcHtbRtab(o) => emit_u32_slice(o, buffer),
            Self::TcHtbCtab(o) => emit_u32_slice(o, buffer),
            Self::TcRate(n) | Self::TcCeil(n) => NativeEndian::write_u64(buffer, *n),
            Self::HtbOpt(ref opt) => {
                let mut buf = HtbGlobBuffer::new(buffer);
                buf.set_version(opt.version);
                buf.set_rate2quatum(opt.rate2quatum);
                buf.set_defcls(opt.defcls);
                buf.set_debug(opt.debug);
                buf.set_direct_pkts(opt.direct_pkts);
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Ingress => unreachable!(),
            Self::U32(u) => u.kind(),
            Self::Bpf(u) => u.kind(),
            Self::TcHtbOpt(_) => TCA_HTB_PARMS,
            Self::TcHtbRtab(_) => TCA_HTB_RTAB,
            Self::TcHtbCtab(_) => TCA_HTB_CTAB,
            Self::TcRate(_) => TCA_HTB_RATE64,
            Self::TcCeil(_) => TCA_HTB_CEIL64,
            Self::HtbOpt(_) => TCA_HTB_INIT,
            Self::Other(o) => o.kind(),
        }
    }
}

impl<'a, T, S> ParseableParametrized<NlaBuffer<&'a T>, S> for TcOpt
where
    T: AsRef<[u8]> + ?Sized,
    S: AsRef<str>,
{
    fn parse_with_param(buf: &NlaBuffer<&'a T>, kind: S) -> Result<Self, DecodeError> {
        Ok(match kind.as_ref() {
            ingress::KIND => TcOpt::Ingress,
            u32::KIND => Self::U32(u32::Nla::parse(buf).context("failed to parse u32 nlas")?),
            htb::KIND => match buf.kind() {
                TCA_HTB_INIT => {
                    let buf = HtbGlobBuffer::new(buf.value());
                    Self::HtbOpt(HtbGlob {
                        version: buf.version(),
                        rate2quatum: buf.rate2quatum(),
                        defcls: buf.defcls(),
                        debug: buf.debug(),
                        direct_pkts: buf.direct_pkts(),
                    })
                }
                TCA_HTB_PARMS => {
                    let buf = TcHtbOptBuffer::new(buf.value());
                    let rate = TcRateSpecBuffer::new(buf.rate());
                    let ceil = TcRateSpecBuffer::new(buf.ceil());
                    Self::TcHtbOpt(TcHtbOpt {
                        rate: TcRateSpec {
                            cell_log: rate.cell_log(),
                            linklayer: rate.linklayer(),
                            overhead: rate.overhead(),
                            cell_align: rate.cell_align(),
                            mpu: rate.mpu(),
                            rate: rate.rate(),
                        },
                        ceil: TcRateSpec {
                            cell_log: ceil.cell_log(),
                            linklayer: ceil.linklayer(),
                            overhead: ceil.overhead(),
                            cell_align: ceil.cell_align(),
                            mpu: ceil.mpu(),
                            rate: ceil.rate(),
                        },
                        buffer: buf.buffer(),
                        cbuffer: buf.cbuffer(),
                        quantum: buf.quantum(),
                        level: buf.level(),
                        prio: buf.prio(),
                    })
                }
                TCA_HTB_RATE64 => Self::TcRate(NativeEndian::read_u64(buf.value())),
                TCA_HTB_CEIL64 => Self::TcCeil(NativeEndian::read_u64(buf.value())),
                _ => Self::Other(DefaultNla::parse(buf)?),
            },
            _ => Self::Other(DefaultNla::parse(buf)?),
        })
    }
}

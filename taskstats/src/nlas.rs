// SPDX-License-Identifier: MIT

//use crate::constants::*;
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian as ne};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer, NlasIterator},
    parsers::*,
    traits::*,
    DecodeError,
};
use std::mem::size_of_val;
use serde::{Serialize, Deserialize};


pub const TASKSTATS_CMD_ATTR_PID: u16 = 1;
pub const TASKSTATS_CMD_ATTR_TGID: u16 = 2;
pub const TASKSTATS_CMD_ATTR_REGISTER_CPUMASK: u16 = 3;
pub const TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK: u16 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStatsCmdAttrs {
    Pid(u32),
    TGid(u32),
    RegisterCPUMask(String),
    DeRegisterCPUMask(String),
}

impl Nla for TaskStatsCmdAttrs {
    fn value_len(&self) -> usize {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(v) => size_of_val(v),
            TGid(v) => size_of_val(v),
            RegisterCPUMask(s) => s.len() + 1,
            DeRegisterCPUMask(s) => s.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(_) => TASKSTATS_CMD_ATTR_PID,
            TGid(_) => TASKSTATS_CMD_ATTR_TGID,
            RegisterCPUMask(_) => TASKSTATS_CMD_ATTR_REGISTER_CPUMASK,
            DeRegisterCPUMask(_) => TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use TaskStatsCmdAttrs::*;
        match self {
            Pid(v) => ne::write_u32(buffer, *v),
            TGid(v) => ne::write_u32(buffer, *v),
            RegisterCPUMask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            DeRegisterCPUMask(s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskStatsCmdAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_CMD_ATTR_REGISTER_CPUMASK => Self::RegisterCPUMask(
                parse_string(payload).context("invalid TASKSTATS_CMD_ATTR_REGISTER_CPUMASK value")?,
            ),
            TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK => Self::DeRegisterCPUMask(
                parse_string(payload).context("invalid TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK value")?,
            ),
            TASKSTATS_CMD_ATTR_PID => {
                Self::Pid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_PID value")?)
            }
            TASKSTATS_CMD_ATTR_TGID => {
                Self::TGid(parse_u32(payload).context("invalid TASKSTATS_CMD_ATTR_TGID value")?)
            }
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {}", kind))),
        })
    }
}

/*-------------------- Taskstats Events --------------------*/


/// Event code definition 
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatsEventAttrs {
    /// process id
	Pid(i32),
    /// Thread group id
	TGid(i32),
    /// taskstats structure
    Stats(struct_tasksstats),
    /// contains pid + stats
    AggrPid(Statistics),
    /// contains tgid + stats
    AggrTGid(Statistics),
    /// contains nothing
    Null
}

const TASKSTATS_TYPE_PID:u16 = 1;		/* Process id */
const TASKSTATS_TYPE_TGID:u16 = 2;		/* Thread group id */
const TASKSTATS_TYPE_STATS:u16 = 3;		/* taskstats structure */
const TASKSTATS_TYPE_AGGR_PID:u16 = 4;	/* contains pid + stats */
const TASKSTATS_TYPE_AGGR_TGID:u16 = 5;	/* contains tgid + stats */
const TASKSTATS_TYPE_NULL:u16 = 6;		/* contains nothing */


#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Taststats + additional information
pub struct Statistics
{
    pub tgid:           i32,
    pub pid:            i32,
    pub timestamp_ns:   u64,
    pub data:           struct_tasksstats
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
///the actual struct containing statistics
/* 
    created by bindgen
    use c reperesentation rather than NativeEndian (which is usually used in this crate) 
    for correct field alignments 
*/

pub struct struct_tasksstats
{
    pub version: u16,
    pub ac_exitcode: u32,
    pub ac_flag: u8,
    pub ac_nice: u8,
    pub cpu_count: u64,
    pub cpu_delay_total: u64,
    pub blkio_count: u64,
    pub blkio_delay_total: u64,
    pub swapin_count: u64,
    pub swapin_delay_total: u64,
    pub cpu_run_real_total: u64,
    pub cpu_run_virtual_total: u64,
    pub ac_comm: [u8; 32usize],
    pub ac_sched: u8,
    pub ac_pad: [u8; 3usize],
    pub __bindgen_padding_0: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: u64,
    pub ac_utime: u64,
    pub ac_stime: u64,
    pub ac_minflt: u64,
    pub ac_majflt: u64,
    pub coremem: u64,
    pub virtmem: u64,
    pub hiwater_rss: u64,
    pub hiwater_vm: u64,
    pub read_char: u64,
    pub write_char: u64,
    pub read_syscalls: u64,
    pub write_syscalls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub ac_utimescaled: u64,
    pub ac_stimescaled: u64,
    pub cpu_scaled_run_real_total: u64,
    pub freepages_count: u64,
    pub freepages_delay_total: u64,
    pub thrashing_count: u64,
    pub thrashing_delay_total: u64,
}



/**************************************************/
/* 	Parseable for TaskStatsEventAttrs              */
/**************************************************/
impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TaskStatsEventAttrs {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            TASKSTATS_TYPE_STATS => Self::Stats(
                struct_tasksstats::parse(&payload).context("invalid TASKSTATS_TYPE_STATS value")?,
            ),
            TASKSTATS_TYPE_PID => {
                Self::Pid(parse_i32(payload).context("invalid TASKSTATS_TYPE_PID value")?)
            },
            TASKSTATS_TYPE_TGID => {
                Self::TGid(parse_i32(payload).context("invalid TASKSTATS_TYPE_TGID value")?)
            },
            TASKSTATS_TYPE_AGGR_PID => {
                return parse_sub_nlas(payload).and_then(|x| Ok(Self::AggrPid(x)))
            },
            TASKSTATS_TYPE_AGGR_TGID => {
                return parse_sub_nlas(payload).and_then(|x| Ok(Self::AggrTGid(x)))
            },
            TASKSTATS_TYPE_NULL => Self::Null,
            kind => return Err(DecodeError::from(format!("Unknown NLA type: {}", kind))),
        })
    }
}


/****************************/
/* 	parse_sub_nlas      	*/
/****************************/
fn parse_sub_nlas(payload: &[u8]) -> Result< Statistics, DecodeError>
{
    let sub_nlas = parse_taskstats_event_nlas(payload)?;
    let mut pid = -1;
    let mut tgid = -1;

    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    let timestamp_ns = if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) } == 0
    {
        (time.tv_sec * 1000000000 + time.tv_nsec) as u64
    }
    else
        {0};


    for sub_nla in sub_nlas.iter()
    {
        match sub_nla
        {
            TaskStatsEventAttrs::Pid(x) => pid = *x,
            TaskStatsEventAttrs::TGid(x) => tgid = *x,
            TaskStatsEventAttrs::Stats(x) => return Ok(Statistics {
                pid, tgid,
                timestamp_ns,
                data: *x
            }),
            _ => ()
        }
    }
    Err(DecodeError::from(format!("Cannot decode sub nlas")))
}


/********************************/
/* parse_taskstats_event_nlas   */
/********************************/
pub fn parse_taskstats_event_nlas(buf: &[u8]) -> Result<Vec<TaskStatsEventAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskStatsEventAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse taskstats message attributes")?;

    Ok(nlas)
}



/************************************************/
/* ParseableParametrized for Statistics     	*/
/************************************************/
impl Parseable<[u8]> for struct_tasksstats {
    fn parse(buf: &[u8]) -> Result<Self, DecodeError>
    {
        // let mut str = struct_tasksstats::default();
        
        if buf.len() >= std::mem::size_of::<struct_tasksstats>()
        {
            let p = buf.as_ptr() as *const struct_tasksstats;
            unsafe{return Ok(*p)}

        }

        Err(DecodeError::from(format!("Buffer too short for struct_tasksstats")))

    }
}


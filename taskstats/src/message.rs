// SPDX-License-Identifier: MIT

//! Generic netlink controller implementation
//!
//! This module provides the definition of the taskstats packet.

//pub mod nlas;
use crate::nlas::*;
use anyhow::Context;
use netlink_packet_generic::{GenlFamily, GenlHeader};
use netlink_packet_utils::{nla::NlasIterator, traits::*, DecodeError};
use std::convert::{TryFrom, TryInto};
use serde::{Serialize, Deserialize};

/// Netlink attributes for this family

/// Command code definition 
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskStatsCmdCodes {
    /// user->kernel request/get-response
	Get,
    /// kernel->user event
	New,
}

pub const TASKSTATS_CMD_GET: u8 = 1;
pub const TASKSTATS_CMD_NEW: u8 = 2;

impl From<TaskStatsCmdCodes> for u8 {
    fn from(cmd: TaskStatsCmdCodes) -> u8 {
        use TaskStatsCmdCodes::*;
        match cmd {
            Get => TASKSTATS_CMD_GET,
            New => TASKSTATS_CMD_NEW,
        }
    }
}

impl TryFrom<u8> for TaskStatsCmdCodes {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use TaskStatsCmdCodes::*;
        Ok(match value {
            TASKSTATS_CMD_GET => Get,
            TASKSTATS_CMD_NEW => New,
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unknown taskstat command: {}",
                    cmd
                )))
            }
        })
    }
}


/// Payload of taskstats
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskStatsCmd {
    /// Command code of this message
    pub cmd: TaskStatsCmdCodes,
    /// Netlink attributes in this message
    pub nlas: Vec<TaskStatsCmdAttrs>,
    /// family id is not fixed
    pub family_id: u16
}

impl GenlFamily for TaskStatsCmd {
    fn family_name() -> &'static str {
        "taskstats"
    }

    fn family_id(&self) -> u16 {
        self.family_id
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        1
    }
}

impl Emitable for TaskStatsCmd {
    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TaskStatsCmd {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(TaskStatsCmd {
            cmd: header.cmd.try_into()?,
            nlas: parse_taskstats_cmd_nlas(buf)?,
            // the family is kind of dynamic, it
            // must be set after parsing
            family_id: 0
        })
    }
}

fn parse_taskstats_cmd_nlas(buf: &[u8]) -> Result<Vec<TaskStatsCmdAttrs>, DecodeError> {
    let nlas = NlasIterator::new(buf)
        .map(|nla| nla.and_then(|nla| TaskStatsCmdAttrs::parse(&nla)))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse control message attributes")?;

    Ok(nlas)
}

/*-------------------- Taskstats Events --------------------*/

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskStatsEvent{
    /// Command code of this message
    pub cmd: TaskStatsCmdCodes,
    /// timestamp
    pub timestamp_ns:   u64,
    /// Netlink attributes in this message
    pub nlas: Vec<TaskStatsEventAttrs>,
    // family id is not fixed
    // pub family_id: u16
}

impl ParseableParametrized<[u8], GenlHeader> for TaskStatsEvent {
    fn parse_with_param(buf: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        Ok(TaskStatsEvent {
            cmd: header.cmd.try_into().and_then(|c|{ 
                //Ok(TaskStatsCmdCodes::New)
                match c{
                    TaskStatsCmdCodes::New => Ok(c),
                    x  => Err(DecodeError::from(format!(
                        "Taskstat command must be 'new' not {:?}", x)))
                }
            })?,
            timestamp_ns :
            {
                let mut time = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
            
                if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut time) } == 0
                {
                    (time.tv_sec * 1000000000 + time.tv_nsec) as u64
                }
                else
                    {0}        
            },
            nlas: parse_taskstats_event_nlas(buf)?,
            // the family is kind of dynamic, it
            // must be set after parsing
            //family_id: 0
        })
    }
}

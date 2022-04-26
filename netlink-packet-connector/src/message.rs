// SPDX-License-Identifier: MIT

use std::mem::size_of;
use byteorder::{ByteOrder, NativeEndian as ne};

use crate::{
    //inet,
    traits::{Emitable, ParseableParametrized},
    //unix,
    DecodeError,
    NetlinkDeserializable,
    NetlinkHeader,
    NetlinkPayload,
    NetlinkSerializable
    //SockDiagBuffer,
    //SOCK_DIAG_BY_FAMILY,
    
};

use anyhow::Context;

const NLMSG_DONE: u16 = 3;

pub const PROC_CN_MCAST_LISTEN: u32 = 1;
pub const PROC_CN_MCAST_IGNORE: u32 = 2;

/* structs and constants taken from /usr/include/linux/connector.h */

/*
 * Process Events connector unique ids -- used for message routing
 */
pub const CN_IDX_PROC: u32 =		0x1;
pub const CN_VAL_PROC: u32 =		0x1;
pub const CN_IDX_CIFS: u32 =		0x2;
pub const CN_VAL_CIFS: u32 =        0x1;
pub const CN_W1_IDX	: u32 =	        0x3;	/* w1 communication */
pub const CN_W1_VAL	: u32 =	        0x1;
pub const CN_IDX_V86D: u32 =		0x4;
pub const CN_VAL_V86D_UVESAFB: u32 = 0x1;
pub const CN_IDX_BB	: u32 =		    0x5;	/* BlackBoard, from the TSP GPL sampling framework */
pub const CN_DST_IDX: u32 =			0x6;
pub const CN_DST_VAL: u32 =			0x1;
pub const CN_IDX_DM	: u32 =		    0x7;	/* Device Mapper */
pub const CN_VAL_DM_USERSPACE_LOG: u32 = 0x1;
pub const CN_IDX_DRBD: u32 =		0x8;
pub const CN_VAL_DRBD: u32 =		0x1;
pub const CN_KVP_IDX: u32 =			0x9;	/* HyperV KVP */
pub const CN_KVP_VAL: u32 =			0x1;	/* queries from the kernel */
pub const CN_VSS_IDX: u32 =			0xA;     /* HyperV VSS */
pub const CN_VSS_VAL: u32 =			0x1;     /* queries from the kernel */


pub const CN_NETLINK_USERS: u32 =	11;	/* Highest index + 1 */

/*
 * Maximum connector's message size.
 */
pub const CONNECTOR_MAX_MSG_SIZE:u32 =	16384;

#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
struct cb_id
{
    idx:    u32,
    val:    u32
}


#[derive(Debug, PartialEq, Eq, Clone)]
#[allow(non_camel_case_types)]
pub struct cn_msg
{
    id:         cb_id,
    seq:        u32,
    ack:        u32,
    len:        u16,
    flags:      u16
}


impl Default for cn_msg
{
    /****************************/
    /* default			        */
    /****************************/
    fn default() -> Self
    {
        cn_msg
        {
            id: cb_id{idx:0, val: 0},
            seq: 0,
            ack: 0,
            len: 0,
            flags: 0
        }
    }
}

/****************************/
/* 	ConnectorRequest     	*/
/****************************/
pub struct ConnectorRequest
{
    pub msg:     cn_msg,
    pub data:    Vec::<u8>
}


impl ConnectorRequest
{
    /****************************/
    /* new	            		*/
    /****************************/
    pub fn new(idx: u32, val: u32, data: &[u8]) -> Self
    {
        ConnectorRequest
        {
            msg: cn_msg
            {
                id: cb_id{idx, val},
                len: data.len() as u16,
                ..cn_msg::default()
            },
            data: Vec::<u8>::from(data)
        }
    }
}


/********************************/
/* Emitable for ConnectorRequest	*/
/********************************/
impl Emitable for ConnectorRequest 
{
    fn buffer_len(&self) -> usize 
    {
        size_of::<cn_msg>() + self.data.len()
    }

    fn emit(&self, buffer: &mut [u8]) 
    {
        ne::write_u32(&mut buffer[0..4], self.msg.id.idx);
        ne::write_u32(&mut buffer[4..8], self.msg.id.val);
        ne::write_u32(&mut buffer[8..12], self.msg.seq);
        ne::write_u32(&mut buffer[12..16], self.msg.ack);
        ne::write_u16(&mut buffer[16..18], self.msg.len);
        ne::write_u16(&mut buffer[18..20], self.msg.flags);

        buffer[20..].iter_mut().zip(&self.data[..]).map(|(x, y)| *x = *y).count();
    }
}

/********************************************/
/* NetlinkSerializable for ConnectorRequest	*/
/********************************************/
impl NetlinkSerializable for ConnectorRequest {
    fn message_type(&self) -> u16 {
        NLMSG_DONE
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl From<ConnectorRequest> for NetlinkPayload<ConnectorRequest> {
    fn from(message: ConnectorRequest) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}


/* 
    from /usr/include/linux/cn_proc.h 

   struct nl_proc_connector_msg {
   struct nlmsghdr hdr;
   struct {
      struct cn_msg msg;
      struct proc_event ev;
   }
   __attribute__((__packed__));

struct proc_event {
	enum what {
		/* Use successive bits so the enums can be used to record
		 * sets of events as well
		 */
		PROC_EVENT_NONE = 0x00000000,
		PROC_EVENT_FORK = 0x00000001,
		PROC_EVENT_EXEC = 0x00000002,
		PROC_EVENT_UID  = 0x00000004,
		PROC_EVENT_GID  = 0x00000040,
		PROC_EVENT_SID  = 0x00000080,
		PROC_EVENT_PTRACE = 0x00000100,
		PROC_EVENT_COMM = 0x00000200,
		/* "next" should be 0x00000400 */
		/* "last" is the last process event: exit,
		 * while "next to last" is coredumping event */
		PROC_EVENT_COREDUMP = 0x40000000,
		PROC_EVENT_EXIT = 0x80000000
	} what;
	__u32 cpu;
	__u64 __attribute__((aligned(8))) timestamp_ns;
		/* Number of nano seconds since system boot */
	union { /* must be last field of proc_event struct */
		struct {
			__u32 err;
		} ack;

		struct fork_proc_event {
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
			__kernel_pid_t child_pid;
			__kernel_pid_t child_tgid;
		} fork;

		struct exec_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
		} exec;

		struct id_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			union {
				__u32 ruid; /* task uid */
				__u32 rgid; /* task gid */
			} r;
			union {
				__u32 euid;
				__u32 egid;
			} e;
		} id;

		struct sid_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
		} sid;

		struct ptrace_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__kernel_pid_t tracer_pid;
			__kernel_pid_t tracer_tgid;
		} ptrace;

		struct comm_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			char           comm[16];
		} comm;

		struct coredump_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
		} coredump;

		struct exit_proc_event {
			__kernel_pid_t process_pid;
			__kernel_pid_t process_tgid;
			__u32 exit_code, exit_signal;
			__kernel_pid_t parent_pid;
			__kernel_pid_t parent_tgid;
		} exit;

	} event_data;
};

};

*/
pub const PROC_EVENT_NONE:  u32 = 0x00000000;
pub const PROC_EVENT_FORK:  u32 = 0x00000001;
pub const PROC_EVENT_EXEC:  u32 = 0x00000002;
pub const PROC_EVENT_UID:   u32  = 0x00000004;
pub const PROC_EVENT_GID:   u32  = 0x00000040;
pub const PROC_EVENT_SID:   u32  = 0x00000080;
pub const PROC_EVENT_PTRACE:u32 = 0x00000100;
pub const PROC_EVENT_COMM:  u32 = 0x00000200;
pub const PROC_EVENT_COREDUMP: u32 = 0x40000000;
pub const PROC_EVENT_EXIT:  u32 = 0x80000000;

/****************************/
/* enum ConnectorResponse   */
/****************************/
#[allow(non_camel_case_types)]
pub enum ConnectorResponse {
    none,
    fork(ForkProcEvent),
    exec(ExecProcEvent),
    uid(UIDProcEvent),
    gid(GIDProcEvent),
    sid(SIDProcEvent),
    ptrace(PtraceProcEvent),
    comm(CommProcEvent),
    coredump(CoredumpProcEvent),
    exit(ExitProcEvent),
    other((u32, String)),
}


// impl ConnectorResponse
// {
//     pub fn message_type(&self) -> u16 {
//         use self::ConnectorResponse::*;

//         match self {
//             none =>  PROC_EVENT_NONE,
//             fork(_) =>  PROC_EVENT_FORK,
//             exec(_) =>  PROC_EVENT_EXEC,
//             uid(_) =>  PROC_EVENT_UID,
//             gid(_) =>  PROC_EVENT_GID,
//             sid(_) =>  PROC_EVENT_SID,
//             ptrace(_) =>  PROC_EVENT_PTRACE,
//             comm(_) =>  PROC_EVENT_COMM,
//             coredump(_) =>  PROC_EVENT_COREDUMP,
//             exit(_) =>  PROC_EVENT_EXIT,
//             other((x, _)) => *x
//         }
//     }
// }


#[allow(non_camel_case_types)]
type __kernel_pid_t = i32;

/****************************/
/* 	ForkProcEvent       	*/
/****************************/
pub struct ForkProcEvent
{
    pub parent_pid:     __kernel_pid_t,
    pub parent_tgid:    __kernel_pid_t,
    pub child_pid:      __kernel_pid_t,
    pub child_tgid:     __kernel_pid_t
}


/****************************/
/* 	ExecProcEvent       	*/
/****************************/
pub struct ExecProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
}


/****************************/
/* 	UIDProcEvent          	*/
/****************************/
pub struct UIDProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub ruid:           u32,
    pub rgid:           u32
} 


/****************************/
/* 	GIDProcEvent          	*/
/****************************/
pub struct GIDProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub euid:           u32,
    pub egid:           u32
}


/****************************/
/* SIDProcEvent          	*/
/****************************/
pub struct SIDProcEvent
{
    pub process_tgid:   __kernel_pid_t,
    pub process_pid:    __kernel_pid_t,
}


/****************************/
/* 	PtraceProcEvent       	*/
/****************************/
pub struct PtraceProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub tracer_pid:      __kernel_pid_t,
    pub tracer_tgid:     __kernel_pid_t
}


/****************************/
/* CommProcEvent          	*/
/****************************/
pub struct CommProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub comm:           [u8; 16]
}


/****************************/
/* 	CoredumpProcEvent     	*/
/****************************/
pub struct CoredumpProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub parent_pid:     __kernel_pid_t,
    pub parent_tgid:    __kernel_pid_t,
}


/****************************/
/* 	ExitProcEvent       	*/
/****************************/
pub struct ExitProcEvent
{
    pub process_pid:    __kernel_pid_t,
    pub process_tgid:   __kernel_pid_t,
    pub exit_code:      u32,
    pub exit_signal:    u32,
    pub parent_pid:     __kernel_pid_t,
    pub parent_tgid:    __kernel_pid_t,
}

pub struct ConnectorResponseBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ConnectorResponseBuffer<T> {
    pub fn new(buffer: T) -> ConnectorResponseBuffer<T> {
        ConnectorResponseBuffer { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<ConnectorResponseBuffer<T>, DecodeError> {
        Ok(Self::new(buffer))
    }

    
    /****************************/
    /* read_i32		        	*/
    /****************************/
    fn read_i32(&self, offset: usize) -> i32
    {
        let r = self.buffer.as_ref();
        ne::read_i32(&r[offset..offset+4])
    }



    /****************************/
    /* read_u32		        	*/
    /****************************/
    fn read_u32(&self, offset: usize) -> u32
    {
        let r = self.buffer.as_ref();
        ne::read_u32(&r[offset..offset+4])
    }



    /****************************/
    /* cp_u8 		        	*/
    /****************************/
    fn cp_u8(&self, dest: &mut [u8], offset: usize) -> usize
    {
        let r = self.buffer.as_ref();
        dest[..].iter_mut().zip(&r[offset..]).map(|(x, y)| *x = *y).count()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ConnectorResponseBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> ConnectorResponseBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}


/************************************************/
/* NetlinkDeserializable for ConnectorResponse	*/
/************************************************/
impl NetlinkDeserializable for ConnectorResponse {
    type Error = DecodeError;

    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> 
    {
        match ConnectorResponseBuffer::new_checked(payload) {
            Err(e) => Err(e),
            Ok(buffer) => match ConnectorResponse::parse_with_param(&buffer, header.message_type) {
                Err(e) => Err(e),
                Ok(message) => Ok(message),
            },
        }
    }
}

/************************************************/
/* ParseableParametrized for ConnectorResponse	*/
/************************************************/
impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<ConnectorResponseBuffer<&'a T>, u16> for ConnectorResponse 
{
    fn parse_with_param(buf: &ConnectorResponseBuffer<&'a T>, _message_type: u16) -> Result<Self, DecodeError>
    {
        let what = buf.read_u32(size_of::<cn_msg>());
        let offs = size_of::<cn_msg>() + 16;

        let message = match what 
        {
            PROC_EVENT_NONE => ConnectorResponse::none,
            PROC_EVENT_FORK => 
            {
                ConnectorResponse::fork(ForkProcEvent
                {
                    parent_pid: buf.read_i32(offs),
                    parent_tgid: buf.read_i32(offs + 4),
                    child_pid: buf.read_i32(offs + 8),
                    child_tgid: buf.read_i32(offs + 12),
                })
            },
            PROC_EVENT_EXEC =>
            {
                ConnectorResponse::exec(ExecProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                })
            },
            PROC_EVENT_UID =>
            {
                ConnectorResponse::uid(UIDProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    ruid: buf.read_u32(offs + 8),
                    rgid: buf.read_u32(offs + 12),
                })
            },
            PROC_EVENT_GID =>
            {
                ConnectorResponse::gid(GIDProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    euid: buf.read_u32(offs + 8),
                    egid: buf.read_u32(offs + 12),
                })
            },
            PROC_EVENT_SID =>
            {
                ConnectorResponse::sid(SIDProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                })
            },
            PROC_EVENT_PTRACE =>
            {
                ConnectorResponse::ptrace(PtraceProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    tracer_pid: buf.read_i32(offs + 8),
                    tracer_tgid: buf.read_i32(offs + 12),
                })
            },
            PROC_EVENT_COMM =>
            {
                let mut x = CommProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    comm: [0; 16]
                };

                buf.cp_u8(&mut x.comm, offs + 8);
                ConnectorResponse::comm(x)
            },
            PROC_EVENT_COREDUMP =>
            {
                ConnectorResponse::coredump(CoredumpProcEvent{
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    parent_pid: buf.read_i32(offs + 8),
                    parent_tgid: buf.read_i32(offs + 12),
                })
            },
            PROC_EVENT_EXIT =>
            {
                ConnectorResponse::exit(ExitProcEvent {
                    process_pid: buf.read_i32(offs),
                    process_tgid: buf.read_i32(offs + 4),
                    exit_code:  buf.read_u32(offs + 8),
                    exit_signal: buf.read_u32(offs + 12),
                    parent_pid: buf.read_i32(offs + 16),
                    parent_tgid: buf.read_i32(offs + 20),
                })
            },
            i => {
                let data = String::from_utf8(buf.inner().to_vec())
                    .context("failed to parse audit event data as a valid string")?;
                
                ConnectorResponse::other((i, data))
            }
        };

        Ok(message)
    }
}

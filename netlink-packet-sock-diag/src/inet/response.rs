use anyhow::Context;
use smallvec::SmallVec;
use std::time::Duration;

use crate::{
    inet::{
        nlas::{Nla, NlaBuffer, NlasIterator},
        SocketId,
        SocketIdBuffer,
    },
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

/// The type of timer that is currently active for a TCP socket.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Timer {
    /// A retransmit timer
    Retransmit(Duration, u8),
    /// A keep-alive timer
    KeepAlive(Duration),
    /// A `TIME_WAIT` timer
    TimeWait,
    /// A zero window probe timer
    Probe(Duration),
}

pub const RESPONSE_LEN: usize = 72;

buffer!(InetResponseBuffer(RESPONSE_LEN) {
    family: (u8, 0),
    state: (u8, 1),
    timer: (u8, 2),
    retransmits: (u8, 3),
    socket_id: (slice, 4..52),
    expires: (u32, 52..56),
    recv_queue: (u32, 56..60),
    send_queue: (u32, 60..64),
    uid: (u32, 64..68),
    inode: (u32, 68..72),
    payload: (slice, RESPONSE_LEN..),
});

/// The response to a query for IPv4 or IPv6 sockets
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetResponseHeader {
    /// This should be set to either `AF_INET` or `AF_INET6` for IPv4
    /// or IPv6 sockets respectively.
    pub family: u8,

    /// The socket state.
    pub state: u8,

    /// For TCP sockets, this field describes the type of timer
    /// that is currently active for the socket.
    pub timer: Option<Timer>,

    /// The socket ID object.
    pub socket_id: SocketId,

    /// For listening sockets: the number of pending connections. For
    /// other sockets: the amount of data in the incoming queue.
    pub recv_queue: u32,

    /// For listening sockets: the backlog length. For other sockets:
    /// the amount of memory available for sending.
    pub send_queue: u32,

    /// Socket owner UID.
    pub uid: u32,

    /// Socket inode number.
    pub inode: u32,
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<InetResponseBuffer<&'a T>> for InetResponseHeader {
    fn parse(buf: &InetResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        let err = "invalid socket_id value";
        let socket_id = SocketId::parse_with_param(
            &SocketIdBuffer::new_checked(&buf.socket_id()).context(err)?,
            buf.family(),
        )
        .context(err)?;

        let timer = match buf.timer() {
            1 => {
                let expires = Duration::from_millis(buf.expires() as u64);
                let retransmits = buf.retransmits();
                Some(Timer::Retransmit(expires, retransmits))
            }
            2 => {
                let expires = Duration::from_millis(buf.expires() as u64);
                Some(Timer::KeepAlive(expires))
            }
            3 => Some(Timer::TimeWait),
            4 => {
                let expires = Duration::from_millis(buf.expires() as u64);
                Some(Timer::Probe(expires))
            }
            _ => None,
        };

        Ok(Self {
            family: buf.family(),
            state: buf.state(),
            timer,
            socket_id,
            recv_queue: buf.recv_queue(),
            send_queue: buf.send_queue(),
            uid: buf.uid(),
            inode: buf.inode(),
        })
    }
}

impl Emitable for InetResponseHeader {
    fn buffer_len(&self) -> usize {
        RESPONSE_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = InetResponseBuffer::new(buf);
        buf.set_family(self.family);
        buf.set_state(self.state);
        match self.timer {
            Some(Timer::Retransmit(expires, retransmits)) => {
                buf.set_timer(1);
                buf.set_expires((expires.as_millis() & 0xffff_ffff) as u32);
                buf.set_retransmits(retransmits);
            }
            Some(Timer::KeepAlive(expires)) => {
                buf.set_timer(2);
                buf.set_expires((expires.as_millis() & 0xffff_ffff) as u32);
                buf.set_retransmits(0);
            }
            Some(Timer::TimeWait) => {
                buf.set_timer(3);
                buf.set_expires(0);
                buf.set_retransmits(0);
            }
            Some(Timer::Probe(expires)) => {
                buf.set_timer(4);
                buf.set_expires((expires.as_millis() & 0xffff_ffff) as u32);
                buf.set_retransmits(0);
            }
            None => {
                buf.set_timer(0);
                buf.set_expires(0);
                buf.set_retransmits(0);
            }
        }
        buf.set_recv_queue(self.recv_queue);
        buf.set_send_queue(self.send_queue);
        buf.set_uid(self.uid);
        buf.set_inode(self.inode);
        self.socket_id.emit(buf.socket_id_mut())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InetResponse {
    pub header: InetResponseHeader,
    pub nlas: SmallVec<[Nla; 8]>,
}

impl<'a, T: AsRef<[u8]> + ?Sized> InetResponseBuffer<&'a T> {
    pub fn nlas(&self) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<InetResponseBuffer<&'a T>> for SmallVec<[Nla; 8]> {
    fn parse(buf: &InetResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut nlas = smallvec![];
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }
        Ok(nlas)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<InetResponseBuffer<&'a T>> for InetResponse {
    fn parse(buf: &InetResponseBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header =
            InetResponseHeader::parse(buf).context("failed to parse inet response header")?;
        let nlas =
            SmallVec::<[Nla; 8]>::parse(buf).context("failed to parse inet response NLAs")?;
        Ok(InetResponse { header, nlas })
    }
}

impl Emitable for InetResponse {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.nlas
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

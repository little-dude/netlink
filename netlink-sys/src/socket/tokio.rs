use std::io;

use futures::{Async, Poll};
use mio;
use tokio_reactor::PollEvented;

use super::sys;
use super::Protocol;

/// An I/O object representing a UDP socket.
pub struct TokioSocket(PollEvented<sys::Socket>);

impl TokioSocket {
    /// This function will create a new UDP socket and attempt to bind it to
    /// the `addr` provided.
    pub fn bind(&mut self, addr: &sys::SocketAddr) -> io::Result<()> {
        self.0.get_mut().bind(addr)
    }

    pub fn bind_auto(&mut self) -> io::Result<sys::SocketAddr> {
        self.0.get_mut().bind_auto()
    }

    pub fn new(protocol: Protocol) -> io::Result<Self> {
        let socket = sys::Socket::new(protocol)?;
        socket.set_non_blocking(true)?;
        Ok(TokioSocket(PollEvented::new(socket)))
    }

    pub fn connect(&self, addr: &sys::SocketAddr) -> io::Result<()> {
        self.0.get_ref().connect(addr)
    }

    pub fn poll_send(&mut self, buf: &[u8]) -> Poll<usize, io::Error> {
        // Check if the socket it writable. If PollEvented::poll_write_ready return NotReady, it
        // will already have arranged for the current task to be notified when the socket becomes
        // writable, so we can just return.
        //
        // FIXME: is this poll_write_ready call necessary? Can't we just call send, and see if it
        // returns Async::NotReady? I did it this way because that's how it's done in tokio-udp but
        // I don't know why it's done this way.
        try_ready!(self.0.poll_write_ready());

        match self.0.get_ref().send(buf, 0) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not writable, make sure the current task get notified when the
                // socket becomes writable again.
                self.0.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<usize, io::Error> {
        try_ready!(self.0.poll_read_ready(mio::Ready::readable()));

        match self.0.get_ref().recv(buf, 0) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not readable, make sure the current task get notified when the
                // socket becomes readable again.
                self.0.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_send_to(&mut self, buf: &[u8], target: &sys::SocketAddr) -> Poll<usize, io::Error> {
        try_ready!(self.0.poll_write_ready());

        match self.0.get_ref().send_to(buf, target, 0) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not writable, make sure the current task get notified when the
                // socket becomes writable again.
                self.0.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_recv_from(&mut self, buf: &mut [u8]) -> Poll<(usize, sys::SocketAddr), io::Error> {
        try_ready!(self.0.poll_read_ready(mio::Ready::readable()));

        match self.0.get_ref().recv_from(buf, 0) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.0.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }
}

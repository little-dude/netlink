use std::io;
use std::io::Result;

use crate::mio_crate as mio;
use futures::{Async, Poll};
use tokio_reactor::PollEvented;

use super::sys;
use super::Protocol;

/// An I/O object representing a Netlink socket.
pub struct TokioSocket(PollEvented<sys::Socket>);

impl TokioSocket {
    /// This function will create a new Netlink socket and attempt to bind it to
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

    pub fn add_membership(&mut self, group: u32) -> Result<()> {
        self.0.get_mut().add_membership(group)
    }

    pub fn drop_membership(&mut self, group: u32) -> Result<()> {
        self.0.get_mut().drop_membership(group)
    }

    pub fn poll_send(&mut self, buf: &[u8]) -> Poll<usize, io::Error> {
        // Check if the socket it writable. If PollEvented::poll_write_ready returns NotReady, it
        // will already have arranged for the current task to be notified when the socket becomes
        // writable, so we can just return.
        trace!("poll_send: checking if socket is writable");
        try_ready!(self.0.poll_write_ready());

        trace!("poll_send: socket is writable");
        match self.0.get_ref().send(buf, 0) {
            Ok(n) => {
                trace!("poll_send: wrote {} bytes", n);
                Ok(Async::Ready(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not writable, make sure the current task get notified when the
                // socket becomes writable again.
                trace!("poll_send: could not write, notifying the current task");
                self.0.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_recv(&mut self, buf: &mut [u8]) -> Poll<usize, io::Error> {
        trace!("poll_recv: checking if socket is readable");
        try_ready!(self.0.poll_read_ready(mio::Ready::readable()));

        trace!("poll_recv: socket is readable");
        match self.0.get_ref().recv(buf, 0) {
            Ok(n) => {
                trace!("poll_recv: read {} bytes", n);
                Ok(Async::Ready(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not readable, make sure the current task get notified when the
                // socket becomes readable again.
                trace!("poll_recv: could not read, notifying the current task");
                self.0.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_send_to(&mut self, buf: &[u8], target: &sys::SocketAddr) -> Poll<usize, io::Error> {
        trace!("poll_send_to: checking if socket is writable");
        try_ready!(self.0.poll_write_ready());

        trace!("poll_send_to: socket is writable");
        match self.0.get_ref().send_to(buf, target, 0) {
            Ok(n) => {
                trace!("poll_send_to: wrote {} bytes", n);
                Ok(Async::Ready(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // If the socket is not writable, make sure the current task get notified when the
                // socket becomes writable again.
                trace!("poll_send_to: could not write, notifying the current task");
                self.0.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_recv_from(&mut self, buf: &mut [u8]) -> Poll<(usize, sys::SocketAddr), io::Error> {
        trace!("poll_recv_from: checking if socket is readable");
        try_ready!(self.0.poll_read_ready(mio::Ready::readable()));

        trace!("poll_recv_from: socket is readable");
        match self.0.get_ref().recv_from(buf, 0) {
            Ok(n) => {
                trace!("poll_recv_from: read {} bytes from {}", n.0, n.1);
                Ok(Async::Ready(n))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!("poll_recv: could not read, notifying the current task");
                self.0.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }
}

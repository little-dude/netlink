use failure::Fail;
use futures::{Future, Stream};
use netlink_proto::{ConnectionHandle, SocketAddr};
use crate::packet::constants::{AUDIT_STATUS_ENABLED, AUDIT_STATUS_PID, NLM_F_ACK, NLM_F_REQUEST};
use crate::packet::{AuditMessage, NetlinkFlags, NetlinkMessage, StatusMessage};
use std::process;

lazy_static! {
    static ref KERNEL_UNICAST: SocketAddr = SocketAddr::new(0, 0);
}

use crate::{Error, ErrorKind};

#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle) -> Self {
        Handle(conn)
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage,
    ) -> impl Stream<Item = NetlinkMessage, Error = Error> {
        self.0
            .request(message, *KERNEL_UNICAST)
            .map_err(|e| e.context(ErrorKind::RequestFailed).into())
    }

    // pub fn is_enabled(&mut self) -> impl Future<Item = bool, Error = Error> {
    //     let mut req = NetlinkMessage::from(AuditMessage::GetStatus(
    //         StatusMessage::new()
    //             .set_enabled(true)
    //             .set_mask(AUDIT_STATUS_ENABLED),
    //     ));
    //     handle.request(req).and_then(move |msg| {})
    // }
    pub fn enable(&mut self) -> impl Future<Item = (), Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::SetStatus(
            StatusMessage::new()
                .set_enabled(true)
                .set_pid(process::id())
                .set_mask(AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID),
        ));
        req.header_mut()
            .set_flags(NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK));
        self.request(req).for_each(|message| {
            if message.is_error() {
                Err(ErrorKind::NetlinkError(message).into())
            } else {
                Ok(())
            }
        })
    }

    pub fn set_pid(&mut self) -> impl Future<Item = (), Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::SetStatus(
            StatusMessage::new()
                .set_enabled(true)
                .set_mask(AUDIT_STATUS_ENABLED),
        ));
        req.header_mut()
            .set_flags(NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK));
        self.request(req).for_each(|message| {
            if message.is_error() {
                Err(ErrorKind::NetlinkError(message).into())
            } else {
                Ok(())
            }
        })
    }
}

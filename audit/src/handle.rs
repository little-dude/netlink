use crate::packet::constants::{
    AUDIT_STATUS_ENABLED, AUDIT_STATUS_PID, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_NONREC, NLM_F_REQUEST,
};
use crate::packet::{
    AuditMessage, NetlinkFlags, NetlinkMessage, NetlinkPayload, RuleMessage, StatusMessage,
};
use failure::Fail;
use futures::{Future, Stream};
use netlink_proto::{ConnectionHandle, SocketAddr};
use std::process;

lazy_static! {
    static ref KERNEL_UNICAST: SocketAddr = SocketAddr::new(0, 0);
}

use crate::{Error, ErrorKind};

/// A handle to the netlink connection, used to send and receive netlink messsage
#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle) -> Self {
        Handle(conn)
    }

    /// Send a netlink message, and get the reponse as a stream of messages.
    pub fn request(
        &mut self,
        message: NetlinkMessage,
    ) -> impl Stream<Item = NetlinkMessage, Error = Error> {
        self.0
            .request(message, *KERNEL_UNICAST)
            .map_err(|e| e.context(ErrorKind::RequestFailed).into())
    }

    /// Send a netlink message that expects an acknowledgement. The returned future resolved when
    /// that ACK is received. If anything else is received, the future resolves into an error.
    fn acked_request(&mut self, message: NetlinkMessage) -> impl Future<Item = (), Error = Error> {
        self.request(message).take(1).for_each(|nl_msg| {
            let (header, payload) = nl_msg.into_parts();
            match payload {
                NetlinkPayload::Ack(_) => Ok(()),
                NetlinkPayload::Error(err_msg) => Err(ErrorKind::NetlinkError(err_msg).into()),
                _ => Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into()),
            }
        })
    }

    /// Add the given rule
    pub fn add_rule(&mut self, rule: RuleMessage) -> impl Future<Item = (), Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::AddRule(rule));
        req.header.flags =
            NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE);
        self.acked_request(req)
    }

    /// Deletes a given rule
    pub fn del_rule(&mut self, rule: RuleMessage) -> impl Future<Item = (), Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::DelRule(rule));
        req.header.flags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_NONREC);
        self.acked_request(req)
    }

    /// List the current rules
    pub fn list_rules(&mut self) -> impl Stream<Item = RuleMessage, Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::ListRules(None));
        req.header.flags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_DUMP);

        self.request(req).and_then(|nl_msg| {
            let (header, payload) = nl_msg.into_parts();
            match payload {
                NetlinkPayload::Audit(AuditMessage::ListRules(Some(rule_msg))) => Ok(rule_msg),
                NetlinkPayload::Error(err_msg) => Err(ErrorKind::NetlinkError(err_msg).into()),
                _ => Err(ErrorKind::UnexpectedMessage(NetlinkMessage::new(header, payload)).into()),
            }
        })
    }

    /// Enable receiving audit events
    pub fn enable_events(&mut self) -> impl Future<Item = (), Error = Error> {
        let mut status = StatusMessage::new();
        status.enabled = 1;
        status.pid = process::id();
        status.mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID;
        let mut req = NetlinkMessage::from(AuditMessage::SetStatus(status));
        req.header.flags = NetlinkFlags::from(NLM_F_REQUEST | NLM_F_ACK);
        self.acked_request(req)
    }
}

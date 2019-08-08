use failure::Fail;
use futures::{Future, Stream};
use netlink_packet_audit::{rules::RuleMessage, AuditMessage, StatusMessage};
use netlink_packet_core::{
    header::flags::{NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL, NLM_F_NONREC, NLM_F_REQUEST},
    NetlinkFlags, NetlinkMessage, NetlinkPayload,
};
use netlink_proto::{sys::SocketAddr, ConnectionHandle};
use std::process;

lazy_static! {
    static ref KERNEL_UNICAST: SocketAddr = SocketAddr::new(0, 0);
}

// ==========================================
// mask values
// ==========================================
pub const AUDIT_STATUS_ENABLED: u32 = 1;
pub const AUDIT_STATUS_FAILURE: u32 = 2;
pub const AUDIT_STATUS_PID: u32 = 4;
pub const AUDIT_STATUS_RATE_LIMIT: u32 = 8;
pub const AUDIT_STATUS_BACKLOG_LIMIT: u32 = 16;
pub const AUDIT_STATUS_BACKLOG_WAIT_TIME: u32 = 32;
pub const AUDIT_STATUS_LOST: u32 = 64;
pub const AUDIT_FEATURE_BITMAP_BACKLOG_LIMIT: u32 = 1;
pub const AUDIT_FEATURE_BITMAP_BACKLOG_WAIT_TIME: u32 = 2;
pub const AUDIT_FEATURE_BITMAP_EXECUTABLE_PATH: u32 = 4;
pub const AUDIT_FEATURE_BITMAP_EXCLUDE_EXTEND: u32 = 8;
pub const AUDIT_FEATURE_BITMAP_SESSIONID_FILTER: u32 = 16;
pub const AUDIT_FEATURE_BITMAP_LOST_RESET: u32 = 32;
pub const AUDIT_FEATURE_BITMAP_FILTER_FS: u32 = 64;
pub const AUDIT_FEATURE_BITMAP_ALL: u32 = 127;
pub const AUDIT_VERSION_LATEST: u32 = 127;
pub const AUDIT_VERSION_BACKLOG_LIMIT: u32 = 1;
pub const AUDIT_VERSION_BACKLOG_WAIT_TIME: u32 = 2;

use crate::{Error, ErrorKind};

/// A handle to the netlink connection, used to send and receive netlink messsage
#[derive(Clone, Debug)]
pub struct Handle(ConnectionHandle<AuditMessage>);

impl Handle {
    pub(crate) fn new(conn: ConnectionHandle<AuditMessage>) -> Self {
        Handle(conn)
    }

    /// Send a netlink message, and get the reponse as a stream of messages.
    pub fn request(
        &mut self,
        message: NetlinkMessage<AuditMessage>,
    ) -> impl Stream<Item = NetlinkMessage<AuditMessage>, Error = Error> {
        self.0
            .request(message, *KERNEL_UNICAST)
            .map_err(|e| e.context(ErrorKind::RequestFailed).into())
    }

    /// Send a netlink message that expects an acknowledgement. The returned future resolved when
    /// that ACK is received. If anything else is received, the future resolves into an error.
    fn acked_request(
        &mut self,
        message: NetlinkMessage<AuditMessage>,
    ) -> impl Future<Item = (), Error = Error> {
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
                NetlinkPayload::InnerMessage(AuditMessage::ListRules(Some(rule_msg))) => {
                    Ok(rule_msg)
                }
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

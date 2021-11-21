// SPDX-License-Identifier: MIT

use std::process;

use futures::{
    future::{self, Either},
    stream::{Stream, StreamExt, TryStream},
    FutureExt,
};
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

use crate::packet::{
    rules::RuleMessage,
    AuditMessage,
    NetlinkMessage,
    NetlinkPayload,
    StatusMessage,
    NLM_F_ACK,
    NLM_F_CREATE,
    NLM_F_DUMP,
    NLM_F_EXCL,
    NLM_F_NONREC,
    NLM_F_REQUEST,
};

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

use crate::Error;

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
    ) -> Result<impl Stream<Item = NetlinkMessage<AuditMessage>>, Error> {
        self.0
            .request(message, SocketAddr::new(0, 0))
            .map_err(|_| Error::RequestFailed)
    }

    /// Send a netlink message that expects an acknowledgement. The returned future resolved when
    /// that ACK is received. If anything else is received, the future resolves into an error.
    async fn acked_request(&mut self, message: NetlinkMessage<AuditMessage>) -> Result<(), Error> {
        let mut response = self.request(message)?;
        if let Some(message) = response.next().await {
            let (header, payload) = message.into_parts();
            // NetlinkError and AuditMessage are forwarded to the
            // handle. Ack is signaled by the stream finishing.
            if let NetlinkPayload::Error(err_msg) = payload {
                Err(Error::NetlinkError(err_msg))
            } else {
                Err(Error::UnexpectedMessage(NetlinkMessage::new(
                    header, payload,
                )))
            }
        } else {
            Ok(())
        }
    }

    /// Add the given rule
    pub async fn add_rule(&mut self, rule: RuleMessage) -> Result<(), Error> {
        let mut req = NetlinkMessage::from(AuditMessage::AddRule(rule));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE;
        self.acked_request(req).await
    }

    /// Deletes a given rule
    pub async fn del_rule(&mut self, rule: RuleMessage) -> Result<(), Error> {
        let mut req = NetlinkMessage::from(AuditMessage::DelRule(rule));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_NONREC;
        self.acked_request(req).await
    }

    /// List the current rules
    pub fn list_rules(&mut self) -> impl TryStream<Ok = RuleMessage, Error = Error> {
        let mut req = NetlinkMessage::from(AuditMessage::ListRules(None));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match self.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                let (header, payload) = msg.into_parts();
                match payload {
                    NetlinkPayload::InnerMessage(AuditMessage::ListRules(Some(rule_msg))) => {
                        Ok(rule_msg)
                    }
                    NetlinkPayload::Error(err_msg) => Err(Error::NetlinkError(err_msg)),
                    _ => Err(Error::UnexpectedMessage(NetlinkMessage::new(
                        header, payload,
                    ))),
                }
            })),
            Err(e) => Either::Right(future::err::<RuleMessage, Error>(e).into_stream()),
        }
    }

    /// Enable receiving audit events
    pub async fn enable_events(&mut self) -> Result<(), Error> {
        let mut status = StatusMessage::new();
        status.enabled = 1;
        status.pid = process::id();
        status.mask = AUDIT_STATUS_ENABLED | AUDIT_STATUS_PID;
        let mut req = NetlinkMessage::from(AuditMessage::SetStatus(status));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        self.acked_request(req).await
    }

    /// Get current audit status
    pub async fn get_status(&mut self) -> Result<StatusMessage, Error> {
        let mut req = NetlinkMessage::from(AuditMessage::GetStatus(None));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        let mut request = self.request(req)?;

        let response = request.next().await.ok_or(Error::RequestFailed)?;

        match response.into_parts() {
            (_, NetlinkPayload::InnerMessage(AuditMessage::GetStatus(Some(status)))) => Ok(status),
            (header, payload) => Err(Error::UnexpectedMessage(NetlinkMessage::new(
                header, payload,
            ))),
        }
    }
}

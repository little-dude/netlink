use crate::{
    constants::*,
    rules::{RuleBuffer, RuleMessage},
    traits::{Parseable, ParseableParametrized},
    AuditMessage,
    DecodeError,
    StatusMessage,
    StatusMessageBuffer,
};
use anyhow::Context;

pub struct AuditBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> AuditBuffer<T> {
    pub fn new(buffer: T) -> AuditBuffer<T> {
        AuditBuffer { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<AuditBuffer<T>, DecodeError> {
        Ok(Self::new(buffer))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AuditBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        &self.buffer.as_ref()
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> AuditBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<AuditBuffer<&'a T>, u16> for AuditMessage {
    fn parse_with_param(buf: &AuditBuffer<&'a T>, message_type: u16) -> Result<Self, DecodeError> {
        use self::AuditMessage::*;
        let message = match message_type {
            AUDIT_GET if buf.length() == 0 => GetStatus(None),
            AUDIT_GET => {
                let err = "failed to parse AUDIT_GET message";
                let buf = StatusMessageBuffer::new(buf.inner());
                GetStatus(Some(StatusMessage::parse(&buf).context(err)?))
            }
            AUDIT_SET => {
                let err = "failed to parse AUDIT_SET message";
                let buf = StatusMessageBuffer::new(buf.inner());
                SetStatus(StatusMessage::parse(&buf).context(err)?)
            }
            AUDIT_ADD_RULE => {
                let err = "failed to parse AUDIT_ADD_RULE message";
                let buf = RuleBuffer::new_checked(buf.inner()).context(err)?;
                AddRule(RuleMessage::parse(&buf).context(err)?)
            }
            AUDIT_DEL_RULE => {
                let err = "failed to parse AUDIT_DEL_RULE message";
                let buf = RuleBuffer::new_checked(buf.inner()).context(err)?;
                DelRule(RuleMessage::parse(&buf).context(err)?)
            }
            AUDIT_LIST_RULES if buf.length() == 0 => ListRules(None),
            AUDIT_LIST_RULES => {
                let err = "failed to parse AUDIT_LIST_RULES message";
                let buf = RuleBuffer::new_checked(buf.inner()).context(err)?;
                ListRules(Some(RuleMessage::parse(&buf).context(err)?))
            }
            i if (AUDIT_EVENT_MESSAGE_MIN..AUDIT_EVENT_MESSAGE_MAX).contains(&i) => {
                let data = String::from_utf8(buf.inner().to_vec())
                    .context("failed to parse audit event data as a valid string")?;
                Event((i, data))
            }
            i => {
                let data = String::from_utf8(buf.inner().to_vec())
                    .context("failed to parse audit event data as a valid string")?;
                Other((i, data))
            }
        };
        Ok(message)
    }
}

use crate::{
    commands::*, events::*, netlink::DecodeError, rules::RuleBuffer, AuditMessage, Parseable,
    ParseableParametrized, StatusMessageBuffer,
};
use failure::ResultExt;

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
        &self.buffer.as_ref()[..]
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> AuditBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[..]
    }
}

impl<'buffer, T: AsRef<[u8]> + ?Sized> ParseableParametrized<AuditMessage, u16>
    for AuditBuffer<&'buffer T>
{
    #[rustfmt::skip]
    fn parse_with_param(&self, message_type: u16) -> Result<AuditMessage, DecodeError> {
        use self::AuditMessage::*;
        let message = match message_type {
            AUDIT_GET if self.length() == 0 => GetStatus(None),
            AUDIT_GET => GetStatus(Some(
                StatusMessageBuffer::new(self.inner())
                    .parse()
                    .context("failed to parse AUDIT_GET message")?,
            )),
            AUDIT_SET => SetStatus(
                StatusMessageBuffer::new(self.inner())
                    .parse()
                    .context("failed to parse AUDIT_SET message")?,
            ),
            AUDIT_ADD_RULE => AddRule(
                RuleBuffer::new_checked(&self.inner())
                    .context("failed to parse AUDIT_ADD_RULE message")?
                    .parse()
                    .context("failed to parse AUDIT_ADD_RULE message")?,
            ),
            AUDIT_DEL_RULE => DelRule(
                RuleBuffer::new_checked(&self.inner())
                    .context("failed to parse AUDIT_DEL_RULE message")?
                    .parse()
                    .context("failed to parse AUDIT_DEL_RULE message")?,
            ),
            AUDIT_LIST_RULES if self.length() == 0 => ListRules(None),
            AUDIT_LIST_RULES => ListRules(Some(
                RuleBuffer::new_checked(&self.inner())
                    .context("failed to parse AUDIT_LIST_RULES message")?
                    .parse()
                    .context("failed to parse AUDIT_LIST_RULES message")?,
            )),
            i if i >= AUDIT_EVENT_MESSAGE_MIN && i <= AUDIT_EVENT_MESSAGE_MAX => {
                let data = String::from_utf8(self.inner().to_vec())
                    .context("failed to parse audit event data as a valid string")?;
                Event((i, data))
            }
            _ => return Err(format!("unknown message type {}", message_type).into()),

        };
        Ok(message)
    }
}

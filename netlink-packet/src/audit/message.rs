use failure::ResultExt;

use constants::*;
use {DecodeError, Emitable, Parseable, RuleBuffer, RuleMessage, StatusMessage};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AuditMessage {
    GetStatus(Option<StatusMessage>),
    SetStatus(StatusMessage),
    AddRule(RuleMessage),
    DelRule(RuleMessage),
    ListRules(Option<RuleMessage>),
}

impl AuditMessage {
    pub fn is_get_status(&self) -> bool {
        if let AuditMessage::GetStatus(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_set_status(&self) -> bool {
        if let AuditMessage::GetStatus(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_add_rule(&self) -> bool {
        if let AuditMessage::AddRule(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_del_rule(&self) -> bool {
        if let AuditMessage::DelRule(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn is_list_rules(&self) -> bool {
        if let AuditMessage::ListRules(_) = *self {
            true
        } else {
            false
        }
    }

    pub fn message_type(&self) -> u16 {
        use self::AuditMessage::*;

        match self {
            GetStatus(_) => AUDIT_GET,
            SetStatus(_) => AUDIT_SET,
            ListRules(_) => AUDIT_LIST_RULES,
            AddRule(_) => AUDIT_ADD_RULE,
            DelRule(_) => AUDIT_DEL_RULE,
        }
    }

    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        use self::AuditMessage::*;

        let message = match message_type {
            AUDIT_GET if buffer.is_empty() => GetStatus(None),
            AUDIT_GET => GetStatus(Some(
                buffer.parse().context("failed to parse AUDIT_GET message")?,
            )),
            AUDIT_SET => SetStatus(buffer.parse().context("failed to parse AUDIT_SET message")?),
            AUDIT_ADD_RULE => AddRule(
                RuleBuffer::new_checked(&buffer)
                    .context("failed to parse AUDIT_ADD_RULE message")?
                    .parse()
                    .context("failed to parse AUDIT_ADD_RULE message")?,
            ),
            AUDIT_DEL_RULE => DelRule(
                RuleBuffer::new_checked(&buffer)
                    .context("failed to parse AUDIT_DEL_RULE message")?
                    .parse()
                    .context("failed to parse AUDIT_DEL_RULE message")?,
            ),
            AUDIT_LIST_RULES if buffer.is_empty() => ListRules(None),
            AUDIT_LIST_RULES => ListRules(Some(
                RuleBuffer::new_checked(&buffer)
                    .context("failed to parse AUDIT_LIST_RULES message")?
                    .parse()
                    .context("failed to parse AUDIT_LIST_RULES message")?,
            )),
            _ => return Err(format!("unknown message type {}", message_type).into()),
        };
        Ok(message)
    }
}

impl Emitable for AuditMessage {
    fn buffer_len(&self) -> usize {
        use self::AuditMessage::*;

        match self {
            GetStatus(Some(ref msg)) => msg.buffer_len(),
            SetStatus(ref msg) => msg.buffer_len(),
            AddRule(ref msg) => msg.buffer_len(),
            DelRule(ref msg) => msg.buffer_len(),
            ListRules(Some(ref msg)) => msg.buffer_len(),

            GetStatus(None) | ListRules(None) => 0,
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        use self::AuditMessage::*;

        match self {
            GetStatus(Some(ref msg)) => msg.emit(buffer),
            SetStatus(ref msg) => msg.emit(buffer),
            AddRule(ref msg) => msg.emit(buffer),
            DelRule(ref msg) => msg.emit(buffer),
            ListRules(Some(ref msg)) => msg.emit(buffer),
            ListRules(None) | GetStatus(None) => {}
        }
    }
}

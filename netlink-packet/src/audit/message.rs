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
    /// Event message (message types 1300 through 1399). This includes the following message types
    /// (this list is non-exhaustive, and not really kept up to date): `AUDIT_SYSCALL`,
    /// `AUDIT_PATH`, `AUDIT_IPC`, `AUDIT_SOCKETCALL`, `AUDIT_CONFIG_CHANGE`, `AUDIT_SOCKADDR`,
    /// `AUDIT_CWD`, `AUDIT_EXECVE`, `AUDIT_IPC_SET_PERM`, `AUDIT_MQ_OPEN`, `AUDIT_MQ_SENDRECV`,
    /// `AUDIT_MQ_NOTIFY`, `AUDIT_MQ_GETSETATTR`, `AUDIT_KERNEL_OTHER`, `AUDIT_FD_PAIR`,
    /// `AUDIT_OBJ_PID`, `AUDIT_TTY`, `AUDIT_EOE`, `AUDIT_BPRM_FCAPS`, `AUDIT_CAPSET`,
    /// `AUDIT_MMAP`, `AUDIT_NETFILTER_PKT`, `AUDIT_NETFILTER_CFG`, `AUDIT_SECCOMP`,
    /// `AUDIT_PROCTITLE`, `AUDIT_FEATURE_CHANGE`, `AUDIT_REPLACE`, `AUDIT_KERN_MODULE`,
    /// `AUDIT_FANOTIFY`.
    ///
    /// The first element of the tuple is the message type, and the second is the event data.
    Event((u16, String)),
}

impl AuditMessage {
    pub fn is_event(&self) -> bool {
        if let AuditMessage::Event(_) = *self {
            true
        } else {
            false
        }
    }

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
            Event((message_type, _)) => *message_type,
        }
    }

    pub(crate) fn parse(message_type: u16, buffer: &[u8]) -> Result<Self, DecodeError> {
        use self::AuditMessage::*;

        let message = match message_type {
            AUDIT_GET if buffer.is_empty() => GetStatus(None),
            AUDIT_GET => GetStatus(Some(
                buffer
                    .parse()
                    .context("failed to parse AUDIT_GET message")?,
            )),
            AUDIT_SET => SetStatus(
                buffer
                    .parse()
                    .context("failed to parse AUDIT_SET message")?,
            ),
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
            i if i >= AUDIT_EVENT_MESSAGE_MIN && i <= AUDIT_EVENT_MESSAGE_MAX => {
                let data = String::from_utf8(buffer.to_vec())
                    .context("failed to parse audit event data as a valid string")?;
                Event((i, data))
            }
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
            Event((_, ref data)) => data.len(),
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
            Event((_, ref data)) => buffer.copy_from_slice(data.as_bytes()),
        }
    }
}

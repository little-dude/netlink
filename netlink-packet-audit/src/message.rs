use crate::{
    constants::*,
    rules::RuleMessage,
    traits::{Emitable, ParseableParametrized},
    AuditBuffer, DecodeError, NetlinkDeserializable, NetlinkHeader, NetlinkPayload,
    NetlinkSerializable, StatusMessage,
};

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

impl NetlinkSerializable<AuditMessage> for AuditMessage {
    fn message_type(&self) -> u16 {
        self.message_type()
    }

    fn buffer_len(&self) -> usize {
        <Self as Emitable>::buffer_len(self)
    }

    fn serialize(&self, buffer: &mut [u8]) {
        self.emit(buffer)
    }
}

impl NetlinkDeserializable<AuditMessage> for AuditMessage {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        match AuditBuffer::new_checked(payload) {
            Err(e) => Err(e),
            Ok(buffer) => match AuditMessage::parse_with_param(&buffer, header.message_type) {
                Err(e) => Err(e),
                Ok(message) => Ok(message),
            },
        }
    }
}

impl From<AuditMessage> for NetlinkPayload<AuditMessage> {
    fn from(message: AuditMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

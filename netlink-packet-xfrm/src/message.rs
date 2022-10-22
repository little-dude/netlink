// SPDX-License-Identifier: MIT

use crate::{
    constants::*,
    monitor::{
        AcquireMessage, ExpireMessage, GetAsyncEventMessage, MappingMessage, MigrateMessage,
        NewAsyncEventMessage, PolicyExpireMessage, ReportMessage,
    },
    policy::{
        DefaultMessage, DelGetMessage as PolicyDelGetMessage, FlushMessage as PolicyFlushMessage,
        GetSpdInfoMessage, ModifyMessage as PolicyModifyMessage, NewSpdInfoMessage,
    },
    state::{
        AllocSpiMessage, DelGetMessage as StateDelGetMessage, FlushMessage as StateFlushMessage,
        GetDumpMessage, GetSadInfoMessage, ModifyMessage as StateModifyMessage, NewSadInfoMessage,
    },
    NetlinkDeserializable, NetlinkHeader, NetlinkPayload, NetlinkSerializable, XfrmBuffer,
};

use netlink_packet_utils::{traits::*, DecodeError};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum XfrmMessage {
    AddPolicy(PolicyModifyMessage),
    DeletePolicy(PolicyDelGetMessage),
    GetPolicy(PolicyDelGetMessage),
    GetSpdInfo(GetSpdInfoMessage),
    NewSpdInfo(NewSpdInfoMessage),
    UpdatePolicy(PolicyModifyMessage),
    FlushPolicy(PolicyFlushMessage),
    SetPolicyDefault(DefaultMessage),
    GetPolicyDefault(DefaultMessage),
    AddSa(StateModifyMessage),
    AllocSpi(AllocSpiMessage),
    DeleteSa(StateDelGetMessage),
    FlushSa(StateFlushMessage),
    GetSa(StateDelGetMessage),
    GetDumpSa(GetDumpMessage),
    GetSadInfo(GetSadInfoMessage),
    NewSadInfo(NewSadInfoMessage),
    UpdateSa(StateModifyMessage),
    Acquire(AcquireMessage),
    Expire(ExpireMessage),
    GetAsyncEvent(GetAsyncEventMessage),
    NewAsyncEvent(NewAsyncEventMessage),
    PolicyExpire(PolicyExpireMessage),
    Report(ReportMessage),
    Mapping(MappingMessage),
    Migrate(MigrateMessage),
    Other((u16, Vec<u8>)),
}

impl XfrmMessage {
    pub fn message_type(&self) -> u16 {
        use self::XfrmMessage::*;

        match self {
            AddPolicy(_) => XFRM_MSG_NEWPOLICY,
            DeletePolicy(_) => XFRM_MSG_DELPOLICY,
            GetPolicy(_) => XFRM_MSG_GETPOLICY,
            GetSpdInfo(_) => XFRM_MSG_GETSPDINFO,
            NewSpdInfo(_) => XFRM_MSG_NEWSPDINFO,
            UpdatePolicy(_) => XFRM_MSG_UPDPOLICY,
            FlushPolicy(_) => XFRM_MSG_FLUSHPOLICY,
            SetPolicyDefault(_) => XFRM_MSG_SETDEFAULT,
            GetPolicyDefault(_) => XFRM_MSG_GETDEFAULT,
            AddSa(_) => XFRM_MSG_NEWSA,
            AllocSpi(_) => XFRM_MSG_ALLOCSPI,
            DeleteSa(_) => XFRM_MSG_DELSA,
            FlushSa(_) => XFRM_MSG_FLUSHSA,
            GetSa(_) => XFRM_MSG_GETSA,
            GetDumpSa(_) => XFRM_MSG_GETSA,
            GetSadInfo(_) => XFRM_MSG_GETSADINFO,
            NewSadInfo(_) => XFRM_MSG_NEWSADINFO,
            UpdateSa(_) => XFRM_MSG_UPDSA,
            Acquire(_) => XFRM_MSG_ACQUIRE,
            Expire(_) => XFRM_MSG_EXPIRE,
            GetAsyncEvent(_) => XFRM_MSG_GETAE,
            NewAsyncEvent(_) => XFRM_MSG_NEWAE,
            PolicyExpire(_) => XFRM_MSG_POLEXPIRE,
            Report(_) => XFRM_MSG_REPORT,
            Mapping(_) => XFRM_MSG_MAPPING,
            Migrate(_) => XFRM_MSG_MIGRATE,
            Other((message_type, _)) => *message_type,
        }
    }
}

impl Emitable for XfrmMessage {
    fn buffer_len(&self) -> usize {
        use self::XfrmMessage::*;

        match self {
            AddPolicy(ref msg) => msg.buffer_len(),
            DeletePolicy(ref msg) => msg.buffer_len(),
            GetPolicy(ref msg) => msg.buffer_len(),
            GetSpdInfo(ref msg) => msg.buffer_len(),
            NewSpdInfo(ref msg) => msg.buffer_len(),
            UpdatePolicy(ref msg) => msg.buffer_len(),
            FlushPolicy(ref msg) => msg.buffer_len(),
            SetPolicyDefault(ref msg) => msg.buffer_len(),
            GetPolicyDefault(ref msg) => msg.buffer_len(),
            AddSa(ref msg) => msg.buffer_len(),
            AllocSpi(ref msg) => msg.buffer_len(),
            DeleteSa(ref msg) => msg.buffer_len(),
            FlushSa(ref msg) => msg.buffer_len(),
            GetSa(ref msg) => msg.buffer_len(),
            GetDumpSa(ref msg) => msg.buffer_len(),
            GetSadInfo(ref msg) => msg.buffer_len(),
            NewSadInfo(ref msg) => msg.buffer_len(),
            UpdateSa(ref msg) => msg.buffer_len(),
            Acquire(ref msg) => msg.buffer_len(),
            Expire(ref msg) => msg.buffer_len(),
            GetAsyncEvent(ref msg) => msg.buffer_len(),
            NewAsyncEvent(ref msg) => msg.buffer_len(),
            PolicyExpire(ref msg) => msg.buffer_len(),
            Report(ref msg) => msg.buffer_len(),
            Mapping(ref msg) => msg.buffer_len(),
            Migrate(ref msg) => msg.buffer_len(),
            Other((_, ref data)) => data.len(),
        }
    }

    fn emit(&self, buffer: &mut [u8]) {
        use self::XfrmMessage::*;

        match self {
            AddPolicy(ref msg) => msg.emit(buffer),
            DeletePolicy(ref msg) => msg.emit(buffer),
            GetPolicy(ref msg) => msg.emit(buffer),
            GetSpdInfo(ref msg) => msg.emit(buffer),
            NewSpdInfo(ref msg) => msg.emit(buffer),
            UpdatePolicy(ref msg) => msg.emit(buffer),
            FlushPolicy(ref msg) => msg.emit(buffer),
            SetPolicyDefault(ref msg) => msg.emit(buffer),
            GetPolicyDefault(ref msg) => msg.emit(buffer),
            AddSa(ref msg) => msg.emit(buffer),
            AllocSpi(ref msg) => msg.emit(buffer),
            DeleteSa(ref msg) => msg.emit(buffer),
            FlushSa(ref msg) => msg.emit(buffer),
            GetSa(ref msg) => msg.emit(buffer),
            GetDumpSa(ref msg) => msg.emit(buffer),
            GetSadInfo(ref msg) => msg.emit(buffer),
            NewSadInfo(ref msg) => msg.emit(buffer),
            UpdateSa(ref msg) => msg.emit(buffer),
            Acquire(ref msg) => msg.emit(buffer),
            Expire(ref msg) => msg.emit(buffer),
            GetAsyncEvent(ref msg) => msg.emit(buffer),
            NewAsyncEvent(ref msg) => msg.emit(buffer),
            PolicyExpire(ref msg) => msg.emit(buffer),
            Report(ref msg) => msg.emit(buffer),
            Mapping(ref msg) => msg.emit(buffer),
            Migrate(ref msg) => msg.emit(buffer),
            Other((_, ref data)) => buffer.copy_from_slice(&data[..]),
        }
    }
}

impl NetlinkSerializable for XfrmMessage {
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

impl NetlinkDeserializable for XfrmMessage {
    type Error = DecodeError;
    fn deserialize(header: &NetlinkHeader, payload: &[u8]) -> Result<Self, Self::Error> {
        match XfrmBuffer::new_checked(payload) {
            Err(e) => Err(e),
            Ok(buffer) => match XfrmMessage::parse_with_param(&buffer, header.message_type) {
                Err(e) => Err(e),
                Ok(message) => Ok(message),
            },
        }
    }
}

impl From<XfrmMessage> for NetlinkPayload<XfrmMessage> {
    fn from(message: XfrmMessage) -> Self {
        NetlinkPayload::InnerMessage(message)
    }
}

// SPDX-License-Identifier: MIT

use anyhow::Context;

use crate::{
    constants::*,
    monitor::{
        AcquireMessage,
        AcquireMessageBuffer,
        ExpireMessage,
        ExpireMessageBuffer,
        GetAsyncEventMessage,
        GetAsyncEventMessageBuffer,
        MappingMessage,
        MappingMessageBuffer,
        MigrateMessage,
        MigrateMessageBuffer,
        NewAsyncEventMessage,
        NewAsyncEventMessageBuffer,
        PolicyExpireMessage,
        PolicyExpireMessageBuffer,
        ReportMessage,
        ReportMessageBuffer,
    },
    policy::{
        DefaultMessage,
        DefaultMessageBuffer,
        DelGetMessage as PolicyDelGetMessage,
        DelGetMessageBuffer as PolicyDelGetMessageBuffer,
        FlushMessage as PolicyFlushMessage,
        FlushMessageBuffer as PolicyFlushMessageBuffer,
        GetSpdInfoMessage,
        GetSpdInfoMessageBuffer,
        ModifyMessage as PolicyModifyMessage,
        ModifyMessageBuffer as PolicyModifyMessageBuffer,
        NewSpdInfoMessage,
        NewSpdInfoMessageBuffer,
    },
    state::{
        AllocSpiMessage,
        AllocSpiMessageBuffer,
        DelGetMessage as StateDelGetMessage,
        DelGetMessageBuffer as StateDelGetMessageBuffer,
        FlushMessage as StateFlushMessage,
        FlushMessageBuffer as StateFlushMessageBuffer,
        GetSadInfoMessage,
        GetSadInfoMessageBuffer,
        ModifyMessage as StateModifyMessage,
        ModifyMessageBuffer as StateModifyMessageBuffer,
        NewSadInfoMessage,
        NewSadInfoMessageBuffer,
    },
    XfrmMessage,
};

use netlink_packet_utils::{
    traits::*,
    DecodeError,
};

pub struct XfrmBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> XfrmBuffer<T> {
    pub fn new(buffer: T) -> XfrmBuffer<T> {
        XfrmBuffer { buffer }
    }

    pub fn length(&self) -> usize {
        self.buffer.as_ref().len()
    }

    pub fn new_checked(buffer: T) -> Result<XfrmBuffer<T>, DecodeError> {
        Ok(Self::new(buffer))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> XfrmBuffer<&'a T> {
    pub fn inner(&self) -> &'a [u8] {
        self.buffer.as_ref()
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> XfrmBuffer<&'a mut T> {
    pub fn inner_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<XfrmBuffer<&'a T>, u16> for XfrmMessage {
    fn parse_with_param(buf: &XfrmBuffer<&'a T>, message_type: u16) -> Result<Self, DecodeError> {
        use self::XfrmMessage::*;
        let message = match message_type {
            XFRM_MSG_NEWSA => {
                let err = "failed to parse XFRM_MSG_NEWSA message";
                let msg = StateModifyMessage::parse(&StateModifyMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                AddSa(msg)
            }

            XFRM_MSG_DELSA => {
                let err = "failed to parse XFRM_MSG_DELSA message";
                let msg = StateDelGetMessage::parse(&StateDelGetMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                DeleteSa(msg)
            }

            XFRM_MSG_GETSA => {
                let err = "failed to parse XFRM_MSG_GETSA message";
                let msg = StateDelGetMessage::parse(&StateDelGetMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetSa(msg)
            }

            XFRM_MSG_NEWPOLICY => {
                let err = "failed to parse XFRM_MSG_NEWPOLICY message";
                let msg = PolicyModifyMessage::parse(&PolicyModifyMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                AddPolicy(msg)
            }

            XFRM_MSG_DELPOLICY => {
                let err = "failed to parse XFRM_MSG_DELPOLICY message";
                let msg = PolicyDelGetMessage::parse(&PolicyDelGetMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                DeletePolicy(msg)
            }

            XFRM_MSG_GETPOLICY => {
                let err = "failed to parse XFRM_MSG_GETPOLICY message";
                let msg = PolicyDelGetMessage::parse(&PolicyDelGetMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetPolicy(msg)
            }

            XFRM_MSG_ALLOCSPI => {
                let err = "failed to parse XFRM_MSG_ALLOCSPI message";
                let msg = AllocSpiMessage::parse(&AllocSpiMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                AllocSpi(msg)
            }

            XFRM_MSG_ACQUIRE => {
                let err = "failed to parse XFRM_MSG_ACQUIRE message";
                let msg = AcquireMessage::parse(&AcquireMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                Acquire(msg)
            }

            XFRM_MSG_EXPIRE => {
                let err = "failed to parse XFRM_MSG_EXPIRE message";
                let msg = ExpireMessage::parse(&ExpireMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                Expire(msg)
            }

            XFRM_MSG_UPDPOLICY => {
                let err = "failed to parse XFRM_MSG_UPDPOLICY message";
                let msg = PolicyModifyMessage::parse(&PolicyModifyMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                UpdatePolicy(msg)
            }

            XFRM_MSG_UPDSA => {
                let err = "failed to parse XFRM_MSG_UPDSA message";
                let msg = StateModifyMessage::parse(&StateModifyMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                UpdateSa(msg)
            }

            XFRM_MSG_POLEXPIRE => {
                let err = "failed to parse XFRM_MSG_POLEXPIRE message";
                let msg = PolicyExpireMessage::parse(&PolicyExpireMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                PolicyExpire(msg)
            }

            XFRM_MSG_FLUSHSA => {
                let err = "failed to parse XFRM_MSG_FLUSHSA message";
                let msg = StateFlushMessage::parse(&StateFlushMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                FlushSa(msg)
            }

            XFRM_MSG_FLUSHPOLICY => {
                let err = "failed to parse XFRM_MSG_FLUSHPOLICY message";
                let msg = PolicyFlushMessage::parse(&PolicyFlushMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                FlushPolicy(msg)
            }

            XFRM_MSG_NEWAE => {
                let err = "failed to parse XFRM_MSG_NEWAE message";
                let msg = NewAsyncEventMessage::parse(&NewAsyncEventMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                NewAsyncEvent(msg)
            }

            XFRM_MSG_GETAE => {
                let err = "failed to parse XFRM_MSG_GETAE message";
                let msg = GetAsyncEventMessage::parse(&GetAsyncEventMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetAsyncEvent(msg)
            }

            XFRM_MSG_REPORT => {
                let err = "failed to parse XFRM_MSG_REPORT message";
                let msg = ReportMessage::parse(&ReportMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                Report(msg)
            }

            XFRM_MSG_MIGRATE => {
                let err = "failed to parse XFRM_MSG_MIGRATE message";
                let msg = MigrateMessage::parse(&MigrateMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                Migrate(msg)
            }

            XFRM_MSG_NEWSADINFO => {
                let err = "failed to parse XFRM_MSG_NEWSADINFO message";
                let msg = NewSadInfoMessage::parse(&NewSadInfoMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                NewSadInfo(msg)
            }

            XFRM_MSG_GETSADINFO => {
                let err = "failed to parse XFRM_MSG_GETSADINFO message";
                let msg = GetSadInfoMessage::parse(&GetSadInfoMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetSadInfo(msg)
            }

            XFRM_MSG_NEWSPDINFO => {
                let err = "failed to parse XFRM_MSG_NEWSPDINFO message";
                let msg = NewSpdInfoMessage::parse(&NewSpdInfoMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                NewSpdInfo(msg)
            }

            XFRM_MSG_GETSPDINFO => {
                let err = "failed to parse XFRM_MSG_GETSPDINFO message";
                let msg = GetSpdInfoMessage::parse(&GetSpdInfoMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetSpdInfo(msg)
            }

            XFRM_MSG_MAPPING => {
                let err = "failed to parse XFRM_MSG_MAPPING message";
                let msg = MappingMessage::parse(&MappingMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                Mapping(msg)
            }

            XFRM_MSG_SETDEFAULT => {
                let err = "failed to parse XFRM_MSG_SETDEFAULT message";
                let msg = DefaultMessage::parse(&DefaultMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                SetPolicyDefault(msg)
            }

            XFRM_MSG_GETDEFAULT => {
                let err = "failed to parse XFRM_MSG_GETDEFAULT message";
                let msg = DefaultMessage::parse(&DefaultMessageBuffer::new_checked(&buf.inner()).context(err)?).context(err)?;
                GetPolicyDefault(msg)
            }

            i => {
                let data = buf.inner().to_vec();
                Other((i, data))
            }
        };
        Ok(message)
    }
}

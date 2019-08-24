use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

use crate::{netlink::DecodeError, rules::*, Field, Parseable};

// FIXME: when const fn are stable, use them, instead of defining a macro
// const fn u32_array(start: usize, len: usize) -> Field {
//     start..(start + 4 * len)
// }
macro_rules! u32_array {
    ($start:expr, $len:expr) => {
        $start..($start + 4 * $len)
    };
}

const FLAGS: Field = 0..4;
const ACTION: Field = 4..8;
const FIELD_COUNT: Field = 8..12;
const SYSCALLS: Field = u32_array!(FIELD_COUNT.end, AUDIT_BITMASK_SIZE);
const FIELDS: Field = u32_array!(SYSCALLS.end, AUDIT_MAX_FIELDS);
const VALUES: Field = u32_array!(FIELDS.end, AUDIT_MAX_FIELDS);
const FIELD_FLAGS: Field = u32_array!(VALUES.end, AUDIT_MAX_FIELDS);
const BUFLEN: Field = FIELD_FLAGS.end..FIELD_FLAGS.end + 4;

pub(crate) const RULE_BUF_MIN_LEN: usize = BUFLEN.end;

#[allow(non_snake_case)]
fn BUF(len: usize) -> Field {
    BUFLEN.end..(BUFLEN.end + len)
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleBuffer<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> RuleBuffer<T> {
    pub fn new(buffer: T) -> RuleBuffer<T> {
        RuleBuffer { buffer }
    }

    pub fn new_checked(buffer: T) -> Result<Self, DecodeError> {
        let packet = Self::new(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    pub(crate) fn check_len(&self) -> Result<(), DecodeError> {
        let len = self.buffer.as_ref().len();
        if len < BUFLEN.end {
            Err(format!(
                "buffer size is {}, whereas a rule buffer is at least {} long",
                len, BUFLEN.end
            )
            .into())
        } else if len < BUFLEN.end + self.buflen() as usize {
            Err(format!(
                "buffer length is {}, but it should be {} (header) + {} (length field)",
                len,
                BUFLEN.end,
                self.buflen()
            )
            .into())
        } else {
            Ok(())
        }
    }

    pub fn flags(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[FLAGS])
    }

    pub fn action(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[ACTION])
    }

    pub fn field_count(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[FIELD_COUNT])
    }

    pub fn buflen(&self) -> u32 {
        NativeEndian::read_u32(&self.buffer.as_ref()[BUFLEN])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> RuleBuffer<&'a T> {
    pub fn syscalls(&self) -> &'a [u8] {
        &self.buffer.as_ref()[SYSCALLS]
    }

    pub fn fields(&self) -> &'a [u8] {
        &self.buffer.as_ref()[FIELDS]
    }

    pub fn values(&self) -> &'a [u8] {
        &self.buffer.as_ref()[VALUES]
    }

    pub fn field_flags(&self) -> &'a [u8] {
        &self.buffer.as_ref()[FIELD_FLAGS]
    }

    pub fn buf(&self) -> &'a [u8] {
        let field = BUF(self.buflen() as usize);
        &self.buffer.as_ref()[field.start..field.end]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RuleBuffer<T> {
    pub fn set_flags(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[FLAGS], value)
    }

    pub fn set_action(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[ACTION], value)
    }

    pub fn set_field_count(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[FIELD_COUNT], value)
    }

    pub fn set_buflen(&mut self, value: u32) {
        NativeEndian::write_u32(&mut self.buffer.as_mut()[BUFLEN], value)
    }

    pub fn syscalls_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[SYSCALLS]
    }

    pub fn fields_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[FIELDS]
    }

    pub fn set_field(&mut self, position: usize, value: u32) {
        let offset = FIELDS.start + (position * 4);
        assert!(position <= FIELDS.end - 4);
        NativeEndian::write_u32(&mut self.buffer.as_mut()[offset..offset + 4], value)
    }

    pub fn values_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[VALUES]
    }

    pub fn set_value(&mut self, position: usize, value: u32) {
        let offset = VALUES.start + (position * 4);
        assert!(position <= VALUES.end - 4);
        NativeEndian::write_u32(&mut self.buffer.as_mut()[offset..offset + 4], value)
    }

    pub fn field_flags_mut(&mut self) -> &mut [u8] {
        &mut self.buffer.as_mut()[FIELD_FLAGS]
    }

    pub fn set_field_flags(&mut self, position: usize, value: u32) {
        let offset = FIELD_FLAGS.start + (position * 4);
        assert!(position <= FIELD_FLAGS.end - 4);
        NativeEndian::write_u32(&mut self.buffer.as_mut()[offset..offset + 4], value)
    }

    pub fn buf_mut(&mut self) -> &mut [u8] {
        let field = BUF(self.buflen() as usize);
        &mut self.buffer.as_mut()[field.start..field.end]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<RuleMessage> for RuleBuffer<&'a T> {
    fn parse(&self) -> Result<RuleMessage, DecodeError> {
        use self::RuleField::*;

        self.check_len().context("invalid rule message buffer")?;
        let mut rule = RuleMessage::new();
        rule.flags = self.flags().into();
        rule.action = self.action().into();
        rule.syscalls = RuleSyscalls::from_slice(self.syscalls())?;

        let mut offset = 0;

        let fields = self
            .fields()
            .chunks(4)
            .map(|chunk| NativeEndian::read_u32(chunk));
        let values = self
            .values()
            .chunks(4)
            .map(|chunk| NativeEndian::read_u32(chunk));
        let field_flags = self
            .field_flags()
            .chunks(4)
            .map(|chunk| RuleFieldFlags::from(NativeEndian::read_u32(chunk)));
        for (field, value, flags) in fields
            .zip(values.zip(field_flags))
            .map(|(field, (value, flags))| (field, value, flags))
            .take(self.field_count() as usize)
        {
            let field = match field {
                AUDIT_PID => Pid(value),
                AUDIT_UID => Uid(value),
                AUDIT_EUID => Euid(value),
                AUDIT_SUID => Suid(value),
                AUDIT_FSUID => Fsuid(value),
                AUDIT_GID => Gid(value),
                AUDIT_EGID => Egid(value),
                AUDIT_SGID => Sgid(value),
                AUDIT_FSGID => Fsgid(value),
                AUDIT_LOGINUID => Loginuid(value),
                AUDIT_PERS => Pers(value),
                AUDIT_ARCH => Arch(value),
                AUDIT_MSGTYPE => Msgtype(value),
                AUDIT_PPID => Ppid(value),
                AUDIT_LOGINUID_SET => LoginuidSet(value),
                AUDIT_SESSIONID => Sessionid(value),
                AUDIT_FSTYPE => Fstype(value),
                AUDIT_DEVMAJOR => Devmajor(value),
                AUDIT_DEVMINOR => Devminor(value),
                AUDIT_INODE => Inode(value),
                AUDIT_EXIT => Exit(value),
                AUDIT_SUCCESS => Success(value),
                AUDIT_PERM => Perm(value),
                AUDIT_FILETYPE => Filetype(value),
                AUDIT_OBJ_UID => ObjUid(value),
                AUDIT_OBJ_GID => ObjGid(value),
                AUDIT_FIELD_COMPARE => FieldCompare(value),
                AUDIT_EXE => Exe(value),
                AUDIT_ARG0 => Arg0(value),
                AUDIT_ARG1 => Arg1(value),
                AUDIT_ARG2 => Arg2(value),
                AUDIT_ARG3 => Arg3(value),
                _ => {
                    // For all the other fields, the value is a string
                    let str_end = offset + value as usize;
                    if str_end > self.buf().len() {
                        return Err(format!(
                            "failed to decode field. type={} (value should be a string?)",
                            field
                        )
                        .into());
                    }
                    let s: String = String::from_utf8_lossy(&self.buf()[offset..str_end]).into();
                    offset = str_end;
                    match field {
                        AUDIT_WATCH => Watch(s),
                        AUDIT_DIR => Dir(s),
                        AUDIT_FILTERKEY => Filterkey(s),
                        AUDIT_SUBJ_USER => SubjUser(s),
                        AUDIT_SUBJ_ROLE => SubjRole(s),
                        AUDIT_SUBJ_TYPE => SubjType(s),
                        AUDIT_SUBJ_SEN => SubjSen(s),
                        AUDIT_SUBJ_CLR => SubjClr(s),
                        AUDIT_OBJ_USER => ObjUser(s),
                        AUDIT_OBJ_ROLE => ObjRole(s),
                        AUDIT_OBJ_TYPE => ObjType(s),
                        AUDIT_OBJ_LEV_LOW => ObjLevLow(s),
                        AUDIT_OBJ_LEV_HIGH => ObjLevHigh(s),
                        _ => {
                            return Err(format!(
                                "failed to decode field (unknown type) type={}, value={}",
                                field, s
                            )
                            .into());
                        }
                    }
                }
            };
            rule.fields.push((field, flags));
        }
        Ok(rule)
    }
}

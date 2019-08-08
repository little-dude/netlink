use byteorder::{ByteOrder, NativeEndian};

use crate::{
    rules::{
        RuleAction, RuleBuffer, RuleField, RuleFieldFlags, RuleFlags, RuleSyscalls,
        AUDIT_MAX_FIELDS, RULE_BUF_MIN_LEN,
    },
    Emitable,
};

pub const AUDIT_PID: u32 = 0;
pub const AUDIT_UID: u32 = 1;
pub const AUDIT_EUID: u32 = 2;
pub const AUDIT_SUID: u32 = 3;
pub const AUDIT_FSUID: u32 = 4;
pub const AUDIT_GID: u32 = 5;
pub const AUDIT_EGID: u32 = 6;
pub const AUDIT_SGID: u32 = 7;
pub const AUDIT_FSGID: u32 = 8;
pub const AUDIT_LOGINUID: u32 = 9;
pub const AUDIT_PERS: u32 = 10;
pub const AUDIT_ARCH: u32 = 11;
pub const AUDIT_MSGTYPE: u32 = 12;
pub const AUDIT_SUBJ_USER: u32 = 13;
pub const AUDIT_SUBJ_ROLE: u32 = 14;
pub const AUDIT_SUBJ_TYPE: u32 = 15;
pub const AUDIT_SUBJ_SEN: u32 = 16;
pub const AUDIT_SUBJ_CLR: u32 = 17;
pub const AUDIT_PPID: u32 = 18;
pub const AUDIT_OBJ_USER: u32 = 19;
pub const AUDIT_OBJ_ROLE: u32 = 20;
pub const AUDIT_OBJ_TYPE: u32 = 21;
pub const AUDIT_OBJ_LEV_LOW: u32 = 22;
pub const AUDIT_OBJ_LEV_HIGH: u32 = 23;
pub const AUDIT_LOGINUID_SET: u32 = 24;
pub const AUDIT_SESSIONID: u32 = 25;
pub const AUDIT_FSTYPE: u32 = 26;
pub const AUDIT_DEVMAJOR: u32 = 100;
pub const AUDIT_DEVMINOR: u32 = 101;
pub const AUDIT_INODE: u32 = 102;
pub const AUDIT_EXIT: u32 = 103;
pub const AUDIT_SUCCESS: u32 = 104;
pub const AUDIT_WATCH: u32 = 105;
pub const AUDIT_PERM: u32 = 106;
pub const AUDIT_DIR: u32 = 107;
pub const AUDIT_FILETYPE: u32 = 108;
pub const AUDIT_OBJ_UID: u32 = 109;
pub const AUDIT_OBJ_GID: u32 = 110;
pub const AUDIT_FIELD_COMPARE: u32 = 111;
pub const AUDIT_EXE: u32 = 112;
pub const AUDIT_ARG0: u32 = 200;
pub const AUDIT_ARG1: u32 = 201;
pub const AUDIT_ARG2: u32 = 202;
pub const AUDIT_ARG3: u32 = 203;
pub const AUDIT_FILTERKEY: u32 = 210;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleMessage {
    pub flags: RuleFlags,
    pub action: RuleAction,
    pub fields: Vec<(RuleField, RuleFieldFlags)>,
    pub syscalls: RuleSyscalls,
}

impl Default for RuleMessage {
    fn default() -> Self {
        RuleMessage::new()
    }
}

impl RuleMessage {
    pub fn new() -> Self {
        RuleMessage {
            flags: RuleFlags::from(0),
            action: RuleAction::from(0),
            fields: Vec::with_capacity(AUDIT_MAX_FIELDS),
            syscalls: RuleSyscalls::new_zeroed(),
        }
    }

    #[rustfmt::skip]
    fn compute_string_values_length(&self) -> usize {
        use self::RuleField::*;
        let mut len = 0;
        for (field, _) in self.fields.iter() {
            match field {
                Watch(ref s)
                    | Dir(ref s)
                    | Filterkey(ref s)
                    | SubjUser(ref s)
                    | SubjRole(ref s)
                    | SubjType(ref s)
                    | SubjSen(ref s)
                    | SubjClr(ref s)
                    | ObjUser(ref s)
                    | ObjRole(ref s)
                    | ObjType(ref s)
                    | ObjLevLow(ref s)
                    | ObjLevHigh(ref s)
                    => len += s.len(),
                _ => {}
            }
        }
        len
    }
}

fn set_str_field<T>(rule_buffer: &mut RuleBuffer<T>, position: usize, buflen: &mut usize, s: &str)
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    // append the string to the strings buffer
    rule_buffer.buf_mut()[*buflen..*buflen + s.len()].copy_from_slice(s.as_bytes());
    // set the field's value to the string length
    rule_buffer.set_value(position, s.len() as u32);
    *buflen += s.len();
}

impl Emitable for RuleMessage {
    fn buffer_len(&self) -> usize {
        RULE_BUF_MIN_LEN + self.compute_string_values_length()
    }

    fn emit(&self, buffer: &mut [u8]) {
        use self::RuleField::*;
        let mut rule_buffer = RuleBuffer::new(buffer);

        rule_buffer.set_flags(self.flags.into());
        rule_buffer.set_action(self.action.into());
        rule_buffer.set_field_count(self.fields.len() as u32);
        {
            let syscalls = rule_buffer.syscalls_mut();
            for (i, word) in self.syscalls.0.iter().enumerate() {
                NativeEndian::write_u32(&mut syscalls[i * 4..i * 4 + 4], *word);
            }
        }
        rule_buffer.set_buflen(self.compute_string_values_length() as u32);

        let mut buflen = 0;

        for (i, (field, flags)) in self.fields.iter().enumerate() {
            rule_buffer.set_field_flags(i, (*flags).into());
            match field {
                Watch(ref s) => {
                    rule_buffer.set_field(i, AUDIT_WATCH);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                Dir(ref s) => {
                    rule_buffer.set_field(i, AUDIT_DIR);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                Filterkey(ref s) => {
                    rule_buffer.set_field(i, AUDIT_FILTERKEY);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                SubjUser(ref s) => {
                    rule_buffer.set_field(i, AUDIT_SUBJ_USER);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                SubjRole(ref s) => {
                    rule_buffer.set_field(i, AUDIT_SUBJ_ROLE);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                SubjType(ref s) => {
                    rule_buffer.set_field(i, AUDIT_SUBJ_TYPE);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                SubjSen(ref s) => {
                    rule_buffer.set_field(i, AUDIT_SUBJ_SEN);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                SubjClr(ref s) => {
                    rule_buffer.set_field(i, AUDIT_SUBJ_CLR);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                ObjUser(ref s) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_USER);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                ObjRole(ref s) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_ROLE);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                ObjType(ref s) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_TYPE);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                ObjLevLow(ref s) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_LEV_LOW);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                ObjLevHigh(ref s) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_LEV_HIGH);
                    set_str_field(&mut rule_buffer, i, &mut buflen, s);
                }
                Pid(val) => {
                    rule_buffer.set_field(i, AUDIT_PID);
                    rule_buffer.set_value(i, *val);
                }
                Uid(val) => {
                    rule_buffer.set_field(i, AUDIT_UID);
                    rule_buffer.set_value(i, *val);
                }
                Euid(val) => {
                    rule_buffer.set_field(i, AUDIT_EUID);
                    rule_buffer.set_value(i, *val);
                }
                Suid(val) => {
                    rule_buffer.set_field(i, AUDIT_SUID);
                    rule_buffer.set_value(i, *val);
                }
                Fsuid(val) => {
                    rule_buffer.set_field(i, AUDIT_FSUID);
                    rule_buffer.set_value(i, *val);
                }
                Gid(val) => {
                    rule_buffer.set_field(i, AUDIT_GID);
                    rule_buffer.set_value(i, *val);
                }
                Egid(val) => {
                    rule_buffer.set_field(i, AUDIT_EGID);
                    rule_buffer.set_value(i, *val);
                }
                Sgid(val) => {
                    rule_buffer.set_field(i, AUDIT_SGID);
                    rule_buffer.set_value(i, *val);
                }
                Fsgid(val) => {
                    rule_buffer.set_field(i, AUDIT_FSGID);
                    rule_buffer.set_value(i, *val);
                }
                Loginuid(val) => {
                    rule_buffer.set_field(i, AUDIT_LOGINUID);
                    rule_buffer.set_value(i, *val);
                }
                Pers(val) => {
                    rule_buffer.set_field(i, AUDIT_PERS);
                    rule_buffer.set_value(i, *val);
                }
                Arch(val) => {
                    rule_buffer.set_field(i, AUDIT_ARCH);
                    rule_buffer.set_value(i, *val);
                }
                Msgtype(val) => {
                    rule_buffer.set_field(i, AUDIT_MSGTYPE);
                    rule_buffer.set_value(i, *val);
                }
                Ppid(val) => {
                    rule_buffer.set_field(i, AUDIT_PPID);
                    rule_buffer.set_value(i, *val);
                }
                LoginuidSet(val) => {
                    rule_buffer.set_field(i, AUDIT_LOGINUID_SET);
                    rule_buffer.set_value(i, *val);
                }
                Sessionid(val) => {
                    rule_buffer.set_field(i, AUDIT_SESSIONID);
                    rule_buffer.set_value(i, *val);
                }
                Fstype(val) => {
                    rule_buffer.set_field(i, AUDIT_FSTYPE);
                    rule_buffer.set_value(i, *val);
                }
                Devmajor(val) => {
                    rule_buffer.set_field(i, AUDIT_DEVMAJOR);
                    rule_buffer.set_value(i, *val);
                }
                Devminor(val) => {
                    rule_buffer.set_field(i, AUDIT_DEVMINOR);
                    rule_buffer.set_value(i, *val);
                }
                Inode(val) => {
                    rule_buffer.set_field(i, AUDIT_INODE);
                    rule_buffer.set_value(i, *val);
                }
                Exit(val) => {
                    rule_buffer.set_field(i, AUDIT_EXIT);
                    rule_buffer.set_value(i, *val);
                }
                Success(val) => {
                    rule_buffer.set_field(i, AUDIT_SUCCESS);
                    rule_buffer.set_value(i, *val);
                }
                Perm(val) => {
                    rule_buffer.set_field(i, AUDIT_PERM);
                    rule_buffer.set_value(i, *val);
                }
                Filetype(val) => {
                    rule_buffer.set_field(i, AUDIT_FILETYPE);
                    rule_buffer.set_value(i, *val);
                }
                ObjUid(val) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_UID);
                    rule_buffer.set_value(i, *val);
                }
                ObjGid(val) => {
                    rule_buffer.set_field(i, AUDIT_OBJ_GID);
                    rule_buffer.set_value(i, *val);
                }
                FieldCompare(val) => {
                    rule_buffer.set_field(i, AUDIT_FIELD_COMPARE);
                    rule_buffer.set_value(i, *val);
                }
                Exe(val) => {
                    rule_buffer.set_field(i, AUDIT_EXE);
                    rule_buffer.set_value(i, *val);
                }
                Arg0(val) => {
                    rule_buffer.set_field(i, AUDIT_ARG0);
                    rule_buffer.set_value(i, *val);
                }
                Arg1(val) => {
                    rule_buffer.set_field(i, AUDIT_ARG1);
                    rule_buffer.set_value(i, *val);
                }
                Arg2(val) => {
                    rule_buffer.set_field(i, AUDIT_ARG2);
                    rule_buffer.set_value(i, *val);
                }
                Arg3(val) => {
                    rule_buffer.set_field(i, AUDIT_ARG3);
                    rule_buffer.set_value(i, *val);
                }
            }
        }
    }
}

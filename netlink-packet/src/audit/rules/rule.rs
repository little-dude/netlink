use bit_field::BitArray;
use {Emitable, RuleBuffer, RULE_BUF_MIN_LEN};

use constants::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleMessage {
    pub flags: RuleFlags,
    pub action: RuleAction,
    pub fields: Vec<(RuleField, RuleFieldFlags)>,
    pub mask: RuleMask,
}

impl RuleMessage {
    pub fn new() -> Self {
        RuleMessage {
            flags: RuleFlags::from(0),
            action: RuleAction::from(0),
            fields: Vec::with_capacity(AUDIT_MAX_FIELDS),
            mask: RuleMask::new_zeroed(),
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

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum RuleAction {
    Never,
    Possible,
    Always,
    Unknown(u32),
}

impl From<u32> for RuleAction {
    fn from(value: u32) -> Self {
        use self::RuleAction::*;
        match value {
            AUDIT_NEVER => Never,
            AUDIT_POSSIBLE => Possible,
            AUDIT_ALWAYS => Always,
            _ => Unknown(value),
        }
    }
}

impl From<RuleAction> for u32 {
    fn from(value: RuleAction) -> Self {
        use self::RuleAction::*;
        match value {
            Never => AUDIT_NEVER,
            Possible => AUDIT_POSSIBLE,
            Always => AUDIT_ALWAYS,
            Unknown(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RuleField {
    Pid(u32),
    Uid(u32),
    Euid(u32),
    Suid(u32),
    Fsuid(u32),
    Gid(u32),
    Egid(u32),
    Sgid(u32),
    Fsgid(u32),
    Loginuid(u32),
    Pers(u32),
    Arch(u32),
    Msgtype(u32),
    Ppid(u32),
    LoginuidSet(u32),
    Sessionid(u32),
    Fstype(u32),
    Devmajor(u32),
    Devminor(u32),
    Inode(u32),
    Exit(u32),
    Success(u32),
    Perm(u32),
    Filetype(u32),
    ObjUid(u32),
    ObjGid(u32),
    FieldCompare(u32),
    Exe(u32),
    Arg0(u32),
    Arg1(u32),
    Arg2(u32),
    Arg3(u32),
    Filterkey(u32),

    Watch(String),
    Dir(String),

    SubjUser(String),
    SubjRole(String),
    SubjType(String),
    SubjSen(String),
    SubjClr(String),

    ObjUser(String),
    ObjRole(String),
    ObjType(String),
    ObjLevLow(String),
    ObjLevHigh(String),
}

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum RuleFieldFlags {
    BitMask,
    BitTest,
    LessThan,
    GreaterThan,
    NotEqual,
    Equal,
    LessThanOrEqual,
    GreaterThanOrEqual,
    None,
    Unknown(u32),
}

impl From<u32> for RuleFieldFlags {
    fn from(value: u32) -> Self {
        use self::RuleFieldFlags::*;
        match value {
            AUDIT_BIT_MASK => BitMask,
            AUDIT_BIT_TEST => BitTest,
            AUDIT_LESS_THAN => LessThan,
            AUDIT_GREATER_THAN => GreaterThan,
            AUDIT_NOT_EQUAL => NotEqual,
            AUDIT_EQUAL => Equal,
            AUDIT_LESS_THAN_OR_EQUAL => LessThanOrEqual,
            AUDIT_GREATER_THAN_OR_EQUAL => GreaterThanOrEqual,
            0 => None,
            _ => Unknown(value),
        }
    }
}

impl From<RuleFieldFlags> for u32 {
    fn from(value: RuleFieldFlags) -> Self {
        use self::RuleFieldFlags::*;
        match value {
            BitMask => AUDIT_BIT_MASK,
            BitTest => AUDIT_BIT_TEST,
            LessThan => AUDIT_LESS_THAN,
            GreaterThan => AUDIT_GREATER_THAN,
            NotEqual => AUDIT_NOT_EQUAL,
            Equal => AUDIT_EQUAL,
            LessThanOrEqual => AUDIT_LESS_THAN_OR_EQUAL,
            GreaterThanOrEqual => AUDIT_GREATER_THAN_OR_EQUAL,
            None => 0,
            Unknown(value) => value,
        }
    }
}

const MASK_LEN: usize = 4 * AUDIT_BITMASK_SIZE;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RuleMask(pub(crate) Vec<u8>);

impl RuleMask {
    pub fn new_zeroed() -> Self {
        RuleMask(vec![0; MASK_LEN])
    }

    pub fn new_maxed() -> Self {
        RuleMask(vec![0xff; MASK_LEN])
    }

    pub fn unset_all(&mut self) -> &mut Self {
        self.0 = vec![0; MASK_LEN];
        self
    }

    pub fn set_all(&mut self) -> &mut Self {
        self.0 = vec![0xff; MASK_LEN];
        self
    }

    pub fn unset(&mut self, syscall: usize) -> &mut Self {
        self.0.set_bit(MASK_LEN - 1 - syscall, false);
        self
    }

    pub fn set(&mut self, syscall: usize) -> &mut Self {
        self.0.set_bit(MASK_LEN - 1 - syscall, true);
        self
    }

    pub fn has(&self, syscall: usize) -> bool {
        self.0.get_bit(MASK_LEN - 1 - syscall)
    }
}

#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum RuleFlags {
    FilterUser,
    FilterTask,
    FilterEntry,
    FilterWatch,
    FilterExit,
    FilterType,
    FilterFs,
    NrFilters,
    FilterPrepend,
    Unset,
    Unknown(u32),
}

impl From<u32> for RuleFlags {
    fn from(value: u32) -> Self {
        use self::RuleFlags::*;
        match value {
            AUDIT_FILTER_USER => FilterUser,
            AUDIT_FILTER_TASK => FilterTask,
            AUDIT_FILTER_ENTRY => FilterEntry,
            AUDIT_FILTER_WATCH => FilterWatch,
            AUDIT_FILTER_EXIT => FilterExit,
            AUDIT_FILTER_TYPE => FilterType,
            AUDIT_FILTER_FS => FilterFs,
            AUDIT_NR_FILTERS => NrFilters,
            AUDIT_FILTER_PREPEND => FilterPrepend,
            AUDIT_FILTER_UNSET => Unset,
            _ => Unknown(value),
        }
    }
}

impl From<RuleFlags> for u32 {
    fn from(value: RuleFlags) -> Self {
        use self::RuleFlags::*;
        match value {
            FilterUser => AUDIT_FILTER_USER,
            FilterTask => AUDIT_FILTER_TASK,
            FilterEntry => AUDIT_FILTER_ENTRY,
            FilterWatch => AUDIT_FILTER_WATCH,
            FilterExit => AUDIT_FILTER_EXIT,
            FilterType => AUDIT_FILTER_TYPE,
            FilterFs => AUDIT_FILTER_FS,
            NrFilters => AUDIT_NR_FILTERS,
            FilterPrepend => AUDIT_FILTER_PREPEND,
            Unset => AUDIT_FILTER_UNSET,
            Unknown(value) => value,
        }
    }
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
        rule_buffer
            .mask_mut()
            .copy_from_slice(self.mask.0.as_slice());
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
                Filterkey(val) => {
                    rule_buffer.set_field(i, AUDIT_FILTERKEY);
                    rule_buffer.set_value(i, *val);
                }
            }
        }
    }
}

fn set_str_field<T>(rule_buffer: &mut RuleBuffer<T>, position: usize, buflen: &mut usize, s: &str)
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    // append the string to the strings buffer
    &mut rule_buffer.buf_mut()[*buflen..*buflen + s.len()].copy_from_slice(s.as_bytes());
    // set the field's value to the string length
    rule_buffer.set_value(position, s.len() as u32);
    *buflen = *buflen + s.len();
}

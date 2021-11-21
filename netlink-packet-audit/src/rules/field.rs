// SPDX-License-Identifier: MIT

use crate::constants::*;

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

    Watch(String),
    Dir(String),
    Filterkey(String),

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

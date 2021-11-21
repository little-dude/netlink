// SPDX-License-Identifier: MIT

use crate::constants::*;

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

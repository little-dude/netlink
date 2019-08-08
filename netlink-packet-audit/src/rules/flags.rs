/// Apply rule to user-generated messages
pub const AUDIT_FILTER_USER: u32 = 0;
/// Apply rule at task creation (not syscall)
pub const AUDIT_FILTER_TASK: u32 = 1;
/// Apply rule at syscall entry
pub const AUDIT_FILTER_ENTRY: u32 = 2;
/// Apply rule to file system watches
pub const AUDIT_FILTER_WATCH: u32 = 3;
/// Apply rule at syscall exit
pub const AUDIT_FILTER_EXIT: u32 = 4;
/// Apply rule at audit_log_start
pub const AUDIT_FILTER_TYPE: u32 = 5;
pub const AUDIT_FILTER_FS: u32 = 6;
/// Mask to get actual filter
pub const AUDIT_NR_FILTERS: u32 = 7;
pub const AUDIT_FILTER_PREPEND: u32 = 16;
/// Filter is unset
pub const AUDIT_FILTER_UNSET: u32 = 128;

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

// ==========================================
// 1000 - 1099 are for commanding the audit system
// ==========================================
/// Get status
pub const AUDIT_GET: u16 = 1000;
/// Set status (enable/disable/auditd)
pub const AUDIT_SET: u16 = 1001;
/// List syscall rules -- deprecated
pub const AUDIT_LIST: u16 = 1002;
/// Add syscall rule -- deprecated
pub const AUDIT_ADD: u16 = 1003;
/// Delete syscall rule -- deprecated
pub const AUDIT_DEL: u16 = 1004;
/// Message from userspace -- deprecated
pub const AUDIT_USER: u16 = 1005;
/// Define the login id and information
pub const AUDIT_LOGIN: u16 = 1006;
/// Insert file/dir watch entry
pub const AUDIT_WATCH_INS: u16 = 1007;
/// Remove file/dir watch entry
pub const AUDIT_WATCH_REM: u16 = 1008;
/// List all file/dir watches
pub const AUDIT_WATCH_LIST: u16 = 1009;
/// Get info about sender of signal to auditd
pub const AUDIT_SIGNAL_INFO: u16 = 1010;
/// Add syscall filtering rule
pub const AUDIT_ADD_RULE: u16 = 1011;
/// Delete syscall filtering rule
pub const AUDIT_DEL_RULE: u16 = 1012;
/// List syscall filtering rules
pub const AUDIT_LIST_RULES: u16 = 1013;
/// Trim junk from watched tree
pub const AUDIT_TRIM: u16 = 1014;
/// Append to watched tree
pub const AUDIT_MAKE_EQUIV: u16 = 1015;
/// Get TTY auditing status
pub const AUDIT_TTY_GET: u16 = 1016;
/// Set TTY auditing status
pub const AUDIT_TTY_SET: u16 = 1017;
/// Turn an audit feature on or off
pub const AUDIT_SET_FEATURE: u16 = 1018;
/// Get which features are enabled
pub const AUDIT_GET_FEATURE: u16 = 1019;

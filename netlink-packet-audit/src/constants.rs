pub use netlink_packet_core::constants::*;

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

// ==========================================
// 1100 - 1199 user space trusted application messages
// ==========================================

/// Userspace messages mostly uninteresting to kernel
pub const AUDIT_FIRST_USER_MSG: u16 = 1100;
/// We filter this differently
pub const AUDIT_USER_AVC: u16 = 1107;
/// Non-ICANON TTY input meaning
pub const AUDIT_USER_TTY: u16 = 1124;
pub const AUDIT_LAST_USER_MSG: u16 = 1199;

/// More user space messages;
pub const AUDIT_FIRST_USER_MSG2: u16 = 2100;
pub const AUDIT_LAST_USER_MSG2: u16 = 2999;

// ==========================================
// 1200 - 1299 messages internal to the audit daemon
// ==========================================

/// Daemon startup record
pub const AUDIT_DAEMON_START: u16 = 1200;
/// Daemon normal stop record
pub const AUDIT_DAEMON_END: u16 = 1201;
/// Daemon error stop record
pub const AUDIT_DAEMON_ABORT: u16 = 1202;
/// Daemon config change
pub const AUDIT_DAEMON_CONFIG: u16 = 1203;

// ==========================================
// 1300 - 1399 audit event messages
// ==========================================

pub const AUDIT_EVENT_MESSAGE_MIN: u16 = 1300;
pub const AUDIT_EVENT_MESSAGE_MAX: u16 = 1399;
/// Syscall event
pub const AUDIT_SYSCALL: u16 = 1300;
/// Filename path information
pub const AUDIT_PATH: u16 = 1302;
/// IPC record
pub const AUDIT_IPC: u16 = 1303;
/// sys_socketcall arguments
pub const AUDIT_SOCKETCALL: u16 = 1304;
/// Audit system configuration change
pub const AUDIT_CONFIG_CHANGE: u16 = 1305;
/// sockaddr copied as syscall arg
pub const AUDIT_SOCKADDR: u16 = 1306;
/// Current working directory
pub const AUDIT_CWD: u16 = 1307;
/// execve arguments
pub const AUDIT_EXECVE: u16 = 1309;
/// IPC new permissions record type
pub const AUDIT_IPC_SET_PERM: u16 = 1311;
/// POSIX MQ open record type
pub const AUDIT_MQ_OPEN: u16 = 1312;
/// POSIX MQ send/receive record type
pub const AUDIT_MQ_SENDRECV: u16 = 1313;
/// POSIX MQ notify record type
pub const AUDIT_MQ_NOTIFY: u16 = 1314;
/// POSIX MQ get/set attribute record type
pub const AUDIT_MQ_GETSETATTR: u16 = 1315;
/// For use by 3rd party modules
pub const AUDIT_KERNEL_OTHER: u16 = 1316;
/// audit record for pipe/socketpair
pub const AUDIT_FD_PAIR: u16 = 1317;
/// ptrace target
pub const AUDIT_OBJ_PID: u16 = 1318;
/// Input on an administrative TTY
pub const AUDIT_TTY: u16 = 1319;
/// End of multi-record event
pub const AUDIT_EOE: u16 = 1320;
/// Information about fcaps increasing perms
pub const AUDIT_BPRM_FCAPS: u16 = 1321;
/// Record showing argument to sys_capset
pub const AUDIT_CAPSET: u16 = 1322;
/// Record showing descriptor and flags in mmap
pub const AUDIT_MMAP: u16 = 1323;
/// Packets traversing netfilter chains
pub const AUDIT_NETFILTER_PKT: u16 = 1324;
/// Netfilter chain modifications
pub const AUDIT_NETFILTER_CFG: u16 = 1325;
/// Secure Computing event
pub const AUDIT_SECCOMP: u16 = 1326;
/// Proctitle emit event
pub const AUDIT_PROCTITLE: u16 = 1327;
/// audit log listing feature changes
pub const AUDIT_FEATURE_CHANGE: u16 = 1328;
/// Replace auditd if this packet unanswerd
pub const AUDIT_REPLACE: u16 = 1329;
/// Kernel Module events
pub const AUDIT_KERN_MODULE: u16 = 1330;
/// Fanotify access decision
pub const AUDIT_FANOTIFY: u16 = 1331;

// ==========================================
// 1400 - 1499 SE Linux use
// ==========================================

/// SE Linux avc denial or grant
pub const AUDIT_AVC: u16 = 1400;
/// Internal SE Linux Errors
pub const AUDIT_SELINUX_ERR: u16 = 1401;
/// dentry, vfsmount pair from avc
pub const AUDIT_AVC_PATH: u16 = 1402;
/// Policy file load
pub const AUDIT_MAC_POLICY_LOAD: u16 = 1403;
/// Changed enforcing,permissive,off
pub const AUDIT_MAC_STATUS: u16 = 1404;
/// Changes to booleans
pub const AUDIT_MAC_CONFIG_CHANGE: u16 = 1405;
/// NetLabel: allow unlabeled traffic
pub const AUDIT_MAC_UNLBL_ALLOW: u16 = 1406;
/// NetLabel: add CIPSOv4 DOI entry
pub const AUDIT_MAC_CIPSOV4_ADD: u16 = 1407;
/// NetLabel: del CIPSOv4 DOI entry
pub const AUDIT_MAC_CIPSOV4_DEL: u16 = 1408;
/// NetLabel: add LSM domain mapping
pub const AUDIT_MAC_MAP_ADD: u16 = 1409;
/// NetLabel: del LSM domain mapping
pub const AUDIT_MAC_MAP_DEL: u16 = 1410;
/// Not used
pub const AUDIT_MAC_IPSEC_ADDSA: u16 = 1411;
/// Not used
pub const AUDIT_MAC_IPSEC_DELSA: u16 = 1412;
/// Not used
pub const AUDIT_MAC_IPSEC_ADDSPD: u16 = 1413;
/// Not used
pub const AUDIT_MAC_IPSEC_DELSPD: u16 = 1414;
/// Audit an IPSec event
pub const AUDIT_MAC_IPSEC_EVENT: u16 = 1415;
/// NetLabel: add a static label
pub const AUDIT_MAC_UNLBL_STCADD: u16 = 1416;
/// NetLabel: del a static label
pub const AUDIT_MAC_UNLBL_STCDEL: u16 = 1417;
/// NetLabel: add CALIPSO DOI entry
pub const AUDIT_MAC_CALIPSO_ADD: u16 = 1418;
/// NetLabel: del CALIPSO DOI entry
pub const AUDIT_MAC_CALIPSO_DEL: u16 = 1419;

// ==========================================
// 1700 - 1799 kernel anomaly records
// ==========================================

pub const AUDIT_FIRST_KERN_ANOM_MSG: u16 = 1700;
pub const AUDIT_LAST_KERN_ANOM_MSG: u16 = 1799;
/// Device changed promiscuous mode
pub const AUDIT_ANOM_PROMISCUOUS: u16 = 1700;
/// Process ended abnormally
pub const AUDIT_ANOM_ABEND: u16 = 1701;
/// Suspicious use of file links
pub const AUDIT_ANOM_LINK: u16 = 1702;

// ==========================================
// 1800 - 1899 kernel integrity events
// ==========================================

/// Data integrity verification
pub const AUDIT_INTEGRITY_DATA: u16 = 1800;
/// Metadata integrity verification
pub const AUDIT_INTEGRITY_METADATA: u16 = 1801;
/// Integrity enable status
pub const AUDIT_INTEGRITY_STATUS: u16 = 1802;
/// Integrity HASH type
pub const AUDIT_INTEGRITY_HASH: u16 = 1803;
/// PCR invalidation msgs
pub const AUDIT_INTEGRITY_PCR: u16 = 1804;
/// policy rule
pub const AUDIT_INTEGRITY_RULE: u16 = 1805;

// 2000 is for otherwise unclassified kernel audit messages (legacy)
pub const AUDIT_KERNEL: u16 = 2000;

// rule flags

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

// Rule actions

/// Do not build context if rule matches
pub const AUDIT_NEVER: u32 = 0;
/// Build context if rule matches
pub const AUDIT_POSSIBLE: u32 = 1;
/// Generate audit record if rule matches
pub const AUDIT_ALWAYS: u32 = 2;

pub const AUDIT_MAX_FIELDS: usize = 64;
pub const AUDIT_MAX_KEY_LEN: usize = 256;
pub const AUDIT_BITMASK_SIZE: usize = 64;

pub const AUDIT_SYSCALL_CLASSES: u32 = 16;
pub const AUDIT_CLASS_DIR_WRITE: u32 = 0;
pub const AUDIT_CLASS_DIR_WRITE_32: u32 = 1;
pub const AUDIT_CLASS_CHATTR: u32 = 2;
pub const AUDIT_CLASS_CHATTR_32: u32 = 3;
pub const AUDIT_CLASS_READ: u32 = 4;
pub const AUDIT_CLASS_READ_32: u32 = 5;
pub const AUDIT_CLASS_WRITE: u32 = 6;
pub const AUDIT_CLASS_WRITE_32: u32 = 7;
pub const AUDIT_CLASS_SIGNAL: u32 = 8;
pub const AUDIT_CLASS_SIGNAL_32: u32 = 9;
pub const AUDIT_UNUSED_BITS: u32 = 134216704;

// Field Comparing Constants
pub const AUDIT_COMPARE_UID_TO_OBJ_UID: u32 = 1;
pub const AUDIT_COMPARE_GID_TO_OBJ_GID: u32 = 2;
pub const AUDIT_COMPARE_EUID_TO_OBJ_UID: u32 = 3;
pub const AUDIT_COMPARE_EGID_TO_OBJ_GID: u32 = 4;
pub const AUDIT_COMPARE_AUID_TO_OBJ_UID: u32 = 5;
pub const AUDIT_COMPARE_SUID_TO_OBJ_UID: u32 = 6;
pub const AUDIT_COMPARE_SGID_TO_OBJ_GID: u32 = 7;
pub const AUDIT_COMPARE_FSUID_TO_OBJ_UID: u32 = 8;
pub const AUDIT_COMPARE_FSGID_TO_OBJ_GID: u32 = 9;
pub const AUDIT_COMPARE_UID_TO_AUID: u32 = 10;
pub const AUDIT_COMPARE_UID_TO_EUID: u32 = 11;
pub const AUDIT_COMPARE_UID_TO_FSUID: u32 = 12;
pub const AUDIT_COMPARE_UID_TO_SUID: u32 = 13;
pub const AUDIT_COMPARE_AUID_TO_FSUID: u32 = 14;
pub const AUDIT_COMPARE_AUID_TO_SUID: u32 = 15;
pub const AUDIT_COMPARE_AUID_TO_EUID: u32 = 16;
pub const AUDIT_COMPARE_EUID_TO_SUID: u32 = 17;
pub const AUDIT_COMPARE_EUID_TO_FSUID: u32 = 18;
pub const AUDIT_COMPARE_SUID_TO_FSUID: u32 = 19;
pub const AUDIT_COMPARE_GID_TO_EGID: u32 = 20;
pub const AUDIT_COMPARE_GID_TO_FSGID: u32 = 21;
pub const AUDIT_COMPARE_GID_TO_SGID: u32 = 22;
pub const AUDIT_COMPARE_EGID_TO_FSGID: u32 = 23;
pub const AUDIT_COMPARE_EGID_TO_SGID: u32 = 24;
pub const AUDIT_COMPARE_SGID_TO_FSGID: u32 = 25;
pub const AUDIT_MAX_FIELD_COMPARE: u32 = 25;

// =======================================================================
// rule fields
// =======================================================================
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

pub const AUDIT_BIT_MASK: u32 = 0x0800_0000;
pub const AUDIT_LESS_THAN: u32 = 0x1000_0000;
pub const AUDIT_GREATER_THAN: u32 = 0x2000_0000;
pub const AUDIT_NOT_EQUAL: u32 = 0x3000_0000;
pub const AUDIT_EQUAL: u32 = 0x4000_0000;
pub const AUDIT_BIT_TEST: u32 = AUDIT_BIT_MASK | AUDIT_EQUAL;
pub const AUDIT_LESS_THAN_OR_EQUAL: u32 = AUDIT_LESS_THAN | AUDIT_EQUAL;
pub const AUDIT_GREATER_THAN_OR_EQUAL: u32 = AUDIT_GREATER_THAN | AUDIT_EQUAL;
pub const AUDIT_OPERATORS: u32 = AUDIT_EQUAL | AUDIT_NOT_EQUAL | AUDIT_BIT_MASK;

// ============================================
// failure to log actions
// ============================================
pub const AUDIT_FAIL_SILENT: u32 = 0;
pub const AUDIT_FAIL_PRINTK: u32 = 1;
pub const AUDIT_FAIL_PANIC: u32 = 2;

pub const AUDIT_PERM_EXEC: u32 = 1;
pub const AUDIT_PERM_WRITE: u32 = 2;
pub const AUDIT_PERM_READ: u32 = 4;
pub const AUDIT_PERM_ATTR: u32 = 8;
pub const AUDIT_MESSAGE_TEXT_MAX: u32 = 8560;
pub const AUDIT_FEATURE_VERSION: u32 = 1;
pub const AUDIT_FEATURE_ONLY_UNSET_LOGINUID: u32 = 0;
pub const AUDIT_FEATURE_LOGINUID_IMMUTABLE: u32 = 1;
pub const AUDIT_LAST_FEATURE: u32 = 1;

/// Unused multicast group for audit
pub const AUDIT_NLGRP_NONE: u32 = 0;
/// Multicast group to listen for audit events
pub const AUDIT_NLGRP_READLOG: u32 = 1;

pub const __AUDIT_ARCH_CONVENTION_MASK: u32 = 0x3000_0000;
pub const __AUDIT_ARCH_CONVENTION_MIPS64_N32: u32 = 0x2000_0000;
pub const __AUDIT_ARCH_64BIT: u32 = 0x0800_0000;
pub const __AUDIT_ARCH_LE: u32 = 0x4000_0000;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
pub const AUDIT_ARCH_ALPHA: u32 = 0xC000_9026;
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
pub const AUDIT_ARCH_ARMEB: u32 = 0x28;
pub const AUDIT_ARCH_CRIS: u32 = 0x4000_004C;
pub const AUDIT_ARCH_FRV: u32 = 0x5441;
pub const AUDIT_ARCH_I386: u32 = 0x4000_0003;
pub const AUDIT_ARCH_IA64: u32 = 0xC000_0032;
pub const AUDIT_ARCH_M32R: u32 = 0x58;
pub const AUDIT_ARCH_M68K: u32 = 0x04;
pub const AUDIT_ARCH_MICROBLAZE: u32 = 0xBD;
pub const AUDIT_ARCH_MIPS: u32 = 0x08;
pub const AUDIT_ARCH_MIPSEL: u32 = 0x4000_0008;
pub const AUDIT_ARCH_MIPS64: u32 = 0x8000_0008;
pub const AUDIT_ARCH_MIPS64N32: u32 = 0xA000_0008;
pub const AUDIT_ARCH_MIPSEL64: u32 = 0xC000_0008;
pub const AUDIT_ARCH_MIPSEL64N32: u32 = 0xE000_0008;
pub const AUDIT_ARCH_OPENRISC: u32 = 92;
pub const AUDIT_ARCH_PARISC: u32 = 15;
pub const AUDIT_ARCH_PARISC64: u32 = 0x8000_000F;
pub const AUDIT_ARCH_PPC: u32 = 20;
pub const AUDIT_ARCH_PPC64: u32 = 0x8000_0015;
pub const AUDIT_ARCH_PPC64LE: u32 = 0xC000_0015;
pub const AUDIT_ARCH_S390: u32 = 22;
pub const AUDIT_ARCH_S390X: u32 = 0x8000_0016;
pub const AUDIT_ARCH_SH: u32 = 42;
pub const AUDIT_ARCH_SHEL: u32 = 0x4000_002A;
pub const AUDIT_ARCH_SH64: u32 = 0x8000_002A;
pub const AUDIT_ARCH_SHEL64: u32 = 0xC000_002A;
pub const AUDIT_ARCH_SPARC: u32 = 2;
pub const AUDIT_ARCH_SPARC64: u32 = 0x8000_002B;
pub const AUDIT_ARCH_TILEGX: u32 = 0xC000_00BF;
pub const AUDIT_ARCH_TILEGX32: u32 = 0x4000_00BF;
pub const AUDIT_ARCH_TILEPRO: u32 = 0x4000_00BC;
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

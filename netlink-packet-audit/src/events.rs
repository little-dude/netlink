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

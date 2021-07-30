pub const WG_KEY_LEN: usize = 32;

pub const WG_CMD_GET_DEVICE: u8 = 0;
pub const WG_CMD_SET_DEVICE: u8 = 1;

pub const WGDEVICE_F_REPLACE_PEERS: u32 = 1 << 0;

pub const WGDEVICE_A_UNSPEC: u16 = 0;
pub const WGDEVICE_A_IFINDEX: u16 = 1;
pub const WGDEVICE_A_IFNAME: u16 = 2;
pub const WGDEVICE_A_PRIVATE_KEY: u16 = 3;
pub const WGDEVICE_A_PUBLIC_KEY: u16 = 4;
pub const WGDEVICE_A_FLAGS: u16 = 5;
pub const WGDEVICE_A_LISTEN_PORT: u16 = 6;
pub const WGDEVICE_A_FWMARK: u16 = 7;
pub const WGDEVICE_A_PEERS: u16 = 8;

pub const WGPEER_F_REMOVE_ME: u32 = 1 << 0;
pub const WGPEER_F_REPLACE_ALLOWEDIPS: u32 = 1 << 1;
pub const WGPEER_F_UPDATE_ONLY: u32 = 1 << 2;

pub const WGPEER_A_UNSPEC: u16 = 0;
pub const WGPEER_A_PUBLIC_KEY: u16 = 1;
pub const WGPEER_A_PRESHARED_KEY: u16 = 2;
pub const WGPEER_A_FLAGS: u16 = 3;
pub const WGPEER_A_ENDPOINT: u16 = 4;
pub const WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL: u16 = 5;
pub const WGPEER_A_LAST_HANDSHAKE_TIME: u16 = 6;
pub const WGPEER_A_RX_BYTES: u16 = 7;
pub const WGPEER_A_TX_BYTES: u16 = 8;
pub const WGPEER_A_ALLOWEDIPS: u16 = 9;
pub const WGPEER_A_PROTOCOL_VERSION: u16 = 10;

pub const WGALLOWEDIP_A_UNSPEC: u16 = 0;
pub const WGALLOWEDIP_A_FAMILY: u16 = 1;
pub const WGALLOWEDIP_A_IPADDR: u16 = 2;
pub const WGALLOWEDIP_A_CIDR_MASK: u16 = 3;

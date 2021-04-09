use netlink_packet_utils::{
    buffer,
    buffer_check_length,
    buffer_common,
    fields,
    getter,
    setter,
    DecodeError,
};

pub(crate) const GENL_HEADER_LEN: usize = 4;
pub const GENL_ID_CTRL: u16 = 0x10;

buffer!(GenericNetlinkMessageBuffer(GENL_HEADER_LEN) {
    cmd: (u8, 0),
    version: (u8, 1),
    reserve_1: (u8, 2),
    payload: (slice, GENL_HEADER_LEN..),
});

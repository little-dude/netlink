use super::{field, Error, Flags, Repr, Result};
use byteorder::{ByteOrder, NativeEndian};

pub enum Message<'a> {
    Link(LinkMessage),
    Other(&'a [u8]),
}

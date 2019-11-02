#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Message {
    InetRequest(inet::Request),
    InetResponse(inet::Response),
    UnixRequest(unix::Request),
    UnixResponse(unix::Response),
}

impl Emitable for Message {
    fn buffer_len(&self) -> usize {
        use Message::*;

        match self {
            InetRequest(ref msg) => msg.buffer_len(),
            InetResponse(ref msg) => msg.buffer_len(),
            UnixRequest(ref msg) => msg.buffer_len(),
            UnixResponse(ref msg) => msg.buffer_len(),
        }
    }

    fn emit(&self, buf: &mut [u8]) {
        use Message::*;

        match self {
            InetRequest(ref msg) => msg.emit(),
            InetResponse(ref msg) => msg.emit(),
            UnixRequest(ref msg) => msg.emit(),
            UnixResponse(ref msg) => msg.emit(),
        }
    }
}

buffer!(MessageBuffer(1) {
    family: (u8, 0),
});

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MessageBuffer<&'a T>> for Message {
    fn parse_with_param(
        message_type: u16,
        buf: &MessageBuffer<&'a T>,
    ) -> Result<Self, DecodeError> {
        unimplemented!()
    }
}

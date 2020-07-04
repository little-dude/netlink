use futures::{
    future::{self, Either},
    stream::{StreamExt, TryStream},
    FutureExt,
};

use crate::{
    packet::{NetlinkMessage, NetlinkPayload, RtnlMessage, TcMessage, NLM_F_DUMP, NLM_F_REQUEST},
    Error, Handle,
};

pub struct QDiscGetRequest {
    handle: Handle,
    message: TcMessage,
}

impl QDiscGetRequest {
    pub(crate) fn new(handle: Handle) -> Self {
        QDiscGetRequest {
            handle,
            message: TcMessage::default(),
        }
    }

    /// Execute the request
    pub fn execute(self) -> impl TryStream<Ok = TcMessage, Error = Error> {
        let QDiscGetRequest {
            mut handle,
            message,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::GetQueueDiscipline(message));
        req.header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        match handle.request(req) {
            Ok(response) => Either::Left(response.map(move |msg| {
                let (header, payload) = msg.into_parts();
                match payload {
                    // The kernel use RTM_NEWQDISC for returned message
                    NetlinkPayload::InnerMessage(RtnlMessage::NewQueueDiscipline(msg)) => Ok(msg),
                    NetlinkPayload::Error(err) => Err(Error::NetlinkError(err)),
                    _ => Err(Error::UnexpectedMessage(NetlinkMessage::new(
                        header, payload,
                    ))),
                }
            })),
            Err(e) => Either::Right(future::err::<TcMessage, Error>(e).into_stream()),
        }
    }
}

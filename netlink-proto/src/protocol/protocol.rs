use std::{
    collections::{HashMap, VecDeque},
    fmt::Debug,
};

use netlink_packet_core::{
    constants::*, NetlinkDeserializable, NetlinkMessage, NetlinkPayload, NetlinkSerializable,
};
use netlink_sys::SocketAddr;

use super::Request;

#[derive(Debug, Eq, PartialEq, Hash)]
struct RequestId {
    sequence_number: u32,
    port: u32
}

impl RequestId {
    fn new(sequence_number: u32, sock: SocketAddr) -> Self {
        RequestId {
            sequence_number,
            port: sock.port_number(),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Response<T, M>
where
    T: Debug + Clone + PartialEq + Eq + NetlinkSerializable<T> + NetlinkDeserializable<T>,
    M: Debug,
{
    pub done: bool,
    pub message: NetlinkMessage<T>,
    pub metadata: M,
}

#[derive(Debug, Default)]
pub struct Protocol<T, M>
where
    T: Debug + Clone + PartialEq + Eq + NetlinkSerializable<T> + NetlinkDeserializable<T>,
    M: Debug,
{
    /// Counter that is incremented for each message sent
    sequence_id: u32,

    /// Requests for which we're awaiting a response. Metadata are
    /// associated with each request.
    pending_requests: HashMap<RequestId, M>,

    /// Responses to pending requests
    pub incoming_responses: VecDeque<Response<T, M>>,

    /// Requests from remote peers
    pub incoming_requests: VecDeque<(NetlinkMessage<T>, SocketAddr)>,

    /// The messages to be sent out
    pub outgoing_messages: VecDeque<(NetlinkMessage<T>, SocketAddr)>,
}

impl<T, M> Protocol<T, M>
where
    T: Debug + Clone + PartialEq + Eq + NetlinkSerializable<T> + NetlinkDeserializable<T>,
    M: Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            sequence_id: 0,
            pending_requests: HashMap::new(),
            incoming_responses: VecDeque::new(),
            incoming_requests: VecDeque::new(),
            outgoing_messages: VecDeque::new(),
        }
    }

    pub fn handle_message(&mut self, message: NetlinkMessage<T>, source: SocketAddr) {
        let request_id = RequestId::new(message.header.sequence_number, source);
        debug!("handling messages (request id = {:?})", request_id);
        if self.pending_requests.get(&request_id).is_some() {
            self.handle_response(request_id, message);
        } else {
            self.incoming_requests.push_back((message, source));
        }
    }

    fn handle_response(&mut self, request_id: RequestId, message: NetlinkMessage<T>) {
        // A request is processed if we receive an Ack, Error,
        // Done, Overrun, or InnerMessage without the
        // multipart flag
        debug!("handling response to request {:?}", request_id);
        let mut done = true;
        if let NetlinkPayload::InnerMessage(_) = message.payload {
            if message.header.flags & NLM_F_MULTIPART == NLM_F_MULTIPART {
                done = false;
            }
        }

        let metadata = if done {
            trace!("request {:?} fully processed", request_id);
            self.pending_requests.remove(&request_id).unwrap()
        } else {
            trace!("more responses to request {:?} may come", request_id);
            self.pending_requests.get(&request_id).unwrap().clone()
        };

        let response = Response::<T, M> {
            message,
            done,
            metadata,
        };
        self.incoming_responses.push_back(response);
        debug!("done handling response to request {:?}", request_id);
    }

    pub fn request(&mut self, request: Request<T, M>) {
        let Request {
            mut message,
            metadata,
            destination,
        } = request;

        self.set_sequence_id(&mut message);
        let request_id = RequestId::new(self.sequence_id, destination);
        let flags = message.header.flags;
        self.outgoing_messages.push_back((message, destination));

        // If we expect a response, we store the request id so that we
        // can map the response to this specific request.
        //
        // Note that we expect responses in three cases only:
        //  - when the request has the NLM_F_REQUEST flag
        //  - when the request has the NLM_F_ACK flag
        //  - when the request has the NLM_F_ECHO flag
        if flags & NLM_F_REQUEST == NLM_F_REQUEST
            || flags & NLM_F_ACK == NLM_F_ACK
            || flags & NLM_F_ECHO == NLM_F_ECHO
        {
            self.pending_requests.insert(request_id, metadata);
        }
    }

    fn set_sequence_id(&mut self, message: &mut NetlinkMessage<T>) {
        self.sequence_id += 1;
        message.header.sequence_number = self.sequence_id;
    }
}

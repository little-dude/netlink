use futures::{self, FutureExt, Stream, StreamExt};

use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NLM_F_REQUEST};
use netlink_proto::{sys::SocketAddr, ConnectionHandle};

use crate::{
    try_genl,
    CtrlAttr,
    GenericNetlinkAttr,
    GenericNetlinkError,
    GenericNetlinkHeader,
    GenericNetlinkMessage,
    GENL_ID_CTRL,
};

#[derive(Clone, Debug)]
pub struct GenericNetlinkHandle(ConnectionHandle<GenericNetlinkMessage>);

const CTRL_CMD_GETFAMILY: u8 = 3;
// libnl is using hardcoded number 1 and kernel does not verify the version
const CTRL_CMD_GETFAMILY_VERSION: u8 = 1;

impl GenericNetlinkHandle {
    pub(crate) fn new(conn: ConnectionHandle<GenericNetlinkMessage>) -> Self {
        GenericNetlinkHandle(conn)
    }

    pub async fn resolve_family_name(
        &mut self,
        family_name: &str,
    ) -> Result<u16, GenericNetlinkError> {
        let nl_msg = NetlinkMessage {
            header: NetlinkHeader {
                message_type: GENL_ID_CTRL,
                flags: NLM_F_REQUEST,
                sequence_number: 0,
                port_number: 0,
                ..Default::default()
            },
            payload: GenericNetlinkMessage {
                message_type: GENL_ID_CTRL,
                header: GenericNetlinkHeader {
                    cmd: CTRL_CMD_GETFAMILY,
                    version: CTRL_CMD_GETFAMILY_VERSION,
                },
                nlas: GenericNetlinkAttr::Ctrl(vec![CtrlAttr::FamilyName(family_name.into())]),
            }
            .into(),
        };

        let mut response = match self.0.request(nl_msg, SocketAddr::new(0, 0)) {
            Ok(response) => {
                futures::future::Either::Left(response.map(move |msg| Ok(try_genl!(msg))))
            }
            Err(e) => futures::future::Either::Right(
                futures::future::err::<GenericNetlinkMessage, GenericNetlinkError>(
                    GenericNetlinkError::RequestFailed(format!("{}", e)),
                )
                .into_stream(),
            ),
        };

        match response.next().await {
            Some(Ok(genl_msg)) => {
                match &genl_msg.nlas {
                    GenericNetlinkAttr::Ctrl(nlas) => {
                        for nla in nlas {
                            if let CtrlAttr::FamilyId(family_id) = nla {
                                return Ok(*family_id);
                            }
                        }
                    }
                    _ => {
                        return Err(GenericNetlinkError::RequestFailed(format!(
                            "The NLA reply is not GenericNetlinkAttr::Ctrl: {:?}",
                            &genl_msg
                        )));
                    }
                };
                Err(GenericNetlinkError::RequestFailed(format!(
                    "The NLA reply is not GenericNetlinkAttr::Ctrl: {:?}",
                    &genl_msg
                )))
            }
            Some(Err(e)) => Err(e),
            None => Err(GenericNetlinkError::RequestFailed(
                "No reply got for CTRL_CMD_GETFAMILY".into(),
            )),
        }
    }

    pub fn request(
        &mut self,
        message: NetlinkMessage<GenericNetlinkMessage>,
    ) -> Result<impl Stream<Item = NetlinkMessage<GenericNetlinkMessage>>, GenericNetlinkError>
    {
        self.0.request(message, SocketAddr::new(0, 0)).map_err(|_| {
            GenericNetlinkError::RequestFailed("Failed to send netlink request".into())
        })
    }
}

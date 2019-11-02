use byteorder::{ByteOrder, NativeEndian};
use failure::ResultExt;

pub use crate::utils::nla::{DefaultNla, NlaBuffer, NlasIterator};

use crate::{
    constants::*,
    parsers::{parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable},
    DecodeError,
};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Nla {
    /// Path to which the socket was bound. This attribute is known as
    /// `UNIX_DIAG_NAME` in the kernel.
    Name(String),
    /// VFS information for this socket. This attribute is known as
    /// `UNIX_DIAG_VFS` in the kernel.
    Vfs(Vfs),
    /// Inode number of the socket's peer. This attribute is reported
    /// for connected socket only. This attribute is known as
    /// `UNIX_DIAG_PEER` in the kernel.
    Peer(u32),
    /// The payload associated with this attribute is an array of
    /// inode numbers of sockets that have passed the `connect(2)`
    /// call, but haven't been processed with `accept(2)` yet. This
    /// attribute is reported for listening sockets only. This
    /// attribute is known as `UNIX_DIAG_ICONS` in the kernel.
    PendingConnections(Vec<u32>),
    /// This attribute corresponds to the `UNIX_DIAG_RQLEN`. It
    /// reports the length of the socket receive queue, and the queue
    /// size limit. Note that for **listening** sockets the receive
    /// queue is used to store actual data sent by other sockets. It
    /// is used to store pending connections. So the meaning of this
    /// attribute differs for listening sockets.
    ///
    /// For **listening** sockets:
    ///
    /// - the first the number is the number of pending
    ///   connections. It should be equal to `Nla::PendingConnections`
    ///   value's length.
    /// - the second number is the backlog queue maximum length, which
    ///   equals to the value passed as the second argument to
    ///   `listen(2)`
    ///
    /// For other sockets:
    ///
    /// - the first number is the amount of data in receive queue
    ///   (**note**: I am not sure if it is the actual amount of data
    ///   or the amount of memory allocated. The two might differ
    ///   because of memory allocation strategies: more memory than
    ///   strictly necessary may be allocated for a given `sk_buff`)
    /// - the second number is the memory used by outgoing data. Note
    ///   that strictly UNIX sockets don't have a send queue, since
    ///   the data they send is directly written into the destination
    ///   socket receive queue. But the memory allocated for this data
    ///   is still counted from the sender point of view.
    ReceiveQueueLength(u32, u32),
    /// Socket memory information. See [`MemInfo`] for more details.
    MemInfo(MemInfo),
    /// Shutown state: one of [`SHUT_RD`], [`SHUT_WR`] or [`SHUT_RDWR`]
    Shutdown(u8),
    /// Unknown attribute
    Other(DefaultNla),
}

pub const VFS_LEN: usize = 8;

buffer!(VfsBuffer(8) {
    inode: (u32, 0..4),
    device: (u32, 4..8),
});

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Vfs {
    /// Inode number
    inode: u32,
    /// Device number
    device: u32,
}

impl<T: AsRef<[u8]>> Parseable<VfsBuffer<T>> for Vfs {
    fn parse(buf: &VfsBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            inode: buf.inode(),
            device: buf.device(),
        })
    }
}

impl Emitable for Vfs {
    fn buffer_len(&self) -> usize {
        VFS_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = VfsBuffer::new(buf);
        buf.set_inode(self.inode);
        buf.set_device(self.device);
    }
}

pub const MEM_INFO_LEN: usize = 36;

buffer!(MemInfoBuffer(MEM_INFO_LEN) {
    unused_sk_rmem_alloc: (u32, 0..4),
    so_rcvbuf: (u32, 4..8),
    unused_sk_wmem_queued: (u32, 8..12),
    max_datagram_size: (u32, 12..16),
    unused_sk_fwd_alloc: (u32, 16..20),
    alloc: (u32, 20..24),
    unused_sk_optmem: (u32, 24..28),
    unused_backlog: (u32, 28..32),
    unused_drops: (u32, 32..36),
});

/// # Warning
///
/// I don't have a good understanding of the Unix Domain Sockets, thus
/// take the following documentation with a *huge* grain of salt.
///
/// # Documentation
///
/// ## `UNIX_DIAG_MEMINFO` vs `INET_DIAG_SK_MEMINFO`
///
/// `MemInfo` represent an `UNIX_DIAG_MEMINFO` NLA. This NLA has the
/// same structure than `INET_DIAG_SKMEMINFO`, but since Unix sockets
/// don't actually use the network stack, many fields are not relevant
/// and are always set to 0. According to iproute2 commit
/// [51ff9f2453d066933f24170f0106a7deeefa02d9](https://patchwork.ozlabs.org/patch/222700/), only three attributes can have non-zero values.
///
/// ## Particularities of UNIX sockets
///
/// One particularity of UNIX sockets is that they don't really have a
/// send queue: when sending data, the kernel finds the destination
/// socket and enqueues the data directly in its receive queue (which
/// [see also this StackOverflow
/// answer](https://stackoverflow.com/questions/9644251/how-do-unix-domain-sockets-differentiate-between-multiple-clients)). For
/// instance in `unix_dgram_sendmsg()` in `net/unix/af_unix.c` we
/// have:
///
/// ```c
/// // `other` refers to the peer socket here
/// skb_queue_tail(&other->sk_receive_queue, skb);
/// ```
///
/// Another particularity is that the kernel keeps track of the memory
/// using the sender's `sock.sk_wmem_alloc` attribute. The receiver's
/// `sock.sk_rmem_alloc` is always zero. Memory is allocated when data
/// is written to a socket, and is reclaimed when the data is read
/// from the peer's socket.
///
/// Last but not least, the way unix sockets handle incoming
/// connection differs from the TCP sockets. For TCP sockets, the
/// queue used to store pending connections is
/// `sock.sk_ack_backlog`. But UNIX sockets use the receive queue to
/// store them. They can do that because a listening socket only
/// receive connections, they do not receive actual data from other
/// socket, so there is no ambiguity about the nature of the data
/// stored in the receive queue.
// /// We can see that in `unix_stream_sendmsg()` for instance we have
// /// the follownig function calls:
// ///
// /// ```
// /// unix_stream_sendmsg()
// ///     -> sock_alloc_send_pskb()
// ///     -> skb_set_owner_w()
// ///     -> refcount_add(size, &sk->sk_wmem_alloc);
/// ```
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct MemInfo {
    /// Value of `SO_RCVBUF`, although it does not have any effect on
    /// Unix Domain Sockets. As per `man unix(7)`:
    ///
    /// > The `SO_SNDBUF` socket option does have an effect for UNIX
    /// > domain sockets, but the `SO_RCVBUF` option does not.
    ///
    /// This attribute corresponds to `sock.sk_rcvbuf` in the kernel.
    pub so_rcvbuf: u32,
    /// Maximum size in in bytes of a datagram, as set by
    /// `SO_SNDBUF`. As per `man unix(7)`:
    ///
    /// > For datagram sockets, the `SO_SNDBUF` value imposes an upper
    /// > limit on the size of outgoing datagrams. This limit is
    /// > calculated as the doubled (see `socket(7)`) option value
    /// > less 32 bytes used for overhead.
    ///
    /// This attribute corresponds to `sock.sk_sndbuf` in the kernel.
    pub max_datagram_size: u32,
    /// Memory currently allocated for the data sent but not yet read
    /// from the receiving socket(s). The memory is tracked using the
    /// sending socket `sock.sk_wmem_queued` attribute in the kernel.
    ///
    /// Note that this quantity is a little larger than the actual
    /// data being sent because it takes into account the overhead of
    /// the `sk_buff`s used internally:
    ///
    /// ```c
    /// /* in net/core/sock.c, sk_wmem_alloc is set in
    ///    skb_set_owner_w() with: */
    /// refcount_add(skb->truesize, &sk->sk_wmem_alloc);
    ///
    /// /* truesize is set by __alloc_skb() in net/core/skbuff.c
    ///    by: */
    /// skb->truesize = SKB_TRUESIZE(size);
    ///
    /// /* and SKB_TRUESIZE is defined as: */
    /// #define SKB_TRUESIZE(X) ((X) +                        \
    ///     SKB_DATA_ALIGN(sizeof(struct sk_buff)) +          \
    ///     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
    /// ```
    pub alloc: u32,
}

impl<T: AsRef<[u8]>> Parseable<MemInfoBuffer<T>> for MemInfo {
    fn parse(buf: &MemInfoBuffer<T>) -> Result<Self, DecodeError> {
        Ok(Self {
            so_rcvbuf: buf.so_rcvbuf(),
            max_datagram_size: buf.max_datagram_size(),
            alloc: buf.alloc(),
        })
    }
}

impl Emitable for MemInfo {
    fn buffer_len(&self) -> usize {
        MEM_INFO_LEN
    }

    fn emit(&self, buf: &mut [u8]) {
        let mut buf = MemInfoBuffer::new(buf);
        buf.set_unused_sk_rmem_alloc(0);
        buf.set_so_rcvbuf(self.so_rcvbuf);
        buf.set_unused_sk_wmem_queued(0);
        buf.set_max_datagram_size(self.max_datagram_size);
        buf.set_unused_sk_fwd_alloc(0);
        buf.set_alloc(self.alloc);
        buf.set_unused_sk_optmem(0);
        buf.set_unused_backlog(0);
        buf.set_unused_drops(0);
    }
}

impl crate::utils::nla::Nla for Nla {
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            // +1 because we need to append a null byte
            Name(ref s) => s.as_bytes().len() + 1,
            Vfs(_) => VFS_LEN,
            Peer(_) => 4,
            PendingConnections(ref v) => 4 * v.len(),
            ReceiveQueueLength(_, _) => 8,
            MemInfo(_) => MEM_INFO_LEN,
            Shutdown(_) => 1,
            Other(ref attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            Name(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Vfs(ref value) => value.emit(buffer),
            Peer(value) => NativeEndian::write_u32(buffer, value),
            PendingConnections(ref values) => {
                for (i, v) in values.iter().enumerate() {
                    NativeEndian::write_u32(&mut buffer[i * 4..], *v);
                }
            }
            ReceiveQueueLength(v1, v2) => {
                NativeEndian::write_u32(buffer, v1);
                NativeEndian::write_u32(&mut buffer[4..], v2);
            }
            MemInfo(ref value) => value.emit(buffer),
            Shutdown(value) => buffer[0] = value,
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Name(_) => UNIX_DIAG_NAME,
            Vfs(_) => UNIX_DIAG_VFS,
            Peer(_) => UNIX_DIAG_PEER,
            PendingConnections(_) => UNIX_DIAG_ICONS,
            ReceiveQueueLength(_, _) => UNIX_DIAG_RQLEN,
            MemInfo(_) => UNIX_DIAG_MEMINFO,
            Shutdown(_) => UNIX_DIAG_SHUTDOWN,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            UNIX_DIAG_NAME => {
                let err = "invalid UNIX_DIAG_NAME value";
                Self::Name(parse_string(payload).context(err)?)
            }
            UNIX_DIAG_VFS => {
                let err = "invalid UNIX_DIAG_VFS value";
                let buf = VfsBuffer::new_checked(payload).context(err)?;
                Self::Vfs(Vfs::parse(&buf).context(err)?)
            }
            UNIX_DIAG_PEER => {
                Self::Peer(parse_u32(payload).context("invalid UNIX_DIAG_PEER value")?)
            }
            UNIX_DIAG_ICONS => {
                if payload.len() % 4 != 0 {
                    return Err(DecodeError::from("invalid UNIX_DIAG_ICONS"));
                }
                Self::PendingConnections(payload.chunks(4).map(NativeEndian::read_u32).collect())
            }
            UNIX_DIAG_RQLEN => {
                if payload.len() != 8 {
                    return Err(DecodeError::from("invalid UNIX_DIAG_RQLEN"));
                }
                Self::ReceiveQueueLength(
                    NativeEndian::read_u32(&payload[..4]),
                    NativeEndian::read_u32(&payload[4..]),
                )
            }
            UNIX_DIAG_MEMINFO => {
                let err = "invalid UNIX_DIAG_MEMINFO value";
                let buf = MemInfoBuffer::new_checked(payload).context(err)?;
                Self::MemInfo(MemInfo::parse(&buf).context(err)?)
            }
            UNIX_DIAG_SHUTDOWN => {
                Self::Shutdown(parse_u8(payload).context("invalid UNIX_DIAG_SHUTDOWN value")?)
            }
            kind => {
                Self::Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?)
            }
        })
    }
}

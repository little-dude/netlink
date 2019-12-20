[![Build Status](https://travis-ci.org/little-dude/netlink.svg?branch=master)](https://travis-ci.org/little-dude/netlink)

# netlink-rs

This project aims at providing building blocks for [the netlink
protocol](https://en.wikipedia.org/wiki/Netlink) (see `man 7 netlink`).

The netlink protocol is _huge_ but the some subprotocols are widely
used:

- the [generic netlink protocol](https://lwn.net/Articles/208755/), used to create custom IPCs
- the [`rtnetlink` protocol](https://www.infradead.org/~tgr/libnl/doc/route.html) (see `man 7 rtnetlink`), for manipulating the network stack
- the `audit` protocol to interact with Linux audit system
- the `sock_diag` protocol (see `man 7 sock_diag`) to monitor sockets

## Organization

- the [`netlink_sys`](./netlink-sys) crate provides netlink sockets.  Integration with
  [`mio`](https://github.com/carllerche/mio) and [`tokio`](https://github.com/tokio-rs/) is
  optional.
- Each netlink protocol has a `netlink-packet-<protocol_name>` crate that provides the packets for
  this protocol:
    - [`netlink-packet-route`](./netlink-packet-route) provides `RtnlMessage` which represents
      messages for the route protocol
    - [`netlink-packet-audit`](./netlink-packet-audit) provides `AuditMessage` which represents
      messages for the audit protocol
- the [`netlink-packet-core`](./netlink-packet-core) is the glue for all the other
  `netlink-packet-*` crates. I provides a unique `NetlinkMessage<T>` type that represent any netlink
  message for any sub-protocol.
- the [`netlink_proto`](./netlink-proto) crate an asynchronous implementation of the netlink
  protocol. It only depends on `netlink-packet-core` for the `NetlinkMessage` type and `netlink-sys`
  for the socket.
- the [`rtnetlink`](./rtnetlink) crate provides higher level abstraction for the [route
  protocol](https://www.infradead.org/~tgr/libnl/doc/route.html) (see `man 7 rtnetlink`). This is
  probably what users want to use, if they want to manipulate IP addresses, route tables, etc.
- the [`audit`](./audit) crate provides higher level abstractions for the audit protocol.

## Other netlink projects in rust

Before starting working on this library, I've checked a bunch of other projects
but none seems to be really complete.

- https://github.com/jbaublitz/neli: the main alternative to these crates, as it is actively
  developed.
- Other but less actively developed alternatives:
  - https://github.com/achanda/netlink
  - https://github.com/polachok/pnetlink
  - https://github.com/crhino/netlink-rs
  - https://github.com/carrotsrc/rsnl
  - https://github.com/TaborKelly/nl-utils

## Other non-rust netlink projects

- [`libnl`](https://www.infradead.org/~tgr/libnl/): netlink implementation in
  C. Very complete with awesome documentation.
- [`pyroute2`](https://github.com/svinota/pyroute2/tree/master/pyroute2/netlink): a very complete and readable implementation in pure python.
- [`netlink`](https://github.com/vishvananda/netlink): a very complete and very actively maintained go project, seems to be widely used.

## Credits

My main resource so far has been the source code of
[`pyroute2`](https://github.com/svinota/pyroute2/tree/master/pyroute2/netlink)
and [`netlink`](https://github.com/vishvananda/netlink) **a lot**. These two
projects are great, and very nicely written. As someone who does not read C
fluently, and that does not know much about netlink, they have been invaluable.

I'd also like to praise [`libnl`](https://www.infradead.org/~tgr/libnl/) for
its documentation. It helped me a lot in understanding the protocol basics.

The whole packet parsing logic is inspired by @whitequark excellent blog posts
([part 1](https://lab.whitequark.org/notes/2016-12-13/abstracting-over-mutability-in-rust/),
[part 2](https://lab.whitequark.org/notes/2016-12-17/owning-collections-in-heap-less-rust/)
and [part 3](https://lab.whitequark.org/notes/2017-01-16/abstracting-over-mutability-in-rust-macros/),
although I've only really used the concepts described in the first blog post).
These ideas are also being used in @m-labs's
[`smoltcp`](https://github.com/m-labs/smoltcp) project.

Thanks also to the people behing [tokio](tokio.rs), especially
@carllerche, for the amazing tool they are building, and the support
they provide. The project structure and code quality are mind blowing,
and some parts of this projects are basically rip-offs from tokio's
source code

Finally, thanks to the Rust community, which helped me on multiple occasions

Other resources I particularly appreciated:

- https://www.linuxjournal.com/article/7356
- https://medium.com/@mdlayher/linux-netlink-and-go-part-1-netlink-4781aaeeaca8

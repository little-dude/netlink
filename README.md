netlink-rs
==========

This project aims at providing building blocks for [the netlink
protocol](https://en.wikipedia.org/wiki/Netlink) (see `man 7 netlink`).

The netlink protocol is _huge_ but the two most widely used subprotocols are
[the generic netlink protocol](https://lwn.net/Articles/208755/) and [the route
netlink protocol](https://www.infradead.org/~tgr/libnl/doc/route.html) (see
`man 7 rtnetlink`).

The project is in its early stages, and I'm currently focusing on the route
netlink protocol.

Organization
------------

- the [`netlink-sys`](./netlink-sys) crate provides low level building blocks:
  constants, socket, and packet parsing
- the [`netlink-ip`](./netlink-ip) crate provides higher level abstractions for
  the route netlink protocol. It is fully asynchronous and built on top of
  [tokio](tokio.rs).

Other netlink projects in rust
------------------------------

Before starting working on this library, I've checked a bunch of other projects
but none seems to be really complete.

- https://github.com/achanda/netlink: rust bindings for netlink. Does not seem
  very usable as is, and does not seem to be developped anymore.
- https://github.com/polachok/pnetlink: very similar to this project, but built
  on to of [libpnet](https://github.com/libpnet/libpnet). The author seems to
  be more knowledgeable about netlink than I am. It also has broader coverage
  of the route netlink protocol (support for the `RTM_{NEW,DEL,GET}ROUTE` and
  `RTM_{NEW,DEL,GET}ADDRESS` messages). However, many attributes supported by
  `netlink-sys` are not covered.
- https://github.com/crhino/netlink-rs: rust bindings for libnl. Very
  incomplete and not developed.
- https://github.com/jbaublitz/neli: generic netlink protocol. Pretty recent
  project, actively developed.
- https://github.com/carrotsrc/rsnl: bindings for libnl. Maintained but not
  actively developed.
- https://github.com/TaborKelly/nl-utils: a netlink packet parser. The goal is
  not that same than this project.

Other non-rust netlink projects
-------------------------------

- [`libnl`](https://www.infradead.org/~tgr/libnl/): netlink implementation in
  C. Very complete with awesome documentation.
- [`pyroute2`](https://github.com/svinota/pyroute2/tree/master/pyroute2/netlink): a very complete and readable implementation in pure python.
- [`netlink`](https://github.com/vishvananda/netlink): a very complete and very actively maintained go project, seems to be widely used.

Credits
-------

My main resource so far have been the source code of
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

Thanks also to the people behing [tokio](tokio.rs), especially @carllerche, for
the amazing tool they are building, and the support they provide. The project
structure and code quality are mind blowing, and some parts of this projects
are basically [rip-offs from tokio's source
code](https://github.com/little-dude/netlink/blob/master/netlink-sys/src/framed.rs).

Finally, thanks to the Rust community, which
[helped me](https://users.rust-lang.org/t/help-understanding-libc-call/17308)
in
[multiple occations](https://users.rust-lang.org/t/implementing-a-trait-for-t-and-iterator-item-t/17891).

Other resources I particularly appreciated:

- https://www.linuxjournal.com/article/7356
- https://medium.com/@mdlayher/linux-netlink-and-go-part-1-netlink-4781aaeeaca8

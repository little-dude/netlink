# Release process

## Summary

- bump the versions in the Cargo.toml using `git blame` and `git log`,
  starting from the `netlink-packet-*` and `netlink-sys` crates
- Update the `CHANGELOG` file with version changes, new features, bug fixes
  and breaking changes
- Check that `cargo test` still works once your done
- Create pull request for the changes for CHANGELOG and version dumping.
- Create new tag via command `git tag --sign $(date +%Y%m%d)`
- Publish the tag to github via command `git push --tags upstream`
- Create new release page at [github webpage][github_new_release]
- Publish the crates via command `cargo publish` in changed crate folders

## Detailed process

### Crate groups

First, distinguish three groups of crates:

- `netlink-packet-*` crates
- `netlink-sys`
- `netlink-proto`, `audit` and `rtnetlink`, which depend on the two other groups

Usually start by bumping the versions of the first group of crates,
then `netlink-sys`, and then the last group of crates.

### Dependency graph

Here are the dependency tree for each group.

```
netlink-packet-utils v0.4.0

netlink-packet-core v0.2.4
└── netlink-packet-utils v0.4.0
[dev-dependencies]
└── netlink-packet-route v0.7.0
    ├── netlink-packet-core v0.2.4
    └── netlink-packet-utils v0.4.0

netlink-packet-route v0.7.0
├── netlink-packet-core v0.2.4
│   └── netlink-packet-utils v0.4.0
└── netlink-packet-utils v0.4.0
[dev-dependencies]
└── netlink-sys v0.6.0

netlink-packet-audit v0.2.2
├── netlink-packet-core v0.2.4
│   └── netlink-packet-utils v0.4.0
└── netlink-packet-utils v0.4.0

netlink-packet-sock-diag v0.1.0
├── netlink-packet-core v0.2.4
│   └── netlink-packet-utils v0.4.0
└── netlink-packet-utils v0.4.0
[dev-dependencies]
└── netlink-sys v0.6.0
```

Then `netlink-sys`:

```
netlink-sys v0.6.0
[dev-dependencies]
└── netlink-packet-audit v0.2.2
    ├── netlink-packet-core v0.2.4
    │   └── netlink-packet-utils v0.4.0
    └── netlink-packet-utils v0.4.0
```

Finally, `netlink-proto`, `audit` and `rtnetlink`, which use both the
`netlink-packet-*` crates and `netlink-sys`:

```
netlink-proto v0.6.0
├── netlink-packet-core v0.2.4
│   └── netlink-packet-utils v0.4.0
└── netlink-sys v0.6.0
[dev-dependencies]
├── netlink-packet-audit v0.2.2
└── netlink-packet-route v0.7.0

audit v0.3.1
├── netlink-packet-audit v0.2.2
│   ├── netlink-packet-core v0.2.4
│   │   └── netlink-packet-utils v0.4.0
│   └── netlink-packet-utils v0.4.0
└── netlink-proto v0.6.0
    ├── netlink-packet-core v0.2.4
    └── netlink-sys v0.6.0

rtnetlink v0.7.0
├── netlink-packet-route v0.7.0
│   ├── netlink-packet-core v0.2.4
│   │   └── netlink-packet-utils v0.4.0
│   └── netlink-packet-utils v0.4.0
└── netlink-proto v0.6.0
    ├── netlink-packet-core v0.2.4
    └── netlink-sys v0.6.0
```

### Version bump

For each crate, look at when was the last time the version was
changed. For instance for `rtnetlink`:

```
$ git blame rtnetlink/Cargo.toml  | grep "version = "
88dde610 rtnetlink/Cargo.toml   (little-dude    2021-01-20 20:09:23 +0100  3) version = "0.7.0"
2f721807 rtnetlink/Cargo.toml   (Stefan Bühler  2021-06-06 14:20:15 +0200 26) netlink-proto = { default-features = false, version = "0.6" }
83da33e2 rtnetlink/Cargo.toml   (gabrik         2021-01-22 16:22:16 +0100 29) tokio = { version = "1.0.1", features = ["rt"], optional = true}
83da33e2 rtnetlink/Cargo.toml   (gabrik         2021-01-22 16:22:16 +0100 30) async-std = { version = "1.9.0", features = ["unstable"], optional = true}
ef3a79a8 rtnetlink/Cargo.toml   (Tim Zhang      2021-01-15 19:31:38 +0800 35) tokio = { version = "1.0.1", features = ["macros", "rt", "rt-multi-thread"] }
83da33e2 rtnetlink/Cargo.toml   (gabrik         2021-01-22 16:22:16 +0100 36) async-std = { version = "1.9.0", features = ["attributes"]}

$ git log  --oneline 88dde610.. rtnetlink/
2f72180 Cargo.toml: move path specs to workspace [patch.crates-io] section
1e8bc53 CI: Fix rtnetlink example
cae6e09 Merge pull request #97 from SkamDart/SkamDart/ip-monitor
35b6cb9 use `unwrap()` instead of `.is_ok()` so that the error is printed
2f0877a (origin/release) rustfmt, clippy
5c39136 Merge pull request #130 from benjumanji/wireguard-type
af1ee71 Merge pull request #137 from little-dude/rtnetlink-macros
83da33e added features and examples to rtnetlink
079b5f3 (origin/rtnetlink-macros) rtnetlink: use macros in response handling
b681f35 Add basic test for bringing up interface
5201dcd ip monitor clone
```

Based on the changes, decide whether bumping the patch or minor
version. For crates that like `rtnetlink`, usually just bump the
minor version. For `netlink-packet-*` and `netlink-sys`, try to bump
it only if really necessary, because bumping it means bumping all the
crates that depend on it.

Once we have bumped all the version locally, push to a `release`
branch to have CI running. If CI passes, just go with `cargo publish`,
again starting from the `netlink-packet-*` and `netlink-sys`
crates. `--dry-run` is nice but it doesn't really work. For instance
if `netlink-packet-utils` is bumped from 0.x to 0.x+1,
then `cargo publish --dry-run` will not work for `netlink-packet-core`,
because the crate depends on `netlink-packet-utils` 0.x+1, which hasn't be
published yet.

[github_new_release]: https://github.com/little-dude/netlink/releases/new

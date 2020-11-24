use tokio::task;

use crate::Error;
use nix::{
    fcntl::OFlag,
    sched::CloneFlags,
    sys::{
        stat::Mode,
        wait::{waitpid, WaitStatus},
    },
    unistd::{fork, ForkResult},
};
use std::{option::Option, path::Path, process::exit};

pub const NETNS_PATH: &str = "/run/netns/";
pub const SELF_NS_PATH: &str = "/proc/self/ns/net";
pub const NONE_FS: &str = "none";

pub struct NetworkNamespace();

impl NetworkNamespace {
    /// Add a new network namespace.
    /// This is equivalent to `ip netns add NS_NAME`.
    pub async fn add(ns_name: String) -> Result<(), Error> {
        // Forking process to avoid moving caller into new namespace
        log::trace!("Forking...");
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child, .. }) => {
                // as the wait is blocking spawning it in a blocking task
                let res = task::spawn_blocking(move || {
                    log::trace!("Parent waiting child: {}", child);
                    match waitpid(child, None) {
                        Ok(wait_status) => match wait_status {
                            WaitStatus::Exited(_, res) => {
                                log::trace!("Child exist status: {}", res);
                                if res == 0 {
                                    return Ok(());
                                }
                                let err_msg = format!("Child result: {}", res);
                                Err(Error::NamespaceError(err_msg))
                            }
                            WaitStatus::Signaled(_, signal, has_dump) => {
                                let err_msg = format!(
                                    "Child process was killed by signal: {} with core dump {}",
                                    signal, has_dump
                                );
                                Err(Error::NamespaceError(err_msg))
                            }
                            _ => {
                                let err_msg = String::from("Unknown child process status");
                                Err(Error::NamespaceError(err_msg))
                            }
                        },
                        Err(e) => {
                            let err_msg = format!("wait failed: {}", e);
                            Err(Error::NamespaceError(err_msg))
                        }
                    }
                })
                .await;
                match res {
                    Ok(r) => r,
                    Err(e) => {
                        let err_msg = format!("wait failed: {}", e);
                        log::error!("{}", err_msg);
                        Err(Error::NamespaceError(err_msg))
                    }
                }
            }
            Ok(ForkResult::Child) => {
                log::trace!("Child creating namespace");

                let mut netns_path = String::new();

                let dir_path = Path::new(NETNS_PATH);
                let mut mkdir_mode = Mode::empty();
                let mut open_flags = OFlag::empty();
                let mut mount_flags = nix::mount::MsFlags::empty();
                let mut setns_flags = CloneFlags::empty();
                let none_fs = Path::new(&NONE_FS);
                let none_p4: Option<&Path> = None;

                // flags in mkdir
                mkdir_mode.insert(Mode::S_IRWXU);
                mkdir_mode.insert(Mode::S_IRGRP);
                mkdir_mode.insert(Mode::S_IXGRP);
                mkdir_mode.insert(Mode::S_IROTH);
                mkdir_mode.insert(Mode::S_IXOTH);

                open_flags.insert(OFlag::O_RDONLY);
                open_flags.insert(OFlag::O_CREAT);
                open_flags.insert(OFlag::O_EXCL);

                netns_path.push_str(NETNS_PATH);
                netns_path.push_str(&ns_name);

                // creating namespaces folder if not exists
                #[allow(clippy::collapsible_if)]
                if nix::sys::stat::stat(dir_path).is_err() {
                    if nix::unistd::mkdir(dir_path, mkdir_mode).is_err() {
                        exit(-1);
                    }
                }

                mount_flags.insert(nix::mount::MsFlags::MS_BIND);
                mount_flags.insert(nix::mount::MsFlags::MS_REC);

                if nix::mount::mount(
                    Some(Path::new(dir_path)),
                    dir_path,
                    Some(none_fs),
                    mount_flags,
                    none_p4,
                )
                .is_err()
                {
                    exit(-1);
                }

                mount_flags = nix::mount::MsFlags::empty();
                mount_flags.insert(nix::mount::MsFlags::MS_SHARED);
                mount_flags.insert(nix::mount::MsFlags::MS_REC);
                if nix::mount::mount(
                    Some(Path::new("")),
                    dir_path,
                    Some(none_fs),
                    mount_flags,
                    none_p4,
                )
                .is_err()
                {
                    exit(-1);
                }

                let ns_path = Path::new(&netns_path);

                // creating the netns file
                let fd = match nix::fcntl::open(ns_path, open_flags, Mode::empty()) {
                    Ok(raw_fd) => raw_fd,
                    Err(_) => exit(-1),
                };

                if nix::unistd::close(fd).is_err() {
                    let _ = nix::unistd::unlink(ns_path);
                    exit(-1)
                }

                // unshare to the new network namespace
                if nix::sched::unshare(CloneFlags::CLONE_NEWNET).is_err() {
                    let _ = nix::unistd::unlink(ns_path);
                    exit(-1);
                }
                open_flags = OFlag::empty();
                open_flags.insert(OFlag::O_RDONLY);
                open_flags.insert(OFlag::O_CLOEXEC);

                let fd = match nix::fcntl::open(Path::new(&SELF_NS_PATH), open_flags, Mode::empty())
                {
                    Ok(raw_fd) => raw_fd,
                    Err(_) => exit(-1),
                };

                let self_path = Path::new(&SELF_NS_PATH);

                // bind to the netns
                if nix::mount::mount(
                    Some(self_path),
                    ns_path,
                    Some(none_fs),
                    nix::mount::MsFlags::MS_BIND,
                    none_p4,
                )
                .is_err()
                {
                    let _ = nix::unistd::unlink(ns_path);
                    exit(-1);
                }

                setns_flags.insert(CloneFlags::CLONE_NEWNET);
                if nix::sched::setns(fd, setns_flags).is_err() {
                    let _ = nix::unistd::unlink(ns_path);
                    exit(-1);
                }

                exit(0)
            }
            Err(e) => {
                let err_msg = format!("Fork failed: {}", e);
                Err(Error::NamespaceError(err_msg))
            }
        }
    }

    /// Remove a network namespace
    /// This is equivalent to `ip netns del NS_NAME`.
    pub async fn del(ns_name: String) -> Result<(), Error> {
        let jh = task::spawn_blocking(move || {
            let mut netns_path = String::new();
            netns_path.push_str(NETNS_PATH);
            netns_path.push_str(&ns_name);
            let ns_path = Path::new(&netns_path);

            if nix::mount::umount2(ns_path, nix::mount::MntFlags::MNT_DETACH).is_err() {
                let err_msg = String::from("Namespace unmound failed (are you running as root?)");
                return Err(Error::NamespaceError(err_msg));
            }

            if nix::unistd::unlink(ns_path).is_err() {
                let err_msg =
                    String::from("Namespace file remove failed (are you running as root?)");
                return Err(Error::NamespaceError(err_msg));
            }
            Ok(())
        });
        match jh.await {
            Ok(r) => r,
            Err(e) => {
                let err_msg = format!("Namespace removal failed: {}", e);
                Err(Error::NamespaceError(err_msg))
            }
        }
    }
}

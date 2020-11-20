use nix::fcntl::OFlag;
use nix::sched::*;
use nix::sys::stat::Mode;
use std::option::Option;
use std::path::Path;

pub const NETNS_PATH: &str = "/var/run/netns/";
pub const SELF_NS_PATH: &str = "/proc/self/ns/net";
pub const NONE_FS: &str = "none";


pub struct NetworkNamespace();


impl NetworkNamespace {
    pub async fn add(ns_name: &String) -> nix::Result<()> {
        let mut netns_path = String::new();

        let dir_path = Path::new(NETNS_PATH);
        let mut mkdir_mode = Mode::empty();
        let mut open_flags = OFlag::empty();

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
        netns_path.push_str(ns_name);

        // creating namespaces folder if not exists
        nix::unistd::mkdir(dir_path, mkdir_mode)?;

        let ns_path = Path::new(&netns_path);

        // creating the netns file
        let fd = nix::fcntl::open(ns_path, open_flags, Mode::empty())?;

        nix::unistd::close(fd)?;

        // unshare to the new network namespace
        let ret = nix::sched::unshare(CloneFlags::CLONE_NEWNET);

        let self_path = Path::new(&SELF_NS_PATH);
        let none_fs = Path::new(&NONE_FS);
        let none_p4: Option<&Path> = None;
        // bind to the netns
        nix::mount::mount(
            Some(self_path),
            ns_path,
            Some(none_fs),
            nix::mount::MsFlags::MS_BIND,
            none_p4,
        )?;

        ret
    }


    pub async fn del(ns_name: &String) -> nix::Result<()> {
        let mut netns_path = String::new();
        netns_path.push_str(NETNS_PATH);
        netns_path.push_str(ns_name);
        let ns_path = Path::new(&netns_path);

        nix::mount::umount2(ns_path, nix::mount::MntFlags::MNT_DETACH)?;

        nix::unistd::unlink(ns_path)
    }

}

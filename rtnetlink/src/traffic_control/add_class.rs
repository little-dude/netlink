use std::fs::File;

use crate::{
    constants::{
        ATM_CELL_PAYLOAD,
        ATM_CELL_SIZE,
        SC_CLK_TCK,
        TC_LINKLAYER_MASK,
        TIME_UNITS_PER_SEC,
    },
    packet::{NetlinkMessage, RtnlMessage, TcMessage, NLM_F_ACK},
    try_nl,
    Error,
    Handle,
};
use futures::stream::StreamExt;
use lazy_static::{__Deref, lazy_static};
use netlink_packet_route::{
    tc::{
        constants::{TC_H_MAJ_MASK, TC_H_MIN_MASK},
        tc_htb::{LinkLayer, TcCore, TcHtbOpt, TcRateSpec},
        Nla,
        TcOpt,
    },
    TC_H_MAKE,
};
use netlink_proto::packet::{NLM_F_CREATE, NLM_F_EXCL};
use nix::libc::sysconf;

lazy_static! {
    static ref TC_STATIC: Result<TcCore, Error> = {
        use std::io::prelude::*;
        let mut f =
            File::open("/proc/net/psched").map_err(|e| Error::TcInitError(e.to_string()))?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)
            .map_err(|e| Error::TcInitError(e.to_string()))?;
        let mut slice = buf.split_whitespace();
        let mut arr = [0; 3];
        let mut iter = arr.iter_mut();
        loop {
            match (slice.next(), iter.next()) {
                (Some(s), Some(i)) => {
                    *i = i32::from_str_radix(s, 16)
                        .map_err(|e| Error::TcInitError(e.to_string()))?;
                }
                (_, None) => break Ok(()),
                _ => {
                    break Err(Error::TcInitError(
                        "unrecognized input from /proc/net/psched".to_string(),
                    ))
                }
            }
        }?;
        let [t2us, us2t, clock_res] = arr;
        let clock_factor = clock_res as f64 / TIME_UNITS_PER_SEC as f64;
        let tick_in_usec = t2us as f64 / us2t as f64 * clock_factor;
        Ok(TcCore {
            clock_factor,
            tick_in_usec,
            hz: sysconf_safe(SC_CLK_TCK) as f64,
        })
    };
}

impl TC_STATIC {
    #![allow(arithmetic_overflow)]
    fn time2tick(time: u32) -> Result<u32, Error> {
        let tc_core = TC_STATIC.deref().clone()?;
        let r;
        unsafe {
            r = (time as f64 * tc_core.tick_in_usec).to_int_unchecked::<u32>();
        }
        Ok(r)
    }

    fn calc_xmittime(rate: u64, size: u32) -> Result<u32, Error> {
        Ok(Self::time2tick(
            (TIME_UNITS_PER_SEC as f64 * (size as f64 / rate as f64)) as u32,
        )?)
    }

    fn get_hz() -> Result<u32, Error> {
        let tc_core = TC_STATIC.deref().clone()?;
        Ok(tc_core.hz as u32)
    }

    fn tc_align_to_atm(size: u32) -> u32 {
        let mut cells = size / ATM_CELL_PAYLOAD;
        if (size % ATM_CELL_PAYLOAD) > 0 {
            cells += 1;
        }

        let linksize = cells * ATM_CELL_SIZE; /* Use full cell size to add ATM tax */
        return linksize;
    }

    fn tc_adjust_size(sz: &mut u32, mpu: u32, linklayer: LinkLayer) -> u32 {
        if *sz < mpu {
            *sz = mpu;
        }

        match linklayer {
            LinkLayer::LinklayerAtm => Self::tc_align_to_atm(*sz),
            _ => {
                /* No size adjustments on Ethernet */
                *sz
            }
        }
    }

    fn tc_calc_rtable(
        r: &mut TcRateSpec,
        rtab: &mut [u32; 256],
        cell_log: &mut i32,
        mtu: &mut u32,
        linklayer: LinkLayer,
    ) -> Result<i32, Error> {
        let bps = r.rate;
        let mpu = r.mpu;

        if *mtu == 0 {
            *mtu = 2047;
        }

        if *cell_log < 0 {
            *cell_log = 0;
            while (*mtu >> *cell_log) > 255 {
                *cell_log += 1;
            }
        }

        for i in 0..256 {
            let mut sz = (i as u32 + 1) << *cell_log;
            let sz = Self::tc_adjust_size(&mut sz, mpu as u32, linklayer);
            rtab[i] = Self::calc_xmittime(bps as u64, sz)?;
        }

        r.cell_align = -1;
        r.cell_log = *cell_log as u8;
        r.linklayer = linklayer as u8 & TC_LINKLAYER_MASK as u8;
        Ok(*cell_log)
    }
}

pub struct TrafficClassNewRequest {
    handle: Handle,
    message: TcMessage,
    flags: u16,
}

impl TrafficClassNewRequest {
    pub(crate) fn new(handle: Handle, ifindex: i32) -> Self {
        let mut message = TcMessage::default();
        message.header.index = ifindex;
        Self {
            handle,
            message,
            flags: 1,
        }
    }

    /// Execute the request
    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut handle,
            message,
            flags,
        } = self;

        let mut req = NetlinkMessage::from(RtnlMessage::NewTrafficClass(message));
        req.header.flags = NLM_F_ACK | flags;

        let mut response = handle.request(req)?;
        while let Some(message) = response.next().await {
            try_nl!(message);
        }
        Ok(())
    }

    pub fn parent(mut self, maj: u16, min: u16) -> Self {
        // assert_eq!(self.message.header.parent, TC_H_UNSPEC);
        self.message.header.parent = TC_H_MAKE!((maj as u32) << 16, min as u32);
        self
    }

    pub fn class_id(mut self, maj: u16, min: u16) -> Self {
        // assert_eq!(self.message.header.index, 0);
        self.message.header.handle = TC_H_MAKE!((maj as u32) << 16, min as u32);
        self
    }

    pub fn index(mut self, index: i32) -> Self {
        assert_eq!(self.message.header.index, 0);
        self.message.header.index = index;
        self
    }

    pub fn htb(self) -> HtbTrafficClassNewRequest {
        HtbTrafficClassNewRequest {
            request: self,
            rate: 0,
            ceil: 0,
        }
    }
}

pub struct HtbTrafficClassNewRequest {
    request: TrafficClassNewRequest,
    rate: u64,
    ceil: u64,
}

impl HtbTrafficClassNewRequest {
    pub fn new(request: TrafficClassNewRequest) -> Self {
        HtbTrafficClassNewRequest {
            request: request,
            rate: 0,
            ceil: 0,
        }
    }

    pub async fn execute(self) -> Result<(), Error> {
        let Self {
            mut request,
            rate,
            mut ceil,
        } = self;

        let mut mtu = 1600;
        let mpu = 0;
        let overhead = 0;
        let hz = TC_STATIC::get_hz()? as u64;
        let linklayer = LinkLayer::LinklayerEthernet;
        let mut cell_log = -1;
        let mut buffer;
        let mut cbuffer;
        let mut rtab = [0; 256];
        let mut ctab = [0; 256];

        if ceil == 0 {
            ceil = rate;
        }

        buffer = (rate / hz) as u32 + mtu;
        cbuffer = (ceil / hz) as u32 + mtu;

        let mut r = TcRateSpec::new();
        let mut c = TcRateSpec::new();

        r.rate = if rate >= (1 << 32) {
            !0u32
        } else {
            rate as u32
        };
        c.rate = if ceil >= (1 << 32) {
            !0u32
        } else {
            ceil as u32
        };
        r.mpu = mpu;
        c.mpu = mpu;
        r.overhead = overhead;
        c.overhead = overhead;

        TC_STATIC::tc_calc_rtable(&mut r, &mut rtab, &mut cell_log, &mut mtu, linklayer)?;
        buffer = TC_STATIC::calc_xmittime(rate, buffer)?;

        TC_STATIC::tc_calc_rtable(&mut c, &mut ctab, &mut cell_log, &mut mtu, linklayer)?;
        cbuffer = TC_STATIC::calc_xmittime(ceil, cbuffer)?;

        let opt = TcHtbOpt {
            rate: r,
            ceil: c,
            buffer,
            cbuffer,
            quantum: 0,
            level: 0,
            prio: 0,
        };

        let nlas = &mut request.message.nlas;
        nlas.push(Nla::Kind(netlink_packet_route::tc::htb::KIND.to_string()));
        let mut opts = vec![];
        opts.push(TcOpt::TcRate(rate));
        opts.push(TcOpt::TcCeil(ceil));
        opts.push(TcOpt::TcHtbOpt1(opt));
        opts.push(TcOpt::TcHtbRtab(rtab));
        opts.push(TcOpt::TcHtbCtab(ctab));
        nlas.push(Nla::Options(opts));

        request.flags |= NLM_F_EXCL | NLM_F_CREATE;
        request.execute().await
    }

    pub fn rate(mut self, rate: u64) -> Self {
        self.rate = rate / 8;
        self
    }

    pub fn ceil(mut self, ceil: u64) -> Self {
        self.ceil = ceil / 8;
        self
    }
}

fn sysconf_safe(name: i32) -> i64 {
    unsafe { sysconf(name) }
}

#[cfg(test)]
mod test {
    use std::{fs::File, os::unix::io::AsRawFd, path::Path};

    use futures::stream::TryStreamExt;
    use netlink_packet_route::{tc::constants::TC_H_ROOT, AF_UNSPEC};
    use nix::sched::{setns, CloneFlags};
    use tokio::runtime::Runtime;

    use super::*;
    use crate::{new_connection, packet::LinkMessage, NetworkNamespace, NETNS_PATH, SELF_NS_PATH};

    const TEST_NS: &str = "netlink_test_qdisc_ns";
    const TEST_DUMMY: &str = "test_dummy";

    struct Netns {
        path: String,
        _cur: File,
        last: File,
    }

    impl Netns {
        async fn new(path: &str) -> Self {
            // record current ns
            let last = File::open(Path::new(SELF_NS_PATH)).unwrap();

            // create new ns
            NetworkNamespace::add(path.to_string()).await.unwrap();

            // entry new ns
            let ns_path = Path::new(NETNS_PATH);
            let file = File::open(ns_path.join(path)).unwrap();
            setns(file.as_raw_fd(), CloneFlags::CLONE_NEWNET).unwrap();

            Self {
                path: path.to_string(),
                _cur: file,
                last,
            }
        }
    }
    impl Drop for Netns {
        fn drop(&mut self) {
            println!("exit ns: {}", self.path);
            setns(self.last.as_raw_fd(), CloneFlags::CLONE_NEWNET).unwrap();

            let ns_path = Path::new(NETNS_PATH).join(&self.path);
            nix::mount::umount2(&ns_path, nix::mount::MntFlags::MNT_DETACH).unwrap();
            nix::unistd::unlink(&ns_path).unwrap();
            // _cur File will be closed auto
            // Since there is no async drop, NetworkNamespace::del cannot be called
            // here. Dummy interface will be deleted automatically after netns is
            // deleted.
        }
    }

    async fn setup_env() -> (Handle, LinkMessage, Netns) {
        let netns = Netns::new(TEST_NS).await;

        // Notice: The Handle can only be created after the setns, so that the
        // Handle is the connection within the new ns.
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .add()
            .dummy(TEST_DUMMY.to_string())
            .execute()
            .await
            .unwrap();
        let mut links = handle
            .link()
            .get()
            .match_name(TEST_DUMMY.to_string())
            .execute();
        let link = links.try_next().await.unwrap();
        (handle, link.unwrap(), netns)
    }

    async fn test_async_new_htb_qdisc() {
        let (handle, test_link, _netns) = setup_env().await;
        handle
            .qdisc()
            .add(test_link.header.index as i32)
            .root()
            .handle(0x8001, 0)
            .htb()
            .default(0x30)
            .execute()
            .await
            .unwrap();

        handle
            .traffic_class(test_link.header.index as i32)
            .add()
            .class_id(0x8001, 1)
            .parent(0x8001, 0)
            .htb()
            .rate(20)
            .ceil(20)
            .execute()
            .await
            .unwrap();

        let mut iter = handle
            .traffic_class(test_link.header.index as i32)
            .get()
            .execute();

        let mut found = false;
        while let Some(nl_msg) = iter.try_next().await.unwrap() {
            if nl_msg.header.index == test_link.header.index as i32
                && nl_msg.header.handle == TC_H_MAKE!(0x8001 << 16, 1)
            {
                assert_eq!(nl_msg.header.family, AF_UNSPEC as u8);
                assert_eq!(nl_msg.header.handle, TC_H_MAKE!(0x8001 << 16, 1));
                assert_eq!(nl_msg.header.parent, TC_H_ROOT);
                assert_eq!(nl_msg.header.info, 0);
                found = true;
                break;
            }
        }
        if !found {
            panic!("not found dev:{} class.", test_link.header.index);
        }
    }

    #[test]
    fn test_new_htb_qdisc() {
        Runtime::new().unwrap().block_on(test_async_new_htb_qdisc());
    }
}

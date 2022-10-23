use std::iter::Peekable;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use hex;
use ipnet::IpNet;
use netlink_packet_xfrm::constants::*;
use thiserror::Error;

#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum CliError {
    #[error("Invalid command: {0:?}")]
    InvalidCommand(String),

    #[error("Failed to parse an IP address: {0:?}")]
    InvalidIp(String),

    #[error("Failed to parse a network address (IP and mask): {0:?}/{1:?}")]
    InvalidAddress(String, String),

    #[error("Mismatched address families: {0:?} {1:?}")]
    MismatchedAddressFamily(String, String),

    #[error("Failed to parse argument: '{0}'")]
    InvalidArg(String),

    #[error("Failed to parse argument as hex: '{0}'")]
    InvalidHexArg(String),
}

#[derive(Debug)]
pub struct PolicyAddUpdCliArgs {
    pub update: bool,
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub dev_id: Option<u32>,
    pub direction: u8,
    pub action: u8,
    pub ptype: Option<u8>,
    pub secctx: Option<Vec<u8>>,
    pub proto_num: Option<u8>,
    pub proto_src_port: Option<u16>,
    pub proto_dst_port: Option<u16>,
    pub proto_type: Option<u8>,
    pub proto_code: Option<u8>,
    pub gre_key: Option<u32>,
    pub index: Option<u32>,
    pub priority: Option<u32>,
    pub ifid: Option<u32>,
    pub flags: Option<u8>,
    pub mark_and_mask: Option<(u32, u32)>,
    pub time_limits: Option<(u64, u64)>,
    pub time_use_limits: Option<(u64, u64)>,
    pub byte_limits: Option<(u64, u64)>,
    pub packet_limits: Option<(u64, u64)>,
    pub templates: Vec<PolicyTmplArgs>,
}

#[derive(Debug, Default)]
pub struct PolicyTmplArgs {
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub proto: u8,
    pub spi: u32,
    pub mode: u8,
    pub reqid: u32,
    pub optional: bool,
}

#[derive(Debug, Default)]
pub struct PolicyProtoArgs {
    pub proto_num: Option<u8>,
    pub proto_src_port: Option<u16>,
    pub proto_dst_port: Option<u16>,
    pub proto_type: Option<u8>,
    pub proto_code: Option<u8>,
    pub gre_key: Option<u32>,
}

fn parse_ipnet_arg(ip: &String) -> Result<IpNet, CliError> {
    let ipnet_addr: IpNet;

    // IpNet can only parse IP/prefix formats, it can't handle
    // just IP or IP/IPmask formats.
    if let Ok(ip_addr_net) = IpNet::from_str(ip) {
        ipnet_addr = ip_addr_net;
    } else if let Ok(ip_addr) = IpAddr::from_str(ip) {
        let prefix = if ip_addr.is_ipv4() { 32 } else { 128 };
        ipnet_addr =
            IpNet::new(ip_addr, prefix).map_err(|_| CliError::InvalidIp(ip.to_string()))?;
    } else if let Some(_slash) = ip.find('/') {
        let v: Vec<&str> = ip.split('/').collect();
        if v.len() == 2 {
            let network =
                IpAddr::from_str(v[0]).map_err(|_| CliError::InvalidIp(v[0].to_string()))?;
            let netmask =
                IpAddr::from_str(v[1]).map_err(|_| CliError::InvalidIp(v[1].to_string()))?;
            let mut prefix_len: Option<u32> = None;

            // If the netmask is valid, the number of leading ones
            // will be the prefix length.
            match netmask {
                IpAddr::V4(mask) => {
                    let mask_32: u32 = mask.into();
                    if mask_32.leading_ones() == mask_32.count_ones() {
                        prefix_len = Some(mask_32.leading_ones());
                    }
                }
                IpAddr::V6(mask) => {
                    let mask_128: u128 = mask.into();
                    if mask_128.leading_ones() == mask_128.count_ones() {
                        prefix_len = Some(mask_128.leading_ones());
                    }
                }
            }
            if prefix_len.is_none() {
                return Err(CliError::InvalidAddress(v[0].to_string(), v[1].to_string()));
            }

            if (network.is_ipv4() && netmask.is_ipv4()) || (network.is_ipv6() && netmask.is_ipv6())
            {
                ipnet_addr = IpNet::new(network, prefix_len.unwrap() as u8)
                    .map_err(|_| CliError::InvalidAddress(v[0].to_string(), v[1].to_string()))?;
            } else {
                return Err(CliError::MismatchedAddressFamily(
                    v[0].to_string(),
                    v[1].to_string(),
                ));
            }
        } else {
            return Err(CliError::InvalidArg(ip.to_string()));
        }
    } else {
        match ip.to_lowercase().as_str() {
            "all" | "any" | "all4" | "any4" => {
                ipnet_addr = IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32)
                    .map_err(|_| CliError::InvalidArg(ip.to_string()))?;
            }
            "all6" | "any6" => {
                ipnet_addr = IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128)
                    .map_err(|_| CliError::InvalidArg(ip.to_string()))?;
            }
            _ => {
                return Err(CliError::InvalidIp(ip.to_string()));
            }
        }
    }
    return Ok(ipnet_addr);
}

fn parse_proto_arg<'a>(
    it: &mut Peekable<impl Iterator<Item = (usize, &'a String)>>,
) -> PolicyProtoArgs {
    let mut proto_num: Option<u8> = None;
    let mut proto_src_port: Option<u16> = None;
    let mut proto_dst_port: Option<u16> = None;
    let mut proto_type: Option<u8> = None;
    let mut proto_code: Option<u8> = None;
    let mut gre_key: Option<u32> = None;

    if let Some((_p, proto)) = it.next() {
        match proto.as_str() {
            "tcp" => proto_num = Some(IPPROTO_TCP),
            "udp" => proto_num = Some(IPPROTO_UDP),
            "sctp" => proto_num = Some(IPPROTO_SCTP),
            "dccp" => proto_num = Some(IPPROTO_DCCP),
            "icmp" => proto_num = Some(IPPROTO_ICMP),
            "ipv6-icmp" => proto_num = Some(IPPROTO_ICMPV6),
            "mobility-header" => proto_num = Some(IPPROTO_MH),
            "gre" => proto_num = Some(IPPROTO_GRE),
            _ => {
                // Try converting as a regular number
                if let Ok(pn) = proto.parse::<u8>() {
                    proto_num = Some(pn);
                }
            }
        }

        match proto_num {
            Some(IPPROTO_TCP) | Some(IPPROTO_UDP) | Some(IPPROTO_SCTP) | Some(IPPROTO_DCCP) => {
                // parse ports (16-bit values)
                while let Some((_p, port)) = it.peek() {
                    match port.as_str() {
                        "sport" => {
                            it.next();
                            if let Some((_p, sport)) = it.next() {
                                if let Ok(sp) = sport.parse::<u16>() {
                                    proto_src_port = Some(sp);
                                }
                            }
                        }
                        "dport" => {
                            it.next();
                            if let Some((_p, dport)) = it.next() {
                                if let Ok(dp) = dport.parse::<u16>() {
                                    proto_dst_port = Some(dp);
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }

            Some(IPPROTO_ICMP) | Some(IPPROTO_ICMPV6) | Some(IPPROTO_MH) => {
                // parse type and code (8-bit values)
                while let Some((_p, tc)) = it.peek() {
                    match tc.as_str() {
                        "type" => {
                            it.next();
                            if let Some((_p, t)) = it.next() {
                                if let Ok(type_8) = t.parse::<u8>() {
                                    proto_type = Some(type_8);
                                }
                            }
                        }
                        "code" => {
                            it.next();
                            if let Some((_p, c)) = it.next() {
                                if let Ok(code_8) = c.parse::<u8>() {
                                    proto_code = Some(code_8);
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }

            Some(IPPROTO_GRE) => {
                // parse key from either a dotted quad IPv4 form, or a regular u32
                while let Some((_p, k)) = it.peek() {
                    match k.as_str() {
                        "key" => {
                            it.next();
                            if let Some((_p, ks)) = it.next() {
                                if let Ok(key_32) = ks.parse::<u32>() {
                                    gre_key = Some(key_32);
                                } else if let Ok(ip_addr) = Ipv4Addr::from_str(ks) {
                                    gre_key = Some(ip_addr.into());
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }

            None => (),
            _ => (),
        }
    }

    PolicyProtoArgs {
        proto_num,
        proto_src_port,
        proto_dst_port,
        proto_type,
        proto_code,
        gre_key,
    }
}

fn parse_hex_data(hex_str: &str) -> Result<Vec<u8>, CliError> {
    let mut pos = 0;
    if hex_str.len() > 2 && hex_str.starts_with("0x") {
        pos = 2;
    }
    return Ok(
        hex::decode(&hex_str[pos..]).map_err(|_| CliError::InvalidHexArg(hex_str.to_string()))?
    );
}

#[allow(dead_code)]
pub(crate) fn policy_add_upd_parse_args(
    args: &Vec<String>,
) -> Result<PolicyAddUpdCliArgs, CliError> {
    let mut update: bool = false;
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();
    let mut dev_id: Option<u32> = None;
    let mut direction: Option<u8> = None;
    let mut action: u8 = XFRM_POLICY_ALLOW;
    let mut ptype: Option<u8> = None;
    let mut secctx: Option<Vec<u8>> = None;
    let mut proto_args: PolicyProtoArgs = Default::default();
    let mut index: Option<u32> = None;
    let mut priority: Option<u32> = None;
    let mut ifid: Option<u32> = None;
    let mut flags: Option<u8> = None;
    let mut mark_and_mask: Option<(u32, u32)> = None;
    let mut time_limits: Option<(u64, u64)> = None;
    let mut time_use_limits: Option<(u64, u64)> = None;
    let mut byte_limits: Option<(u64, u64)> = None;
    let mut packet_limits: Option<(u64, u64)> = None;
    let mut templates: Vec<PolicyTmplArgs> = Default::default();

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    if let Some((_pos, command)) = it.next() {
        match command.as_str() {
            "add" => (),
            "update" => update = true,
            _ => return Err(CliError::InvalidCommand(command.to_string())),
        }
    }

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dev" => {
                // iproute2 allows specifying the interface by name,
                // but that requires an extra kernel lookup to convert
                // the interface name to an id. See rtnetlink examples
                // for how to do that. This just allows specifying the
                // interface number and converts from str to u32 (or
                // the special value "none" to 0).
                if let Some((_p, dev)) = it.next() {
                    match dev.as_str() {
                        "none" => dev_id = Some(0),
                        _ => {
                            if let Ok(dev_32) = dev.parse::<u32>() {
                                dev_id = Some(dev_32);
                            }
                        }
                    }
                }
            }
            "dir" => {
                if let Some((_p, dir)) = it.next() {
                    match dir.as_str() {
                        "in" => direction = Some(XFRM_POLICY_IN),
                        "out" => direction = Some(XFRM_POLICY_OUT),
                        "fwd" => direction = Some(XFRM_POLICY_FWD),
                        _ => (),
                    }
                }
            }
            "action" => {
                if let Some((_p, act)) = it.next() {
                    match act.as_str() {
                        "allow" => action = XFRM_POLICY_ALLOW,
                        "block" => action = XFRM_POLICY_BLOCK,
                        _ => (),
                    }
                }
            }
            "ptype" => {
                if let Some((_p, pt)) = it.next() {
                    match pt.as_str() {
                        "main" => ptype = Some(XFRM_POLICY_TYPE_MAIN),
                        "sub" => ptype = Some(XFRM_POLICY_TYPE_SUB),
                        _ => (),
                    }
                }
            }
            "ctx" => {
                if let Some((_p, ctx)) = it.next() {
                    secctx = Some(ctx.to_owned().into_bytes());
                }
            }
            "mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            "index" => {
                if let Some((_p, idx)) = it.next() {
                    if let Ok(idx_32) = idx.parse::<u32>() {
                        index = Some(idx_32);
                    }
                }
            }
            "priority" => {
                if let Some((_p, pri)) = it.next() {
                    if let Ok(pri_32) = pri.parse::<u32>() {
                        priority = Some(pri_32);
                    }
                }
            }
            "flag" => {
                while let Some((_p, fl)) = it.peek() {
                    match fl.as_str() {
                        "localok" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_POLICY_LOCALOK);
                            } else {
                                flags = Some(XFRM_POLICY_LOCALOK);
                            }
                        }
                        "icmp" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_POLICY_ICMP);
                            } else {
                                flags = Some(XFRM_POLICY_ICMP);
                            }
                        }
                        _ => {
                            if fl.len() > 2 && fl.starts_with("0x") {
                                if let Ok(flag) = u8::from_str_radix(&fl.as_str()[2..], 16) {
                                    // Explicitly setting a hex flag overwrites any existing
                                    // value, but any subsequent "flag" args with known flags
                                    // "localok", "icmp", will be OR'd with this value.
                                    it.next();
                                    flags = Some(flag);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "if_id" => {
                if let Some((_p, id)) = it.next() {
                    if let Ok(ifid_32) = id.parse::<u32>() {
                        ifid = Some(ifid_32);
                    }
                }
            }
            "proto" => {
                proto_args = parse_proto_arg(&mut it);
            }
            "limit" => {
                if let Some((_p, lim)) = it.next() {
                    match lim.as_str() {
                        "time-soft" => {
                            if let Some((_p, ts)) = it.next() {
                                if let Ok(ts_64) = ts.parse::<u64>() {
                                    if let Some(lims) = time_limits {
                                        time_limits = Some((ts_64, lims.1));
                                    } else {
                                        time_limits = Some((ts_64, 0));
                                    }
                                }
                            }
                        }
                        "time-hard" => {
                            if let Some((_p, th)) = it.next() {
                                if let Ok(th_64) = th.parse::<u64>() {
                                    if let Some(lims) = time_limits {
                                        time_limits = Some((lims.0, th_64));
                                    } else {
                                        time_limits = Some((0, th_64));
                                    }
                                }
                            }
                        }
                        "time-use-soft" => {
                            if let Some((_p, ts)) = it.next() {
                                if let Ok(ts_64) = ts.parse::<u64>() {
                                    if let Some(lims) = time_use_limits {
                                        time_use_limits = Some((ts_64, lims.1));
                                    } else {
                                        time_use_limits = Some((ts_64, 0));
                                    }
                                }
                            }
                        }
                        "time-use-hard" => {
                            if let Some((_p, th)) = it.next() {
                                if let Ok(th_64) = th.parse::<u64>() {
                                    if let Some(lims) = time_use_limits {
                                        time_use_limits = Some((lims.0, th_64));
                                    } else {
                                        time_use_limits = Some((0, th_64));
                                    }
                                }
                            }
                        }
                        "byte-soft" => {
                            if let Some((_p, bs)) = it.next() {
                                if let Ok(bs_64) = bs.parse::<u64>() {
                                    if let Some(lims) = byte_limits {
                                        byte_limits = Some((bs_64, lims.1));
                                    } else {
                                        byte_limits = Some((bs_64, u64::MAX));
                                    }
                                }
                            }
                        }
                        "byte-hard" => {
                            if let Some((_p, bh)) = it.next() {
                                if let Ok(bh_64) = bh.parse::<u64>() {
                                    if let Some(lims) = byte_limits {
                                        byte_limits = Some((lims.0, bh_64));
                                    } else {
                                        byte_limits = Some((u64::MAX, bh_64));
                                    }
                                }
                            }
                        }
                        "packet-soft" => {
                            if let Some((_p, ps)) = it.next() {
                                if let Ok(ps_64) = ps.parse::<u64>() {
                                    if let Some(lims) = packet_limits {
                                        packet_limits = Some((ps_64, lims.1));
                                    } else {
                                        packet_limits = Some((ps_64, u64::MAX));
                                    }
                                }
                            }
                        }
                        "packet-hard" => {
                            if let Some((_p, ph)) = it.next() {
                                if let Ok(ph_64) = ph.parse::<u64>() {
                                    if let Some(lims) = packet_limits {
                                        packet_limits = Some((lims.0, ph_64));
                                    } else {
                                        packet_limits = Some((u64::MAX, ph_64));
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
            "tmpl" => {
                let mut tmpl_args: PolicyTmplArgs = PolicyTmplArgs::default();

                while let Some((_p, tmpl)) = it.peek() {
                    match tmpl.as_str() {
                        "src" => {
                            it.next();
                            if let Some((_p, ip)) = it.next() {
                                tmpl_args.src_addr = parse_ipnet_arg(ip)?;
                            }
                        }
                        "dst" => {
                            it.next();
                            if let Some((_p, ip)) = it.next() {
                                tmpl_args.dst_addr = parse_ipnet_arg(ip)?;
                            }
                        }
                        "proto" => {
                            // this should be a required option
                            it.next();
                            if let Some((_p, proto)) = it.next() {
                                match proto.as_str() {
                                    "esp" => tmpl_args.proto = IPPROTO_ESP,
                                    "ah" => tmpl_args.proto = IPPROTO_AH,
                                    "comp" => tmpl_args.proto = IPPROTO_COMP,
                                    "route2" => tmpl_args.proto = IPPROTO_ROUTING,
                                    "hao" => tmpl_args.proto = IPPROTO_DSTOPTS,
                                    "ipsec-any" => tmpl_args.proto = IPSEC_PROTO_ANY,
                                    _ => (),
                                }
                            }
                        }
                        "spi" => {
                            it.next();
                            if let Some((_p, spi)) = it.next() {
                                if let Ok(spi_32) = spi.parse::<u32>() {
                                    tmpl_args.spi = spi_32;
                                }
                            }
                        }
                        "mode" => {
                            it.next();
                            if let Some((_p, mode)) = it.next() {
                                match mode.as_str() {
                                    "transport" => tmpl_args.mode = XFRM_MODE_TRANSPORT,
                                    "tunnel" => tmpl_args.mode = XFRM_MODE_TUNNEL,
                                    "ro" => tmpl_args.mode = XFRM_MODE_ROUTEOPTIMIZATION,
                                    "in_trigger" => tmpl_args.mode = XFRM_MODE_IN_TRIGGER,
                                    "beet" => tmpl_args.mode = XFRM_MODE_BEET,
                                    _ => (),
                                }
                            }
                        }
                        "reqid" => {
                            it.next();
                            if let Some((_p, reqid)) = it.next() {
                                if let Ok(reqid_32) = reqid.parse::<u32>() {
                                    tmpl_args.reqid = reqid_32;
                                }
                            }
                        }
                        "level" => {
                            it.next();
                            if let Some((_p, lvl)) = it.next() {
                                match lvl.as_str() {
                                    "required" => tmpl_args.optional = false,
                                    "use" => tmpl_args.optional = true,
                                    _ => (),
                                }
                            }
                        }
                        _ => break,
                    }
                }

                //println!("{:#?}", tmpl_args);
                if tmpl_args.proto != 0 {
                    templates.push(tmpl_args);
                }
            }

            _ => println!("Unknown option[{}]:'{}'", _pos, arg),
        }
    }

    if direction.is_none() {
        return Err(CliError::InvalidArg("Direction is not set".to_string()));
    }

    Ok(PolicyAddUpdCliArgs {
        update,
        src_addr,
        dst_addr,
        dev_id,
        direction: direction.unwrap(),
        action,
        ptype,
        secctx,
        proto_num: proto_args.proto_num,
        proto_src_port: proto_args.proto_src_port,
        proto_dst_port: proto_args.proto_dst_port,
        proto_type: proto_args.proto_type,
        proto_code: proto_args.proto_code,
        gre_key: proto_args.gre_key,
        index,
        priority,
        ifid,
        flags,
        mark_and_mask,
        time_limits,
        time_use_limits,
        byte_limits,
        packet_limits,
        templates,
    })
}

#[derive(Debug)]
pub struct PolicyDelGetCliArgs {
    pub get: bool,
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub dev_id: Option<u32>,
    pub direction: u8,
    pub ptype: Option<u8>,
    pub secctx: Option<Vec<u8>>,
    pub proto_num: Option<u8>,
    pub proto_src_port: Option<u16>,
    pub proto_dst_port: Option<u16>,
    pub proto_type: Option<u8>,
    pub proto_code: Option<u8>,
    pub gre_key: Option<u32>,
    pub index: Option<u32>,
    pub ifid: Option<u32>,
    pub mark_and_mask: Option<(u32, u32)>,
}

#[allow(dead_code)]
pub(crate) fn policy_del_get_parse_args(
    args: &Vec<String>,
) -> Result<PolicyDelGetCliArgs, CliError> {
    let mut get: bool = false;
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();
    let mut dev_id: Option<u32> = None;
    let mut direction: Option<u8> = None;
    let mut ptype: Option<u8> = None;
    let mut secctx: Option<Vec<u8>> = None;
    let mut proto_args: PolicyProtoArgs = Default::default();
    let mut index: Option<u32> = None;
    let mut ifid: Option<u32> = None;
    let mut mark_and_mask: Option<(u32, u32)> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    if let Some((_pos, command)) = it.next() {
        match command.as_str() {
            "delete" => (),
            "get" => get = true,
            _ => return Err(CliError::InvalidCommand(command.to_string())),
        }
    }

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dev" => {
                if let Some((_p, dev)) = it.next() {
                    match dev.as_str() {
                        "none" => dev_id = Some(0),
                        _ => {
                            if let Ok(dev_32) = dev.parse::<u32>() {
                                dev_id = Some(dev_32);
                            }
                        }
                    }
                }
            }
            "dir" => {
                if let Some((_p, dir)) = it.next() {
                    match dir.as_str() {
                        "in" => direction = Some(XFRM_POLICY_IN),
                        "out" => direction = Some(XFRM_POLICY_OUT),
                        "fwd" => direction = Some(XFRM_POLICY_FWD),
                        _ => (),
                    }
                }
            }
            "ptype" => {
                if let Some((_p, pt)) = it.next() {
                    match pt.as_str() {
                        "main" => ptype = Some(XFRM_POLICY_TYPE_MAIN),
                        "sub" => ptype = Some(XFRM_POLICY_TYPE_SUB),
                        _ => (),
                    }
                }
            }
            "ctx" => {
                if let Some((_p, ctx)) = it.next() {
                    secctx = Some(ctx.to_owned().into_bytes());
                }
            }
            "mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            "index" => {
                if let Some((_p, idx)) = it.next() {
                    if let Ok(idx_32) = idx.parse::<u32>() {
                        index = Some(idx_32);
                    }
                }
            }
            "if_id" => {
                if let Some((_p, id)) = it.next() {
                    if let Ok(ifid_32) = id.parse::<u32>() {
                        ifid = Some(ifid_32);
                    }
                }
            }
            "proto" => {
                proto_args = parse_proto_arg(&mut it);
            }

            _ => println!("Unknown option[{}]:'{}'", _pos, arg),
        }
    }

    //println!("src={:?} dst={:?}", src_addr, dst_addr);

    if direction.is_none() {
        return Err(CliError::InvalidArg("Direction is not set".to_string()));
    }

    Ok(PolicyDelGetCliArgs {
        get,
        src_addr,
        dst_addr,
        dev_id,
        direction: direction.unwrap(),
        ptype,
        secctx,
        proto_num: proto_args.proto_num,
        proto_src_port: proto_args.proto_src_port,
        proto_dst_port: proto_args.proto_dst_port,
        proto_type: proto_args.proto_type,
        proto_code: proto_args.proto_code,
        gre_key: proto_args.gre_key,
        index,
        ifid,
        mark_and_mask,
    })
}

#[derive(Debug)]
pub struct PolicyFlushCliArgs {
    pub ptype: Option<u8>,
}

#[allow(dead_code)]
pub(crate) fn policy_flush_parse_args(args: &Vec<String>) -> Result<PolicyFlushCliArgs, CliError> {
    let mut ptype: Option<u8> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "ptype" => {
                if let Some((_p, pt)) = it.next() {
                    match pt.as_str() {
                        "main" => ptype = Some(XFRM_POLICY_TYPE_MAIN),
                        "sub" => ptype = Some(XFRM_POLICY_TYPE_SUB),
                        _ => (),
                    }
                }
            }

            _ => return Err(CliError::InvalidArg(arg.to_string())),
        }
    }

    Ok(PolicyFlushCliArgs { ptype })
}

#[derive(Debug)]
pub struct PolicySpdCliArgs {
    pub hthresh4: Option<(u8, u8)>,
    pub hthresh6: Option<(u8, u8)>,
}

#[allow(dead_code)]
pub(crate) fn policy_spd_parse_args(args: &Vec<String>) -> Result<PolicySpdCliArgs, CliError> {
    let mut hthresh4: Option<(u8, u8)> = None;
    let mut hthresh6: Option<(u8, u8)> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "hthresh4" => {
                if let Some((_p, lbits)) = it.next() {
                    if let Ok(lbits_8) = lbits.parse::<u8>() {
                        if let Some((_p, rbits)) = it.next() {
                            if let Ok(rbits_8) = rbits.parse::<u8>() {
                                hthresh4 = Some((lbits_8, rbits_8));
                            }
                        }
                    }
                }
            }
            "hthresh6" => {
                if let Some((_p, lbits)) = it.next() {
                    if let Ok(lbits_8) = lbits.parse::<u8>() {
                        if let Some((_p, rbits)) = it.next() {
                            if let Ok(rbits_8) = rbits.parse::<u8>() {
                                hthresh6 = Some((lbits_8, rbits_8));
                            }
                        }
                    }
                }
            }

            _ => return Err(CliError::InvalidArg(arg.to_string())),
        }
    }

    if let Some((lbits4, rbits4)) = hthresh4 {
        if lbits4 > 32 || rbits4 > 32 {
            return Err(CliError::InvalidArg(
                "hthresh4 LBITS or RBITS > 32".to_string(),
            ));
        }
    }
    if let Some((lbits6, rbits6)) = hthresh6 {
        if lbits6 > 128 || rbits6 > 128 {
            return Err(CliError::InvalidArg(
                "hthresh6 LBITS or RBITS > 128".to_string(),
            ));
        }
    }

    Ok(PolicySpdCliArgs { hthresh4, hthresh6 })
}

#[derive(Debug)]
pub struct PolicyActionCliArgs {
    pub set_action: bool,
    pub in_action: Option<u8>,
    pub fwd_action: Option<u8>,
    pub out_action: Option<u8>,
}

#[allow(dead_code)]
pub(crate) fn policy_action_parse_args(
    args: &Vec<String>,
) -> Result<PolicyActionCliArgs, CliError> {
    let mut set_action: bool = false;
    let mut in_action: Option<u8> = None;
    let mut fwd_action: Option<u8> = None;
    let mut out_action: Option<u8> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    if let Some((_pos, command)) = it.next() {
        match command.as_str() {
            "get" => (),
            "set" => set_action = true,
            _ => return Err(CliError::InvalidCommand(command.to_string())),
        }
    }

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "in" => {
                if let Some((_p, act)) = it.next() {
                    match act.as_str() {
                        "allow" | "accept" => in_action = Some(XFRM_USERPOLICY_ACCEPT),
                        "block" => in_action = Some(XFRM_USERPOLICY_BLOCK),
                        _ => (),
                    }
                }
            }
            "fwd" => {
                if let Some((_p, act)) = it.next() {
                    match act.as_str() {
                        "allow" | "accept" => fwd_action = Some(XFRM_USERPOLICY_ACCEPT),
                        "block" => fwd_action = Some(XFRM_USERPOLICY_BLOCK),
                        _ => (),
                    }
                }
            }
            "out" => {
                if let Some((_p, act)) = it.next() {
                    match act.as_str() {
                        "allow" | "accept" => out_action = Some(XFRM_USERPOLICY_ACCEPT),
                        "block" => out_action = Some(XFRM_USERPOLICY_BLOCK),
                        _ => (),
                    }
                }
            }

            _ => println!("Unknown option[{}]:'{}'", _pos, arg),
        }
    }

    Ok(PolicyActionCliArgs {
        set_action,
        in_action,
        fwd_action,
        out_action,
    })
}

#[derive(Debug)]
pub struct StateAddUpdCliArgs {
    pub update: bool,
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub xfrm_proto: u8,
    pub spi: u32,
    pub enc_alg_name: Option<String>,
    pub enc_alg_key: Vec<u8>,
    pub auth_alg_name: Option<String>,
    pub auth_alg_key: Vec<u8>,
    pub auth_trunc_alg_name: Option<String>,
    pub auth_trunc_alg_key: Vec<u8>,
    pub auth_trunc_len: u32,
    pub aead_alg_name: Option<String>,
    pub aead_alg_key: Vec<u8>,
    pub aead_icv_len: u32,
    pub comp_alg_name: Option<String>,
    pub mode: Option<u8>,
    pub mark_and_mask: Option<(u32, u32)>,
    pub output_mark_and_mask: Option<(u32, u32)>,
    pub reqid: Option<u32>,
    pub secctx: Option<Vec<u8>>,
    pub seq: Option<u32>,
    pub replay_window: Option<u32>,
    pub replay_seq: Option<u32>,
    pub replay_oseq: Option<u32>,
    pub replay_seq_hi: Option<u32>,
    pub replay_oseq_hi: Option<u32>,
    pub selector_src_addr: Option<IpNet>,
    pub selector_dst_addr: Option<IpNet>,
    pub selector_dev_id: Option<u32>,
    pub selector_proto_num: Option<u8>,
    pub selector_proto_src_port: Option<u16>,
    pub selector_proto_dst_port: Option<u16>,
    pub selector_proto_type: Option<u8>,
    pub selector_proto_code: Option<u8>,
    pub selector_gre_key: Option<u32>,
    pub ifid: Option<u32>,
    pub flags: Option<u8>,
    pub extra_flags: Option<u32>,
    pub time_limits: Option<(u64, u64)>,
    pub time_use_limits: Option<(u64, u64)>,
    pub byte_limits: Option<(u64, u64)>,
    pub packet_limits: Option<(u64, u64)>,
    pub encap_type: Option<u16>,
    pub encap_sport: Option<u16>,
    pub encap_dport: Option<u16>,
    pub encap_oa: Option<IpNet>,
    pub care_of_addr: Option<IpNet>,
    pub offload_dev: Option<u32>,
    pub offload_dir: Option<u8>,
    pub tfcpad: Option<u32>,
}

#[allow(dead_code)]
pub(crate) fn state_add_upd_parse_args(args: &Vec<String>) -> Result<StateAddUpdCliArgs, CliError> {
    let mut update: bool = false;
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();
    let mut xfrm_proto: u8 = IPSEC_PROTO_ANY;
    let mut spi: u32 = 0;
    let mut enc_alg_name: Option<String> = None;
    let mut enc_alg_key: Vec<u8> = Vec::default();
    let mut auth_alg_name: Option<String> = None;
    let mut auth_alg_key: Vec<u8> = Vec::default();
    let mut auth_trunc_alg_name: Option<String> = None;
    let mut auth_trunc_alg_key: Vec<u8> = Vec::default();
    let mut auth_trunc_len: u32 = 0;
    let mut aead_alg_name: Option<String> = None;
    let mut aead_alg_key: Vec<u8> = Vec::default();
    let mut aead_icv_len: u32 = 0;
    let mut comp_alg_name: Option<String> = None;
    let mut mode: Option<u8> = None;
    let mut mark_and_mask: Option<(u32, u32)> = None;
    let mut output_mark_and_mask: Option<(u32, u32)> = None;
    let mut reqid: Option<u32> = None;
    let mut secctx: Option<Vec<u8>> = None;
    let mut seq: Option<u32> = None;
    let mut replay_window: Option<u32> = None;
    let mut replay_seq: Option<u32> = None;
    let mut replay_oseq: Option<u32> = None;
    let mut replay_seq_hi: Option<u32> = None;
    let mut replay_oseq_hi: Option<u32> = None;
    let mut selector_src_addr: Option<IpNet> = None;
    let mut selector_dst_addr: Option<IpNet> = None;
    let mut selector_dev_id: Option<u32> = None;
    let mut selector_proto_args: PolicyProtoArgs = Default::default();
    let mut ifid: Option<u32> = None;
    let mut flags: Option<u8> = None;
    let mut extra_flags: Option<u32> = None;
    let mut time_limits: Option<(u64, u64)> = None;
    let mut time_use_limits: Option<(u64, u64)> = None;
    let mut byte_limits: Option<(u64, u64)> = None;
    let mut packet_limits: Option<(u64, u64)> = None;
    let mut encap_type: Option<u16> = None;
    let mut encap_sport: Option<u16> = None;
    let mut encap_dport: Option<u16> = None;
    let mut encap_oa: Option<IpNet> = None;
    let mut care_of_addr: Option<IpNet> = None;
    let mut offload_dev: Option<u32> = None;
    let mut offload_dir: Option<u8> = None;
    let mut tfcpad: Option<u32> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    if let Some((_pos, command)) = it.next() {
        match command.as_str() {
            "add" => (),
            "update" => update = true,
            _ => return Err(CliError::InvalidCommand(command.to_string())),
        }
    }

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }
            "proto" => {
                if let Some((_p, proto)) = it.next() {
                    match proto.as_str() {
                        "esp" => xfrm_proto = IPPROTO_ESP,
                        "ah" => xfrm_proto = IPPROTO_AH,
                        "comp" => xfrm_proto = IPPROTO_COMP,
                        "route2" => xfrm_proto = IPPROTO_ROUTING,
                        "hao" => xfrm_proto = IPPROTO_DSTOPTS,
                        "ipsec-any" => xfrm_proto = IPSEC_PROTO_ANY,
                        _ => (),
                    }
                }
            }
            "spi" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        spi = s_32;
                    }
                }
            }
            "enc" => {
                if let Some((_p, name)) = it.next() {
                    enc_alg_name = Some(name.to_string());

                    if let Some((_p, key)) = it.next() {
                        enc_alg_key = parse_hex_data(key)?
                    }
                }
            }
            "auth" => {
                if let Some((_p, name)) = it.next() {
                    auth_alg_name = Some(name.to_string());

                    if let Some((_p, key)) = it.next() {
                        auth_alg_key = parse_hex_data(key)?
                    }
                }
            }
            "auth-trunc" => {
                if let Some((_p, name)) = it.next() {
                    auth_trunc_alg_name = Some(name.to_string());

                    if let Some((_p, key)) = it.next() {
                        auth_trunc_alg_key = parse_hex_data(key)?
                    }

                    if let Some((_p, l)) = it.next() {
                        if let Ok(t_32) = l.parse::<u32>() {
                            auth_trunc_len = t_32;
                        }
                    }
                }
            }
            "aead" => {
                if let Some((_p, name)) = it.next() {
                    aead_alg_name = Some(name.to_string());

                    if let Some((_p, key)) = it.next() {
                        aead_alg_key = parse_hex_data(key)?
                    }

                    if let Some((_p, i)) = it.next() {
                        if let Ok(i_32) = i.parse::<u32>() {
                            aead_icv_len = i_32;
                        }
                    }
                }
            }
            "comp" => {
                if let Some((_p, name)) = it.next() {
                    comp_alg_name = Some(name.to_string());
                }
            }
            "mode" => {
                if let Some((_p, m)) = it.next() {
                    match m.as_str() {
                        "transport" => mode = Some(XFRM_MODE_TRANSPORT),
                        "tunnel" => mode = Some(XFRM_MODE_TUNNEL),
                        "ro" => mode = Some(XFRM_MODE_ROUTEOPTIMIZATION),
                        "in_trigger" => mode = Some(XFRM_MODE_IN_TRIGGER),
                        "beet" => mode = Some(XFRM_MODE_BEET),
                        _ => (),
                    }
                }
            }
            "mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            "output-mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        output_mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            output_mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            "reqid" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        reqid = Some(r_32);
                    }
                }
            }
            "ctx" => {
                if let Some((_p, ctx)) = it.next() {
                    secctx = Some(ctx.to_owned().into_bytes());
                }
            }
            "seq" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        seq = Some(s_32);
                    }
                }
            }
            "replay-window" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        replay_window = Some(r_32);
                    }
                }
            }
            "replay-seq" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        replay_seq = Some(r_32);
                    }
                }
            }
            "replay-oseq" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        replay_oseq = Some(r_32);
                    }
                }
            }
            "replay-seq-hi" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        replay_seq_hi = Some(r_32);
                    }
                }
            }
            "replay-oseq-hi" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        replay_oseq_hi = Some(r_32);
                    }
                }
            }
            "flag" => {
                while let Some((_p, fl)) = it.peek() {
                    match fl.as_str() {
                        "noecn" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_NOECN);
                            } else {
                                flags = Some(XFRM_STATE_NOECN);
                            }
                        }
                        "decap-dscp" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_DECAP_DSCP);
                            } else {
                                flags = Some(XFRM_STATE_DECAP_DSCP);
                            }
                        }
                        "nopmtudisc" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_NOPMTUDISC);
                            } else {
                                flags = Some(XFRM_STATE_NOPMTUDISC);
                            }
                        }
                        "wildrecv" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_WILDRECV);
                            } else {
                                flags = Some(XFRM_STATE_WILDRECV);
                            }
                        }
                        "icmp" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_ICMP);
                            } else {
                                flags = Some(XFRM_STATE_ICMP);
                            }
                        }
                        "af-unspec" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_AF_UNSPEC);
                            } else {
                                flags = Some(XFRM_STATE_AF_UNSPEC);
                            }
                        }
                        "align4" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_ALIGN4);
                            } else {
                                flags = Some(XFRM_STATE_ALIGN4);
                            }
                        }
                        "esn" => {
                            it.next();
                            if let Some(flag) = flags {
                                flags = Some(flag | XFRM_STATE_ESN);
                            } else {
                                flags = Some(XFRM_STATE_ESN);
                            }
                        }
                        _ => {
                            if fl.len() > 2 && fl.starts_with("0x") {
                                if let Ok(flag) = u8::from_str_radix(&fl.as_str()[2..], 16) {
                                    // Explicitly setting a hex flag overwrites any existing
                                    // value, but any subsequent "flag" args with known flags
                                    // will be OR'd with this value.
                                    it.next();
                                    flags = Some(flag);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "extra-flag" => {
                while let Some((_p, fl)) = it.peek() {
                    match fl.as_str() {
                        "dont-encap-dscp" => {
                            it.next();
                            if let Some(flag) = extra_flags {
                                extra_flags = Some(flag | XFRM_SA_XFLAG_DONT_ENCAP_DSCP);
                            } else {
                                extra_flags = Some(XFRM_SA_XFLAG_DONT_ENCAP_DSCP);
                            }
                        }
                        "oseq-may-wrap" => {
                            it.next();
                            if let Some(flag) = extra_flags {
                                extra_flags = Some(flag | XFRM_SA_XFLAG_OSEQ_MAY_WRAP);
                            } else {
                                extra_flags = Some(XFRM_SA_XFLAG_OSEQ_MAY_WRAP);
                            }
                        }
                        _ => {
                            if fl.len() > 2 && fl.starts_with("0x") {
                                if let Ok(flag) = u32::from_str_radix(&fl.as_str()[2..], 16) {
                                    // Explicitly setting a hex flag overwrites any existing
                                    // value, but any subsequent "flag" args with known flags
                                    // will be OR'd with this value.
                                    it.next();
                                    extra_flags = Some(flag);
                                }
                            }
                            break;
                        }
                    }
                }
            }
            "sel" => {
                while let Some((_p, s)) = it.peek() {
                    match s.as_str() {
                        "src" => {
                            it.next();
                            if let Some((_p, ip)) = it.next() {
                                selector_src_addr = Some(parse_ipnet_arg(ip)?);
                            }
                        }
                        "dst" => {
                            it.next();
                            if let Some((_p, ip)) = it.next() {
                                selector_dst_addr = Some(parse_ipnet_arg(ip)?);
                            }
                        }
                        "dev" => {
                            it.next();
                            if let Some((_p, dev)) = it.next() {
                                match dev.as_str() {
                                    "none" => selector_dev_id = Some(0),
                                    _ => {
                                        if let Ok(dev_32) = dev.parse::<u32>() {
                                            selector_dev_id = Some(dev_32);
                                        }
                                    }
                                }
                            }
                        }
                        "proto" => {
                            it.next();
                            selector_proto_args = parse_proto_arg(&mut it);
                        }
                        _ => break,
                    }
                }
            }
            "if_id" => {
                if let Some((_p, id)) = it.next() {
                    if let Ok(ifid_32) = id.parse::<u32>() {
                        ifid = Some(ifid_32);
                    }
                }
            }
            "limit" => {
                if let Some((_p, lim)) = it.next() {
                    match lim.as_str() {
                        "time-soft" => {
                            if let Some((_p, ts)) = it.next() {
                                if let Ok(ts_64) = ts.parse::<u64>() {
                                    if let Some(lims) = time_limits {
                                        time_limits = Some((ts_64, lims.1));
                                    } else {
                                        time_limits = Some((ts_64, 0));
                                    }
                                }
                            }
                        }
                        "time-hard" => {
                            if let Some((_p, th)) = it.next() {
                                if let Ok(th_64) = th.parse::<u64>() {
                                    if let Some(lims) = time_limits {
                                        time_limits = Some((lims.0, th_64));
                                    } else {
                                        time_limits = Some((0, th_64));
                                    }
                                }
                            }
                        }
                        "time-use-soft" => {
                            if let Some((_p, ts)) = it.next() {
                                if let Ok(ts_64) = ts.parse::<u64>() {
                                    if let Some(lims) = time_use_limits {
                                        time_use_limits = Some((ts_64, lims.1));
                                    } else {
                                        time_use_limits = Some((ts_64, 0));
                                    }
                                }
                            }
                        }
                        "time-use-hard" => {
                            if let Some((_p, th)) = it.next() {
                                if let Ok(th_64) = th.parse::<u64>() {
                                    if let Some(lims) = time_use_limits {
                                        time_use_limits = Some((lims.0, th_64));
                                    } else {
                                        time_use_limits = Some((0, th_64));
                                    }
                                }
                            }
                        }
                        "byte-soft" => {
                            if let Some((_p, bs)) = it.next() {
                                if let Ok(bs_64) = bs.parse::<u64>() {
                                    if let Some(lims) = byte_limits {
                                        byte_limits = Some((bs_64, lims.1));
                                    } else {
                                        byte_limits = Some((bs_64, u64::MAX));
                                    }
                                }
                            }
                        }
                        "byte-hard" => {
                            if let Some((_p, bh)) = it.next() {
                                if let Ok(bh_64) = bh.parse::<u64>() {
                                    if let Some(lims) = byte_limits {
                                        byte_limits = Some((lims.0, bh_64));
                                    } else {
                                        byte_limits = Some((u64::MAX, bh_64));
                                    }
                                }
                            }
                        }
                        "packet-soft" => {
                            if let Some((_p, ps)) = it.next() {
                                if let Ok(ps_64) = ps.parse::<u64>() {
                                    if let Some(lims) = packet_limits {
                                        packet_limits = Some((ps_64, lims.1));
                                    } else {
                                        packet_limits = Some((ps_64, u64::MAX));
                                    }
                                }
                            }
                        }
                        "packet-hard" => {
                            if let Some((_p, ph)) = it.next() {
                                if let Ok(ph_64) = ph.parse::<u64>() {
                                    if let Some(lims) = packet_limits {
                                        packet_limits = Some((lims.0, ph_64));
                                    } else {
                                        packet_limits = Some((u64::MAX, ph_64));
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
            "encap" => {
                if let Some((_p, et)) = it.next() {
                    match et.as_str() {
                        "espinudp-nonike" => encap_type = Some(UDP_ENCAP_ESPINUDP_NON_IKE),
                        "espinudp" => encap_type = Some(UDP_ENCAP_ESPINUDP),
                        "espintcp" => encap_type = Some(TCP_ENCAP_ESPINTCP),
                        _ => (),
                    }
                    if encap_type.is_some() {
                        if let Some((_p, port)) = it.next() {
                            if let Ok(port_16) = port.parse::<u16>() {
                                encap_sport = Some(port_16);
                            }
                        }
                        if let Some((_p, port)) = it.next() {
                            if let Ok(port_16) = port.parse::<u16>() {
                                encap_dport = Some(port_16);
                            }
                        }
                        if let Some((_p, ip)) = it.next() {
                            encap_oa = Some(parse_ipnet_arg(ip)?);
                        }
                    }
                }
            }
            "coa" => {
                if let Some((_p, ip)) = it.next() {
                    care_of_addr = Some(parse_ipnet_arg(ip)?);
                }
            }
            "offload" => {
                while let Some((_p, o)) = it.peek() {
                    match o.as_str() {
                        "dev" => {
                            it.next();
                            if let Some((_p, dev)) = it.next() {
                                if let Ok(dev_32) = dev.parse::<u32>() {
                                    offload_dev = Some(dev_32);
                                }
                            }
                        }
                        "dir" => {
                            it.next();
                            if let Some((_p, dir)) = it.next() {
                                match dir.as_str() {
                                    "in" => offload_dir = Some(XFRM_OFFLOAD_INBOUND),
                                    "out" => offload_dir = Some(0),
                                    _ => break,
                                }
                            }
                        }
                        _ => break,
                    }
                }
            }
            "tfcpad" => {
                if let Some((_p, t)) = it.next() {
                    if let Ok(t_32) = t.parse::<u32>() {
                        tfcpad = Some(t_32);
                    }
                }
            }

            _ => println!("Unknown option[{}]:'{}'", _pos, arg),
        }
    }

    //println!("src={:?} dst={:?}", src_addr, dst_addr);

    Ok(StateAddUpdCliArgs {
        update,
        src_addr,
        dst_addr,
        xfrm_proto,
        spi,
        enc_alg_name,
        enc_alg_key,
        auth_alg_name,
        auth_alg_key,
        auth_trunc_alg_name,
        auth_trunc_alg_key,
        auth_trunc_len,
        aead_alg_name,
        aead_alg_key,
        aead_icv_len,
        comp_alg_name,
        mode,
        mark_and_mask,
        output_mark_and_mask,
        reqid,
        secctx,
        seq,
        replay_window,
        replay_seq,
        replay_oseq,
        replay_seq_hi,
        replay_oseq_hi,
        selector_src_addr,
        selector_dst_addr,
        selector_dev_id,
        selector_proto_num: selector_proto_args.proto_num,
        selector_proto_src_port: selector_proto_args.proto_src_port,
        selector_proto_dst_port: selector_proto_args.proto_dst_port,
        selector_proto_type: selector_proto_args.proto_type,
        selector_proto_code: selector_proto_args.proto_code,
        selector_gre_key: selector_proto_args.gre_key,
        ifid,
        flags,
        extra_flags,
        time_limits,
        time_use_limits,
        byte_limits,
        packet_limits,
        encap_type,
        encap_sport,
        encap_dport,
        encap_oa,
        care_of_addr,
        offload_dev,
        offload_dir,
        tfcpad,
    })
}

#[derive(Debug)]
pub struct StateDelGetCliArgs {
    pub delete: bool,
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub xfrm_proto: u8,
    pub spi: u32,
    pub mark_and_mask: Option<(u32, u32)>,
}

#[allow(dead_code)]
pub(crate) fn state_del_get_parse_args(args: &Vec<String>) -> Result<StateDelGetCliArgs, CliError> {
    let mut delete = true;
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();
    let mut xfrm_proto: u8 = IPSEC_PROTO_ANY;
    let mut spi: u32 = 0;
    let mut mark_and_mask: Option<(u32, u32)> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    if let Some((_pos, command)) = it.next() {
        match command.as_str() {
            "delete" => (),
            "get" => delete = false,
            _ => return Err(CliError::InvalidCommand(command.to_string())),
        }
    }

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }
            "proto" => {
                if let Some((_p, proto)) = it.next() {
                    match proto.as_str() {
                        "esp" => xfrm_proto = IPPROTO_ESP,
                        "ah" => xfrm_proto = IPPROTO_AH,
                        "comp" => xfrm_proto = IPPROTO_COMP,
                        "route2" => xfrm_proto = IPPROTO_ROUTING,
                        "hao" => xfrm_proto = IPPROTO_DSTOPTS,
                        "ipsec-any" => xfrm_proto = IPSEC_PROTO_ANY,
                        _ => (),
                    }
                }
            }
            "spi" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        spi = s_32;
                    }
                }
            }
            "mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }

            _ => println!("Unknown option[{}]:'{}'", _pos, arg),
        }
    }

    //println!("src={:?} dst={:?}", src_addr, dst_addr);

    Ok(StateDelGetCliArgs {
        delete,
        src_addr,
        dst_addr,
        xfrm_proto,
        spi,
        mark_and_mask,
    })
}

#[derive(Debug)]
pub struct StateDumpCliArgs {
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
}

#[allow(dead_code)]
pub(crate) fn state_dump_parse_args(args: &Vec<String>) -> Result<StateDumpCliArgs, CliError> {
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }

            _ => {
                return Err(CliError::InvalidArg(arg.to_string()));
            }
        }
    }

    //println!("src={:?} dst={:?}", src_addr, dst_addr);

    Ok(StateDumpCliArgs { src_addr, dst_addr })
}

#[derive(Debug)]
pub struct StateFlushCliArgs {
    pub protocol: Option<u8>,
}

#[allow(dead_code)]
pub(crate) fn state_flush_parse_args(args: &Vec<String>) -> Result<StateFlushCliArgs, CliError> {
    let mut protocol: Option<u8> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "proto" => {
                if let Some((_p, proto)) = it.next() {
                    match proto.as_str() {
                        "esp" => protocol = Some(IPPROTO_ESP),
                        "ah" => protocol = Some(IPPROTO_AH),
                        "comp" => protocol = Some(IPPROTO_COMP),
                        "route2" => protocol = Some(IPPROTO_ROUTING),
                        "hao" => protocol = Some(IPPROTO_DSTOPTS),
                        "ipsec-any" => protocol = Some(IPSEC_PROTO_ANY),
                        _ => (),
                    }
                }
            }

            _ => return Err(CliError::InvalidArg(arg.to_string())),
        }
    }

    Ok(StateFlushCliArgs { protocol })
}

#[derive(Debug)]
pub struct StateAllocSpiCliArgs {
    pub src_addr: IpNet,
    pub dst_addr: IpNet,
    pub protocol: u8,
    pub mode: Option<u8>,
    pub mark_and_mask: Option<(u32, u32)>,
    pub reqid: Option<u32>,
    pub seq: Option<u32>,
    pub ifid: Option<u32>,
    pub spi_min: Option<u32>,
    pub spi_max: Option<u32>,
}

#[allow(dead_code)]
pub(crate) fn state_alloc_spi_parse_args(
    args: &Vec<String>,
) -> Result<StateAllocSpiCliArgs, CliError> {
    let mut src_addr: IpNet = IpNet::default();
    let mut dst_addr: IpNet = IpNet::default();
    let mut protocol: u8 = IPSEC_PROTO_ANY;
    let mut mode: Option<u8> = None;
    let mut mark_and_mask: Option<(u32, u32)> = None;
    let mut reqid: Option<u32> = None;
    let mut seq: Option<u32> = None;
    let mut ifid: Option<u32> = None;
    let mut spi_min: Option<u32> = None;
    let mut spi_max: Option<u32> = None;

    let mut it = args.iter().enumerate().peekable();
    it.next(); // skip the executable name

    while let Some((_pos, arg)) = it.next() {
        //println!("arg[{}]='{}'", _pos, arg);

        match arg.as_str() {
            "src" => {
                if let Some((_p, ip)) = it.next() {
                    src_addr = parse_ipnet_arg(ip)?;
                }
            }
            "dst" => {
                if let Some((_p, ip)) = it.next() {
                    dst_addr = parse_ipnet_arg(ip)?;
                }
            }
            "proto" => {
                if let Some((_p, proto)) = it.next() {
                    match proto.as_str() {
                        "esp" => protocol = IPPROTO_ESP,
                        "ah" => protocol = IPPROTO_AH,
                        "comp" => protocol = IPPROTO_COMP,
                        "ipsec-any" => protocol = IPSEC_PROTO_ANY,
                        _ => (),
                    }
                }
            }
            "mode" => {
                if let Some((_p, m)) = it.next() {
                    match m.as_str() {
                        "transport" => mode = Some(XFRM_MODE_TRANSPORT),
                        "tunnel" => mode = Some(XFRM_MODE_TUNNEL),
                        "ro" => mode = Some(XFRM_MODE_ROUTEOPTIMIZATION),
                        "in_trigger" => mode = Some(XFRM_MODE_IN_TRIGGER),
                        "beet" => mode = Some(XFRM_MODE_BEET),
                        _ => (),
                    }
                }
            }
            "mark" => {
                if let Some((_p, mark)) = it.next() {
                    if let Ok(mark_32) = mark.parse::<u32>() {
                        mark_and_mask = Some((mark_32, u32::MAX));

                        if let Some((_p, m)) = it.peek() {
                            match m.as_str() {
                                "mask" => {
                                    it.next();
                                    if let Some((_p, mask)) = it.next() {
                                        if let Ok(mask_32) = mask.parse::<u32>() {
                                            mark_and_mask = Some((mark_32, mask_32));
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
            "reqid" => {
                if let Some((_p, r)) = it.next() {
                    if let Ok(r_32) = r.parse::<u32>() {
                        reqid = Some(r_32);
                    }
                }
            }
            "seq" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        seq = Some(s_32);
                    }
                }
            }
            "if_id" => {
                if let Some((_p, id)) = it.next() {
                    if let Ok(ifid_32) = id.parse::<u32>() {
                        ifid = Some(ifid_32);
                    }
                }
            }
            "min" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        spi_min = Some(s_32);
                    }
                }
            }
            "max" => {
                if let Some((_p, s)) = it.next() {
                    if let Ok(s_32) = s.parse::<u32>() {
                        spi_max = Some(s_32);
                    }
                }
            }

            _ => return Err(CliError::InvalidArg(arg.to_string())),
        }
    }

    Ok(StateAllocSpiCliArgs {
        src_addr,
        dst_addr,
        protocol,
        mode,
        mark_and_mask,
        reqid,
        seq,
        ifid,
        spi_min,
        spi_max,
    })
}

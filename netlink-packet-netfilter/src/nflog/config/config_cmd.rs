use netlink_packet_utils::nla::Nla;

const NFULA_CFG_CMD: u16 = libc::NFULA_CFG_CMD as u16;
const NFULNL_CFG_CMD_NONE: u8 = libc::NFULNL_CFG_CMD_NONE as u8;
const NFULNL_CFG_CMD_BIND: u8 = libc::NFULNL_CFG_CMD_BIND as u8;
const NFULNL_CFG_CMD_UNBIND: u8 = libc::NFULNL_CFG_CMD_UNBIND as u8;
const NFULNL_CFG_CMD_PF_BIND: u8 = libc::NFULNL_CFG_CMD_PF_BIND as u8;
const NFULNL_CFG_CMD_PF_UNBIND: u8 = libc::NFULNL_CFG_CMD_PF_UNBIND as u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigCmd {
    None,
    Bind,
    Unbind,
    PfBind,
    PfUnbind,
    Other(u8),
}

impl From<ConfigCmd> for u8 {
    fn from(cmd: ConfigCmd) -> Self {
        match cmd {
            ConfigCmd::None => NFULNL_CFG_CMD_NONE,
            ConfigCmd::Bind => NFULNL_CFG_CMD_BIND,
            ConfigCmd::Unbind => NFULNL_CFG_CMD_UNBIND,
            ConfigCmd::PfBind => NFULNL_CFG_CMD_PF_BIND,
            ConfigCmd::PfUnbind => NFULNL_CFG_CMD_PF_UNBIND,
            ConfigCmd::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for ConfigCmd {
    fn from(cmd: u8) -> Self {
        match cmd {
            NFULNL_CFG_CMD_NONE => ConfigCmd::None,
            NFULNL_CFG_CMD_BIND => ConfigCmd::Bind,
            NFULNL_CFG_CMD_UNBIND => ConfigCmd::Unbind,
            NFULNL_CFG_CMD_PF_BIND => ConfigCmd::PfBind,
            NFULNL_CFG_CMD_PF_UNBIND => ConfigCmd::PfUnbind,
            cmd => ConfigCmd::Other(cmd),
        }
    }
}

impl Nla for ConfigCmd {
    fn value_len(&self) -> usize {
        1
    }

    fn kind(&self) -> u16 {
        NFULA_CFG_CMD
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        buffer[0] = (*self).into();
    }
}

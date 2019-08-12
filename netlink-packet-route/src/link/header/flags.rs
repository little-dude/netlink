/// Link is up (administratively).
pub const IFF_UP: u32 = libc::IFF_UP as u32;
/// Link is up and carrier is OK (RFC2863 OPER_UP)
pub const IFF_RUNNING: u32 = libc::IFF_RUNNING as u32;
/// Link layer is operational
pub const IFF_LOWER_UP: u32 = libc::IFF_LOWER_UP as u32;
/// Driver signals IFF_DORMANT
pub const IFF_DORMANT: u32 = libc::IFF_DORMANT as u32;
/// Link supports broadcasting
pub const IFF_BROADCAST: u32 = libc::IFF_BROADCAST as u32;
/// Link supports multicasting
pub const IFF_MULTICAST: u32 = libc::IFF_MULTICAST as u32;
/// Link supports multicast routing
pub const IFF_ALLMULTI: u32 = libc::IFF_ALLMULTI as u32;
/// Tell driver to do debugging (currently unused)
pub const IFF_DEBUG: u32 = libc::IFF_DEBUG as u32;
/// Link loopback network
pub const IFF_LOOPBACK: u32 = libc::IFF_LOOPBACK as u32;
/// u32erface is point-to-point link
pub const IFF_POINTOPOINT: u32 = libc::IFF_POINTOPOINT as u32;
/// ARP is not supported
pub const IFF_NOARP: u32 = libc::IFF_NOARP as u32;
/// Receive all packets.
pub const IFF_PROMISC: u32 = libc::IFF_PROMISC as u32;
/// Master of a load balancer (bonding)
pub const IFF_MASTER: u32 = libc::IFF_MASTER as u32;
/// Slave of a load balancer
pub const IFF_SLAVE: u32 = libc::IFF_SLAVE as u32;
/// Link selects port automatically (only used by ARM ethernet)
pub const IFF_PORTSEL: u32 = libc::IFF_PORTSEL as u32;
/// Driver supports setting media type (only used by ARM ethernet)
pub const IFF_AUTOMEDIA: u32 = libc::IFF_AUTOMEDIA as u32;

// /// Echo sent packets (testing feature, CAN only)
// pub const IFF_ECHO: u32 = libc::IFF_ECHO as u32;
// /// Dialup device with changing addresses (unused, BSD compatibility)
// pub const IFF_DYNAMIC: u32 = libc::IFF_DYNAMIC as u32;
// /// Avoid use of trailers (unused, BSD compatibility)
// pub const IFF_NOTRAILERS: u32 = libc::IFF_NOTRAILERS as u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct LinkFlags(pub u32);

impl From<u32> for LinkFlags {
    fn from(flags: u32) -> Self {
        LinkFlags(flags)
    }
}

impl<'a> From<&'a LinkFlags> for u32 {
    fn from(flags: &'a LinkFlags) -> u32 {
        flags.0
    }
}

impl From<LinkFlags> for u32 {
    fn from(flags: LinkFlags) -> u32 {
        flags.0
    }
}

impl Default for LinkFlags {
    fn default() -> Self {
        LinkFlags::new()
    }
}

impl LinkFlags {
    pub fn new() -> Self {
        LinkFlags(0)
    }

    /// Set the `IFF_UP` flag
    pub fn set_up(&mut self) {
        self.0 |= IFF_UP
    }

    /// Unset the `IFF_UP` flag
    pub fn unset_up(&mut self) {
        self.0 &= !IFF_UP
    }

    /// Check if the `IFF_UP` flag is set
    pub fn is_up(self) -> bool {
        self.0 & IFF_UP == IFF_UP
    }

    /// Set the `IFF_RUNNING` flag
    pub fn set_running(&mut self) {
        self.0 |= IFF_RUNNING
    }

    /// Unset the `IFF_RUNNING` flag
    pub fn unset_running(&mut self) {
        self.0 &= !IFF_RUNNING
    }

    /// Check if the `IFF_RUNNING` flag is set
    pub fn is_running(self) -> bool {
        self.0 & IFF_RUNNING == IFF_RUNNING
    }

    /// Set the `IFF_LOWER_UP` flag
    pub fn set_lower_up(&mut self) {
        self.0 |= IFF_LOWER_UP
    }

    /// Unset the `IFF_LOWER_UP` flag
    pub fn unset_lower_up(&mut self) {
        self.0 &= !IFF_LOWER_UP
    }

    /// Check if the `IFF_LOWER_UP` flag is set
    pub fn is_lower_up(self) -> bool {
        self.0 & IFF_LOWER_UP == IFF_LOWER_UP
    }

    /// Set the `IFF_DORMANT` flag
    pub fn set_dormant(&mut self) {
        self.0 |= IFF_DORMANT
    }

    /// Unset the `IFF_DORMANT` flag
    pub fn unset_dormant(&mut self) {
        self.0 &= !IFF_DORMANT
    }

    /// Check if the `IFF_DORMANT` flag is set
    pub fn is_dormant(self) -> bool {
        self.0 & IFF_DORMANT == IFF_DORMANT
    }

    /// Set the `IFF_BROADCAST` flag
    pub fn set_broadcast(&mut self) {
        self.0 |= IFF_BROADCAST
    }

    /// Unset the `IFF_BROADCAST` flag
    pub fn unset_broadcast(&mut self) {
        self.0 &= !IFF_BROADCAST
    }

    /// Check if the `IFF_BROADCAST` flag is set
    pub fn is_broadcast(self) -> bool {
        self.0 & IFF_BROADCAST == IFF_BROADCAST
    }

    /// Set the `IFF_MULTICAST` flag
    pub fn set_multicast(&mut self) {
        self.0 |= IFF_MULTICAST
    }

    /// Unset the `IFF_MULTICAST` flag
    pub fn unset_multicast(&mut self) {
        self.0 &= !IFF_MULTICAST
    }

    /// Check if the `IFF_MULTICAST` flag is set
    pub fn is_multicast(self) -> bool {
        self.0 & IFF_MULTICAST == IFF_MULTICAST
    }

    /// Set the `IFF_ALLMULTI` flag
    pub fn set_allmulti(&mut self) {
        self.0 |= IFF_ALLMULTI
    }

    /// Unset the `IFF_ALLMULTI` flag
    pub fn unset_allmulti(&mut self) {
        self.0 &= !IFF_ALLMULTI
    }

    /// Check if the `IFF_ALLMULTI` flag is set
    pub fn is_allmulti(self) -> bool {
        self.0 & IFF_ALLMULTI == IFF_ALLMULTI
    }

    /// Set the `IFF_DEBUG` flag
    pub fn set_debug(&mut self) {
        self.0 |= IFF_DEBUG
    }

    /// Unset the `IFF_DEBUG` flag
    pub fn unset_debug(&mut self) {
        self.0 &= !IFF_DEBUG
    }

    /// Check if the `IFF_DEBUG` flag is set
    pub fn is_debug(self) -> bool {
        self.0 & IFF_DEBUG == IFF_DEBUG
    }

    /// Set the `IFF_LOOPBACK` flag
    pub fn set_loopback(&mut self) {
        self.0 |= IFF_LOOPBACK
    }

    /// Unset the `IFF_LOOPBACK` flag
    pub fn unset_loopback(&mut self) {
        self.0 &= !IFF_LOOPBACK
    }

    /// Check if the `IFF_LOOPBACK` flag is set
    pub fn is_loopback(self) -> bool {
        self.0 & IFF_LOOPBACK == IFF_LOOPBACK
    }

    /// Set the `IFF_POINTOPOINT` flag
    pub fn set_point_to_point(&mut self) {
        self.0 |= IFF_POINTOPOINT
    }

    /// Unset the `IFF_POINTOPOINT` flag
    pub fn unset_point_to_point(&mut self) {
        self.0 &= !IFF_POINTOPOINT
    }

    /// Check if the `IFF_POINTOPOINT` flag is set
    pub fn is_point_to_point(self) -> bool {
        self.0 & IFF_POINTOPOINT == IFF_POINTOPOINT
    }

    /// Set the `IFF_NOARP` flag
    pub fn set_no_arp(&mut self) {
        self.0 |= IFF_NOARP
    }

    /// Unset the `IFF_NOARP` flag
    pub fn unset_no_arp(&mut self) {
        self.0 &= !IFF_NOARP
    }

    /// Check if the `IFF_NOARP` flag is set
    pub fn is_no_arp(self) -> bool {
        self.0 & IFF_NOARP == IFF_NOARP
    }

    /// Set the `IFF_PROMISC` flag
    pub fn set_promiscuous(&mut self) {
        self.0 |= IFF_PROMISC
    }

    /// Unset the `IFF_PROMISCUOUS` flag
    pub fn unset_promiscuous(&mut self) {
        self.0 &= !IFF_PROMISC
    }

    /// Check if the `IFF_PROMISC` flag is set
    pub fn is_promiscuous(self) -> bool {
        self.0 & IFF_PROMISC == IFF_PROMISC
    }

    /// Set the `IFF_MASTER` flag
    pub fn set_master(&mut self) {
        self.0 |= IFF_MASTER
    }

    /// Unset the `IFF_MASTER` flag
    pub fn unset_master(&mut self) {
        self.0 &= !IFF_MASTER
    }

    /// Check if the `IFF_MASTER` flag is set
    pub fn is_master(self) -> bool {
        self.0 & IFF_MASTER == IFF_MASTER
    }

    /// Set the `IFF_SLAVE` flag
    pub fn set_slave(&mut self) {
        self.0 |= IFF_SLAVE
    }

    /// Unset the `IFF_SLAVE` flag
    pub fn unset_slave(&mut self) {
        self.0 &= !IFF_SLAVE
    }

    /// Check if the `IFF_SLAVE` flag is set
    pub fn is_slave(self) -> bool {
        self.0 & IFF_SLAVE == IFF_SLAVE
    }

    /// Set the `IFF_PORTSEL` flag
    pub fn set_port_select(&mut self) {
        self.0 |= IFF_PORTSEL
    }

    /// Unset the `IFF_PORTSEL` flag
    pub fn unset_port_select(&mut self) {
        self.0 &= !IFF_PORTSEL
    }

    /// Check if the `IFF_PORTSEL` flag is set
    pub fn is_port_select(self) -> bool {
        self.0 & IFF_PORTSEL == IFF_PORTSEL
    }

    /// Set the `IFF_AUTOMEDIA` flag
    pub fn set_auto_media_type(&mut self) {
        self.0 |= IFF_AUTOMEDIA
    }

    /// Unset the `IFF_AUTOMEDIA` flag
    pub fn unset_auto_media_type(&mut self) {
        self.0 &= !IFF_AUTOMEDIA
    }

    /// Check if the `IFF_AUTOMEDIA` flag is set
    pub fn is_auto_media_type(self) -> bool {
        self.0 & IFF_AUTOMEDIA == IFF_AUTOMEDIA
    }

    // TODO: ECHO, DYNAMIC, NOTRAILERS
}

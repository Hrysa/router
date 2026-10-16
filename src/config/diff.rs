/// Tracks which services need re-rendering after a config change.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ChangeSet {
    pub nftables: bool,
    pub dhcpd: bool,
    pub ppp: bool,
    pub interfaces: bool,
    pub wireguard: bool,
    pub sysctl: bool,
    pub shaper: bool,
}

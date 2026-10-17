use serde::{Deserialize, Serialize};

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub interfaces: Interfaces,
    #[serde(default)]
    pub routing: Routing,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wan_groups: Vec<super::wan_groups::WanGroup>,
    #[serde(default)]
    pub shaper: super::shaper::Shaper,
    #[serde(default)]
    pub dhcp: Dhcp,
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub singbox: Option<Singbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpn: Option<Vpn>,
    #[serde(default)]
    pub monitoring: Monitoring,
    #[serde(default)]
    pub advanced: Advanced,
    #[serde(default, skip_serializing_if = "Hooks::is_empty")]
    pub hooks: Hooks,
    #[serde(default, skip_serializing_if = "Auth::is_empty")]
    pub auth: Auth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Singbox {
    pub config: String,
}

/// Authentication configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Auth {
    /// Bcrypt hash of the admin password. Empty allows setup only, not API access.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub password_hash: String,
    /// Secret used to sign JWTs. Generated automatically if empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jwt_secret: String,
}

impl Auth {
    fn is_empty(&self) -> bool {
        self.password_hash.is_empty() && self.jwt_secret.is_empty()
    }
}

// ── Interfaces ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Routing {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<StaticRoute>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticRoute {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub comment: String,
    pub destination: String,
    pub interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(default = "main_route_table")]
    pub table: u32,
    #[serde(default = "static_route_metric")]
    pub metric: u32,
    #[serde(default)]
    pub on_link: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn main_route_table() -> u32 {
    254
}
fn static_route_metric() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Interfaces {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<InterfaceConfig>,
}

impl Interfaces {
    /// Find LAN interface (static method, no vlan_id, no gateway).
    pub fn lan(&self) -> Option<&InterfaceConfig> {
        self.items.iter().find(|i| i.is_lan())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct InterfaceConfig {
    /// System interface name (e.g., "eth0", "br-lan"). Immutable key.
    pub name: String,
    /// Optional device MTU. PPPoE tunnel MTU remains in pppoe.mtu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Optional path MTU used to cap TCP MSS in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss_clamp_mtu: Option<u16>,
    /// Display label (e.g., "WAN", "LAN"). Editable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// Connection method: pppoe, dhcp, or static.
    #[serde(default)]
    pub method: InterfaceMethod,
    /// Static IP configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_config: Option<StaticConfig>,
    /// PPPoE configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pppoe: Option<PppoeConfig>,
    /// DHCP client configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<DhcpClientConfig>,
    /// Bridge slave ports (for LAN bridge mode).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridge_ports: Vec<String>,
    /// VLAN ID. If set, this is a VLAN interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
    /// Parent interface for VLAN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Optional override for the stable automatic IPv4 WAN return table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_route_table: Option<u16>,
    /// IPv4 WAN return routing is enabled when absent; false explicitly opts out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_routing: Option<bool>,
}

impl InterfaceConfig {
    /// WAN: pppoe/dhcp method, or static with gateway set.
    pub fn is_wan(&self) -> bool {
        self.method != InterfaceMethod::Static
            || self
                .static_config
                .as_ref()
                .is_some_and(|static_config| !static_config.gateway.is_empty())
    }

    /// LAN: static method, no vlan_id, not WAN.
    pub fn is_lan(&self) -> bool {
        self.method == InterfaceMethod::Static && self.vlan_id.is_none() && !self.is_wan()
    }

    /// VLAN: has vlan_id set.
    pub fn is_vlan(&self) -> bool {
        self.vlan_id.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceMethod {
    Pppoe,
    Dhcp,
    #[default]
    Static,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PppoeConfig {
    pub username: String,
    pub password: String,
    #[serde(default = "default_pppoe_mtu")]
    pub mtu: u16,
    #[serde(default = "default_true")]
    pub mss_clamp: bool,
    #[serde(default = "default_keepalive_interval")]
    pub keepalive_interval: u32,
    #[serde(default = "default_keepalive_failure")]
    pub keepalive_failure: u32,
}

impl Default for PppoeConfig {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            mtu: default_pppoe_mtu(),
            mss_clamp: true,
            keepalive_interval: default_keepalive_interval(),
            keepalive_failure: default_keepalive_failure(),
        }
    }
}

fn default_pppoe_mtu() -> u16 {
    1492
}

fn default_keepalive_interval() -> u32 {
    10
}

fn default_keepalive_failure() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct DhcpClientConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticConfig {
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
}

// ── DHCP ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dhcp {
    /// Multiple DHCP pools. Each pool has its own subnet, range, and settings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<DhcpPool>,
    #[serde(default)]
    pub static_leases: Vec<StaticLease>,
}

impl Default for Dhcp {
    fn default() -> Self {
        Self {
            pools: vec![DhcpPool::default()],
            static_leases: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpPool {
    /// Pool name for identification.
    pub name: String,
    /// Subnet in CIDR (e.g., "192.168.1.0/24").
    pub subnet: String,
    #[serde(default)]
    pub range: DhcpRange,
    #[serde(default = "default_lease_time")]
    pub lease_time: String,
    #[serde(default = "default_domain")]
    pub domain: String,
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<String>,
    /// Gateway override (auto-derived from LAN IP if empty).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gateway: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for DhcpPool {
    fn default() -> Self {
        Self {
            name: "default".into(),
            subnet: "192.168.1.0/24".into(),
            range: DhcpRange::default(),
            lease_time: default_lease_time(),
            domain: default_domain(),
            dns_servers: default_dns_servers(),
            gateway: String::new(),
            enabled: true,
        }
    }
}

fn default_lease_time() -> String {
    "12h".into()
}

pub fn lease_duration_seconds(value: &str) -> Option<u32> {
    let value = value.trim();
    let (number, multiplier) = match value.as_bytes().last()? {
        b's' => (&value[..value.len() - 1], 1),
        b'm' => (&value[..value.len() - 1], 60),
        b'h' => (&value[..value.len() - 1], 3600),
        b'd' => (&value[..value.len() - 1], 86400),
        _ => (value, 1),
    };
    let seconds = number.parse::<u32>().ok()?.checked_mul(multiplier)?;
    (seconds > 0 && seconds <= u32::MAX / 2).then_some(seconds)
}

fn default_domain() -> String {
    "lan.local".into()
}

fn default_dns_servers() -> Vec<String> {
    vec!["192.168.1.1".into()]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DhcpRange {
    pub start: String,
    pub end: String,
}

impl Default for DhcpRange {
    fn default() -> Self {
        Self {
            start: "192.168.1.100".into(),
            end: "192.168.1.250".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticLease {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

// ── Firewall ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Firewall {
    #[serde(default)]
    pub default_policy: DefaultPolicy,
    #[serde(default)]
    pub rules: FirewallRules,
    #[serde(default)]
    pub nat: Nat,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blackhole: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sets: Vec<NftSet>,
}

/// nftables named set — a reusable collection of elements (IPs, ports, etc.).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NftSet {
    /// Set name (used as @name in rules).
    pub name: String,
    /// Element type: ipv4_addr, ipv6_addr, inet_service, etc.
    #[serde(default = "default_set_type")]
    pub set_type: String,
    /// Set elements (one per line: IP, CIDR, port, or port range).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub elements: String,
    /// Whether this set supports CIDR ranges.
    #[serde(default)]
    pub interval: bool,
    /// Optional comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl Default for NftSet {
    fn default() -> Self {
        Self {
            name: String::new(),
            set_type: default_set_type(),
            elements: String::new(),
            interval: false,
            comment: None,
        }
    }
}

fn default_set_type() -> String {
    "ipv4_addr".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DefaultPolicy {
    #[serde(default = "default_policy_drop")]
    pub input: String,
    #[serde(default = "default_policy_drop")]
    pub forward: String,
    #[serde(default = "default_policy_accept")]
    pub output: String,
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self {
            input: default_policy_drop(),
            forward: default_policy_drop(),
            output: default_policy_accept(),
        }
    }
}

fn default_policy_drop() -> String {
    "drop".into()
}

fn default_policy_accept() -> String {
    "accept".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct FirewallRules {
    #[serde(default)]
    pub input: Vec<FirewallRule>,
    #[serde(default)]
    pub forward: Vec<FirewallRule>,
}

impl FirewallRules {
    pub fn next_id(&self) -> u32 {
        self.input
            .iter()
            .chain(self.forward.iter())
            .map(|rule| rule.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirewallRule {
    /// Auto-generated numeric ID for CRUD operations.
    #[serde(default)]
    pub id: u32,
    pub action: Action,
    /// Rule comment — also used as identifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Ingress interfaces to match. Required — at least one must be specified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oif: Option<String>,
    /// Select an IPv4 WAN for new outbound connections (forward Accept rules only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_via: Option<String>,
    /// Keep configured internal destinations on normal routing when selecting a WAN.
    #[serde(default = "default_true")]
    pub preserve_internal_routes: bool,
    #[serde(
        default,
        deserialize_with = "deserialize_proto",
        skip_serializing_if = "Option::is_none"
    )]
    pub proto: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dport: Option<PortSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sport: Option<PortSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saddr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daddr: Option<String>,
    /// Invert interfaces match (match everything EXCEPT these interfaces).
    #[serde(default)]
    pub interfaces_invert: bool,
    /// Invert source address match (match everything EXCEPT this address).
    #[serde(default)]
    pub saddr_invert: bool,
    /// Invert destination address match (match everything EXCEPT this address).
    #[serde(default)]
    pub daddr_invert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    #[serde(default)]
    pub log: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_prefix: Option<String>,
    /// fwmark value for TPROXY routing (ip rule fwmark / ip route table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<u32>,
    /// Local proxy port for TPROXY.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tproxy_port: Option<u16>,
    #[serde(default)]
    pub counter: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Tproxy,
}

/// Port specification: single port, list of ports, range, or set reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    Multiple(Vec<u16>),
    Range { start: u16, end: u16 },
    Set(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Nat {
    #[serde(default)]
    pub masquerade: Vec<MasqueradeRule>,
    #[serde(default)]
    pub port_forward: Vec<PortForward>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasqueradeRule {
    pub oif: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortForward {
    #[serde(default)]
    pub id: u32,
    pub proto: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Destination port to match (WAN-side). Aliases: wan_port, source_port.
    /// Optional for non-TCP/UDP protocols (ICMP, GRE, etc.).
    #[serde(
        alias = "wan_port",
        alias = "source_port",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub target_port: Option<PortSpec>,
    /// Destination address to match (WAN-side). Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_address: Option<String>,
    /// Source address filter (client IP). Optional. Alias: source_ip.
    #[serde(default, alias = "source_ip", skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    /// Invert interfaces match (match everything EXCEPT these interfaces).
    #[serde(default)]
    pub interfaces_invert: bool,
    /// Invert source address match.
    #[serde(default)]
    pub source_address_invert: bool,
    /// Invert target address match.
    #[serde(default)]
    pub target_address_invert: bool,
    /// Interfaces to match on ingress. Required — at least one must be specified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// Redirect destination address (dnat to). Aliases: target_ip, lan_ip.
    #[serde(alias = "target_ip", alias = "lan_ip")]
    pub redirect_address: String,
    /// Redirect destination port (dnat to). Alias: lan_port.
    /// Optional for non-TCP/UDP protocols (ICMP, GRE, etc.).
    #[serde(alias = "lan_port", default, skip_serializing_if = "Option::is_none")]
    pub redirect_port: Option<PortSpec>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ── VPN ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vpn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireguardConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct WireguardConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_wg_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub peers: Vec<WireguardPeer>,
}

fn default_wg_port() -> u16 {
    51820
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireguardPeer {
    pub name: String,
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ── Monitoring ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Monitoring {
    #[serde(default = "default_true")]
    pub vnstat: bool,
    #[serde(default)]
    pub syslog_remote: SyslogRemote,
    #[serde(default)]
    pub bandwidth_alert: BandwidthAlert,
    #[serde(default)]
    pub interface_stats: InterfaceStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SyslogRemote {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default = "default_syslog_port")]
    pub port: u16,
}

fn default_syslog_port() -> u16 {
    514
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandwidthAlert {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_daily_limit")]
    pub daily_limit_gb: u32,
    #[serde(default)]
    pub alert_webhook: String,
}

impl Default for BandwidthAlert {
    fn default() -> Self {
        Self {
            enabled: false,
            daily_limit_gb: default_daily_limit(),
            alert_webhook: String::new(),
        }
    }
}

fn default_daily_limit() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InterfaceStats {
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u32,
}

impl Default for InterfaceStats {
    fn default() -> Self {
        Self {
            poll_interval: default_poll_interval(),
        }
    }
}

fn default_poll_interval() -> u32 {
    30
}

// ── Advanced ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Advanced {
    #[serde(default)]
    pub sysctl: SysctlConfig,
    #[serde(default = "default_conntrack_max")]
    pub conntrack_max: u32,
    #[serde(default)]
    pub ipv6: Ipv6Config,
}

impl Default for Advanced {
    fn default() -> Self {
        Self {
            sysctl: SysctlConfig::default(),
            conntrack_max: default_conntrack_max(),
            ipv6: Ipv6Config::default(),
        }
    }
}

/// Sysctl kernel parameters — stored as plain text, applied with sysctl -p.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SysctlConfig {
    /// Raw sysctl.conf content (key=value lines).
    #[serde(default = "default_sysctl_content")]
    pub content: String,
}

impl Default for SysctlConfig {
    fn default() -> Self {
        Self {
            content: default_sysctl_content(),
        }
    }
}

fn default_sysctl_content() -> String {
    "\
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.neigh.default.gc_thresh1 = 512
net.ipv4.neigh.default.gc_thresh2 = 2048
net.ipv4.neigh.default.gc_thresh3 = 4096
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
"
    .into()
}

fn default_conntrack_max() -> u32 {
    65536
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Ipv6Config {
    #[serde(default)]
    pub enabled: bool,
}

// ── Hooks ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Hooks {
    /// Shell commands to run before services are applied (one command per line).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub before_start: String,
    /// Shell commands to run after services are applied (one command per line).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub after_start: String,
}

impl Hooks {
    fn is_empty(&self) -> bool {
        self.before_start.is_empty() && self.after_start.is_empty()
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_true() -> bool {
    true
}

/// Deserialize proto as either a single string or an array of strings.
fn deserialize_proto<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ProtoInput {
        Single(String),
        Multiple(Vec<String>),
    }

    let opt: Option<ProtoInput> = Option::deserialize(deserializer)?;
    Ok(opt.map(|v| match v {
        ProtoInput::Single(s) => {
            if s.is_empty() {
                vec![]
            } else {
                vec![s]
            }
        }
        ProtoInput::Multiple(v) => v,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_role_inference() {
        // pppoe → WAN
        let iface = InterfaceConfig {
            mtu: None,
            mss_clamp_mtu: None,
            name: "eth0".into(),
            label: String::new(),
            method: InterfaceMethod::Pppoe,
            static_config: None,
            pppoe: Some(PppoeConfig::default()),
            dhcp: None,
            bridge_ports: vec![],
            vlan_id: None,
            parent: None,
            return_route_table: None,
            return_routing: None,
        };
        assert!(iface.is_wan());
        assert!(!iface.is_lan());
        assert!(!iface.is_vlan());

        // static + gateway → WAN
        let iface = InterfaceConfig {
            mtu: None,
            mss_clamp_mtu: None,
            name: "eth0".into(),
            label: String::new(),
            method: InterfaceMethod::Static,
            static_config: Some(StaticConfig {
                address: "203.0.113.2/30".into(),
                gateway: "203.0.113.1".into(),
                dns: vec![],
            }),
            pppoe: None,
            dhcp: None,
            bridge_ports: vec![],
            vlan_id: None,
            parent: None,
            return_route_table: None,
            return_routing: None,
        };
        assert!(iface.is_wan());
        assert!(!iface.is_lan());

        // static + no gateway → LAN
        let iface = InterfaceConfig {
            mtu: None,
            mss_clamp_mtu: None,
            name: "br-lan".into(),
            label: String::new(),
            method: InterfaceMethod::Static,
            static_config: Some(StaticConfig {
                address: "192.168.1.1/24".into(),
                gateway: String::new(),
                dns: vec![],
            }),
            pppoe: None,
            dhcp: None,
            bridge_ports: vec![],
            vlan_id: None,
            parent: None,
            return_route_table: None,
            return_routing: None,
        };
        assert!(!iface.is_wan());
        assert!(iface.is_lan());

        // vlan_id set → VLAN
        let iface = InterfaceConfig {
            mtu: None,
            mss_clamp_mtu: None,
            name: "vlan100".into(),
            label: String::new(),
            method: InterfaceMethod::Static,
            static_config: Some(StaticConfig {
                address: "10.100.0.1/24".into(),
                gateway: String::new(),
                dns: vec![],
            }),
            pppoe: None,
            dhcp: None,
            bridge_ports: vec![],
            vlan_id: Some(100),
            parent: Some("eth1".into()),
            return_route_table: None,
            return_routing: None,
        };
        assert!(!iface.is_wan());
        assert!(!iface.is_lan());
        assert!(iface.is_vlan());
    }

    #[test]
    fn test_interfaces_helpers() {
        let ifaces = Interfaces {
            items: vec![
                InterfaceConfig {
                    mtu: None,
                    mss_clamp_mtu: None,
                    name: "eth0".into(),
                    label: "WAN".into(),
                    method: InterfaceMethod::Pppoe,
                    static_config: None,
                    pppoe: Some(PppoeConfig::default()),
                    dhcp: None,
                    bridge_ports: vec![],
                    vlan_id: None,
                    parent: None,
                    return_route_table: None,
                    return_routing: None,
                },
                InterfaceConfig {
                    mtu: None,
                    mss_clamp_mtu: None,
                    name: "br-lan".into(),
                    label: "LAN".into(),
                    method: InterfaceMethod::Static,
                    static_config: Some(StaticConfig {
                        address: "192.168.1.1/24".into(),
                        gateway: String::new(),
                        dns: vec![],
                    }),
                    pppoe: None,
                    dhcp: None,
                    bridge_ports: vec![],
                    vlan_id: None,
                    parent: None,
                    return_route_table: None,
                    return_routing: None,
                },
            ],
        };
        assert!(ifaces.items[0].is_wan());
        assert!(!ifaces.items[1].is_wan());
        assert!(ifaces.lan().is_some());
        assert_eq!(ifaces.lan().unwrap().name, "br-lan");
    }

    #[test]
    fn test_hooks_default_empty() {
        let yaml = r#"
interfaces:
  items:
    - name: eth0
      method: dhcp
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.hooks.before_start.is_empty());
        assert!(config.hooks.after_start.is_empty());
    }

    #[test]
    fn test_hooks_parse() {
        let yaml = r#"
interfaces:
  items:
    - name: eth0
      method: dhcp
hooks:
  before_start: echo "starting routerd"
  after_start: |-
    modprobe xt_TPROXY
    ip rule add fwmark 1 lookup 1
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.hooks.before_start, "echo \"starting routerd\"");
        assert_eq!(config.hooks.after_start.lines().count(), 2);
    }

    #[test]
    fn test_hooks_omitted_when_empty() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        assert!(!yaml.contains("hooks:"), "empty hooks should be omitted");
    }

    #[test]
    fn test_parse_default_config() {
        let yaml = "interfaces:\n  items:\n    - name: eth0\n      method: dhcp\n";
        let config: Config = serde_yaml::from_str(yaml).expect("failed to parse default config");
        assert!(!config.interfaces.items.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let config = crate::config::routing::test_config();
        let serialized = serde_yaml::to_string(&config).unwrap();
        let deserialized: Config = serde_yaml::from_str(&serialized).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_minimal_config() {
        let yaml = r#"
interfaces:
  items:
    - name: eth0
      method: dhcp
    - name: br-lan
      method: static
      static_config:
        address: "10.0.0.1/24"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.interfaces.items.len(), 2);
        assert_eq!(config.interfaces.items[0].method, InterfaceMethod::Dhcp);
        assert_eq!(config.dhcp.pools[0].range.start, "192.168.1.100");
    }

    #[test]
    fn test_port_spec_variants() {
        let single: PortSpec = serde_yaml::from_str("80").unwrap();
        assert!(matches!(single, PortSpec::Single(80)));

        let multiple: PortSpec = serde_yaml::from_str("[80, 443, 8080]").unwrap();
        if let PortSpec::Multiple(ports) = multiple {
            assert_eq!(ports, vec![80, 443, 8080]);
        } else {
            panic!("expected Multiple");
        }
    }

    #[test]
    fn test_null_fields_omitted_in_serialization() {
        let rule = FirewallRule {
            id: 0,
            action: Action::Accept,
            comment: "test".into(),
            interfaces: vec![],
            oif: None,
            route_via: None,
            preserve_internal_routes: true,
            proto: Some(vec!["tcp".into()]),
            dport: None,
            sport: None,
            saddr: None,
            daddr: None,
            state: None,
            rate: None,
            log: false,
            log_prefix: None,
            mark: None,
            tproxy_port: None,
            counter: false,
            interfaces_invert: false,
            saddr_invert: false,
            daddr_invert: false,
            enabled: true,
        };
        let yaml = serde_yaml::to_string(&rule).unwrap();
        assert!(
            !yaml.contains("interfaces:"),
            "empty interfaces should be omitted"
        );
        assert!(!yaml.contains("oif:"), "null oif should be omitted");
        assert!(!yaml.contains("dport:"), "null dport should be omitted");
        assert!(yaml.contains("comment: test"), "comment should be present");
        assert!(yaml.contains("proto:"), "some proto should be present");
    }

    #[test]
    fn test_proto_deserialization() {
        // String format
        let rule: FirewallRule = serde_json::from_value(serde_json::json!({
            "id": 1, "action": "accept", "interfaces": ["eth0"], "proto": "tcp", "dport": 22
        }))
        .unwrap();
        assert_eq!(rule.proto, Some(vec!["tcp".into()]));

        // Array format
        let rule2: FirewallRule = serde_json::from_value(serde_json::json!({
            "id": 1, "action": "accept", "interfaces": ["eth0"], "proto": ["tcp", "udp"], "dport": 22
        })).unwrap();
        assert_eq!(rule2.proto, Some(vec!["tcp".into(), "udp".into()]));

        // Null
        let rule3: FirewallRule = serde_json::from_value(serde_json::json!({
            "id": 1, "action": "accept", "interfaces": ["eth0"]
        }))
        .unwrap();
        assert_eq!(rule3.proto, None);
    }
}

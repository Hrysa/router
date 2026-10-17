export interface InterfaceConfig {
  name: string;
  mtu?: number;
  mss_clamp_mtu?: number;
  label?: string;
  method: 'static' | 'dhcp' | 'pppoe';
  static_config?: { address: string; gateway?: string; dns?: string[] };
  dhcp?: { hostname?: string };
  pppoe?: {
    username: string;
    password: string;
    mtu: number;
    mss_clamp: boolean;
    keepalive_interval: number;
    keepalive_failure: number;
  };
  bridge_ports?: string[];
  vlan_id?: number;
  parent?: string;
  return_route_table?: number;
  return_routing?: boolean;
}
export interface InterfaceDetail {
  name: string;
  up: boolean;
  mac: string;
  mtu: number;
  rx_bytes: number;
  tx_bytes: number;
}
export type PortSpec =
  | number
  | number[]
  | { start: number; end: number }
  | string;
export interface FirewallRule {
  id: number;
  action: 'accept' | 'drop' | 'reject' | 'tproxy';
  comment?: string;
  interfaces: string[];
  oif?: string;
  route_via?: string;
  preserve_internal_routes?: boolean;
  proto?: string[];
  dport?: PortSpec;
  sport?: PortSpec;
  saddr?: string;
  daddr?: string;
  interfaces_invert?: boolean;
  saddr_invert?: boolean;
  daddr_invert?: boolean;
  state?: string[];
  rate?: string;
  log?: boolean;
  log_prefix?: string;
  counter?: boolean;
  enabled?: boolean;
  mark?: number;
  tproxy_port?: number;
}
export interface PortForward {
  id: number;
  proto: string;
  comment?: string;
  interfaces: string[];
  target_port?: PortSpec;
  target_address?: string;
  source_address?: string;
  redirect_address: string;
  redirect_port?: PortSpec;
  interfaces_invert?: boolean;
  source_address_invert?: boolean;
  target_address_invert?: boolean;
  enabled: boolean;
}
export interface NftSet {
  name: string;
  set_type: string;
  elements?: string;
  interval: boolean;
  comment?: string;
}
export interface Firewall {
  default_policy: { input: string; forward: string; output: string };
  rules: { input: FirewallRule[]; forward: FirewallRule[] };
  nat: { masquerade: { oif: string }[]; port_forward: PortForward[] };
  sets?: NftSet[];
  blackhole?: string[];
}
export interface Pool {
  name: string;
  subnet: string;
  range: { start: string; end: string };
  lease_time: string;
  domain: string;
  dns_servers: string[];
  gateway?: string;
  enabled: boolean;
}
export interface Reservation {
  mac: string;
  ip: string;
  hostname: string;
}
export interface Lease {
  address: string;
  mac: string;
  hostname: string;
  expires: string;
}
export interface Hooks {
  before_start: string;
  after_start: string;
}
export interface ShaperProfile {
  id: number;
  comment: string;
  interface: string;
  enabled: boolean;
  side: 'wan' | 'lan';
  upload_kbit: number;
  download_kbit: number;
  nat: boolean;
  overhead: number;
  mpu: number;
  link_layer: 'none' | 'atm' | 'ptm';
}
export interface ShaperSettings {
  profiles: ShaperProfile[];
}
export interface ShaperStats {
  bytes: number;
  packets: number;
  drops: number;
  backlog_bytes: number;
  ecn_marks: number;
  average_delay_us: number;
}
export interface ShaperStatus {
  timestamp_ms: number;
  error?: string;
  reconnect_active: boolean;
  profiles: {
    id: number;
    interface: string;
    egress?: ShaperStats;
    ingress?: ShaperStats;
  }[];
}
export interface WanGroup {
  id: number;
  name: string;
  members: { interface: string; tier: number; weight: number }[];
  targets: string[];
  interval_seconds: number;
  timeout_seconds: number;
  failure_threshold: number;
  recovery_threshold: number;
  recovery_delay_seconds: number;
}
export interface WanGroupStatus {
  active: boolean;
  error?: string | null;
  groups: {
    id: number;
    name: string;
    active_tier?: number | null;
    members: {
      interface: string;
      tier: number;
      weight: number;
      health: {
        healthy: boolean;
        reason: string;
        successes: number;
        failures: number;
      };
      effective_percent: number;
    }[];
  }[];
}
export interface Config {
  wan_groups?: WanGroup[];
  singbox?: { config: string };
  shaper?: ShaperSettings;
  routing: { routes: StaticRoute[] };
  interfaces: { items: InterfaceConfig[] };
  firewall: Firewall;
  dhcp: { pools?: Pool[]; static_leases: Reservation[] };
  hooks: Hooks;
  [section: string]: unknown;
}
export interface StaticRoute {
  id: number;
  comment: string;
  destination: string;
  interface: string;
  gateway?: string;
  table: number;
  metric: number;
  on_link: boolean;
  enabled: boolean;
}
export interface WanTable {
  name: string;
  interface: string;
  table: number;
}
export interface RoutingSettings {
  routes?: StaticRoute[];
  wan_tables: WanTable[];
}
export interface KernelRoute {
  family: string;
  dst?: string;
  gateway?: string;
  dev?: string;
  table: string | number;
  metric?: number;
  protocol?: string | number;
  type?: string;
  nexthops?: { gateway?: string; dev?: string; weight?: number }[];
}
export interface Service {
  name: string;
  display_name: string;
  active: boolean;
  status: string;
  pid?: number | null;
}
export interface SystemInfo {
  hostname: string;
  uptime_seconds: number;
  uptime_human: string;
}
export interface Status {
  hostname: string;
  uptime: string;
  loadavg: Record<'1m' | '5m' | '15m', string>;
}
export interface SystemStats {
  memory: {
    total_kb: number;
    used_kb: number;
    available_kb: number;
    usage_percent: number;
  };
  cpu: { idle?: number; total?: number };
}
export interface Metrics {
  timestamps: number[];
  interfaces: Record<
    string,
    { rx_bps: number[]; tx_bps: number[]; rx_pps: number[]; tx_pps: number[] }
  >;
  firewall: Record<
    string,
    { chain: string; packets_per_sec: number[]; bytes_per_sec: number[] }
  >;
}
export interface ApplyResult {
  success: boolean;
  services_restarted: string[];
  errors: string[];
  changeset?: unknown;
}
export interface Backup {
  id: string;
  size: number;
  created: string;
}

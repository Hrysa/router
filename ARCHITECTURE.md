# Architecture

## System Overview

routerd is a Linux router daemon that manages network services through a unified YAML configuration. It uses **systemd-networkd** for interface management and generates all service configs from a single `config.yml`.

```
┌─────────────┐        ┌────────────────────────────────────────┐
│  SPA WebUI  │───────→│          API Server (routerd)          │
└─────────────┘  REST  │                                        │
                       │  ┌──────────┐  ┌───────────────────┐   │
┌─────────────┐        │  │ Config   │  │  Config Renderer  │   │
│  CLI tool   │───────→│  │ Store    │  │                   │   │
│ (optional)  │  REST  │  │ (YAML)   │  │                   │   │
└─────────────┘        │  └────┬─────┘  └────────┬──────────┘   │
                       │       │                 │              │
                       │       ▼                 ▼              │
                       │  ┌────────────────────────────────┐    │
                       │  │   Service Manager (apply)      │    │
                       │  │  write configs + restart svc   │    │
                       │  └────────────────────────────────┘    │
                       └────────────────────────────────────────┘
                                           │
                     ┌─────────┬───────────┼───────────┬──────────┐
                     ▼         ▼           ▼           ▼          ▼
                 nftables    kea-dhcp4           systemd-     wireguard
                                    networkd
```

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Presentation                                      │
│  SPA WebUI, CLI, REST API, Monitoring                       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Business Logic                                    │
│  Config Management, Renderers, Service Manager, Auth        │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Infrastructure                                    │
│  config.yml, systemd services, nftables, kea-dhcp4          │
└─────────────────────────────────────────────────────────────┘
```

**Dependency flow:** Layer 3 → Layer 2 → Layer 1

---

## Layer 1: Infrastructure

External systems and data sources that routerd manages.

### Config Source

| File | Purpose |
|------|---------|
| `config.yml` | Single source of truth for all router settings |
| `config/backups/` | Timestamped config backups |

### Managed Services

#### Core (always active)

| Component | systemd unit | Config file | Validation |
|-----------|--------------|-------------|------------|
| Firewall | `nftables` | — (JSON applied directly, no file) | `nft -j -c -f` |
| Network | `systemd-networkd` | `/etc/systemd/network/50-routerd-*.network` | — |

#### Optional (via `enabled` field)

| Component | systemd unit | Config file | `enabled` field |
|-----------|--------------|-------------|-----------------|
| DHCP | `kea-dhcp4` | `/etc/kea/kea-dhcp4.conf` | `dhcp.enabled` |
| VPN | `wg-quick@wg0` | `/etc/wireguard/wg0.conf` | `vpn.wireguard.enabled` |
| PPPoE | `pppd` | `/etc/ppp/peers/isp` | `interfaces.wan.method` (implicit) |
| Traffic | `vnstat` | — | `monitoring.vnstat` |

### systemd-networkd Config Files

All managed files use `50-routerd-` prefix for cleanup:

| File | Purpose |
|------|---------|
| `50-routerd-wan.network` | WAN interface (DHCP/static/PPPoE unmanaged) |
| `50-routerd-ppp0.network` | PPPoE tunnel routing (if applicable) |
| `50-routerd-br-lan.netdev` | Bridge device definition |
| `50-routerd-br-lan.network` | Bridge static IP |
| `50-routerd-br-lan-slave.network` | Bridge member ports |
| `50-routerd-vlan<id>.netdev` | VLAN device definition |
| `50-routerd-vlan<id>.network` | VLAN static IP |

---

## Layer 2: Business Logic

Core modules that transform config into service configurations and manage their lifecycle.

### Config Management (`src/config/`)

| Module | Purpose |
|--------|---------|
| `schema.rs` | Serde structs for `config.yml` |
| `store.rs` | Atomic read/write with backup |
| `validator.rs` | Validation logic for config values |
| `diff.rs` | Change detection between old/new config |
| `init.rs` | First-run auto-detect setup |

### Renderers (`src/renderer/`)

Transform abstract config into concrete service files:

| Module | Output |
|--------|--------|
| `nftables.rs` | nftables JSON ruleset (built with the `nftables` crate; applied via `nft -j -f`, never written to disk) |
| `interfaces.rs` | `50-routerd-*.network`/`.netdev` files |
| `kea.rs` | `/etc/kea/kea-dhcp4.conf` |
| `ppp.rs` | `/etc/ppp/peers/isp` |
| `wireguard.rs` | `/etc/wireguard/wg0.conf` |
| `sysctl.rs` | `/etc/sysctl.d/90-routerd.conf` |
| `sysctl.rs` | Sysctl settings |

### Service Management (`src/service/`)

| Module | Purpose |
|--------|--------|
| `apply.rs` | Render → validate → write → restart pipeline |
| `manager.rs` | Systemd lifecycle (start/stop/restart) |
| `hooks.rs` | User-defined lifecycle hooks |
| `rollback.rs` | Config rollback on failure |
| `singbox.rs` | Download/install sing-box binary |

### Auth (`src/auth/`)

| Module | Purpose |
|--------|---------|
| `jwt.rs` | JWT token generation/validation |
| `password.rs` | Password hashing (bcrypt) |

---

## Layer 3: Presentation

User-facing interfaces and monitoring.

### API Server (`src/api/`)

| Module | Purpose |
|--------|--------|
| `server.rs` | Axum HTTP/HTTPS server + SPA serving |
| `handlers/auth.rs` | Login / JWT issuance |
| `handlers/config.rs` | Read/update router configuration |
| `handlers/service.rs` | Trigger service restarts |
| `handlers/status.rs` | System status |
| `handlers/monitor.rs` | Live monitoring data |
| `middleware/auth.rs` | JWT validation middleware |
| `error.rs` | API error types |

### Monitoring (`src/monitor/`)

| Module | Purpose |
|--------|---------|
| `interfaces.rs` | Live interface state |
| `traffic.rs` | Bandwidth statistics |
| `leases.rs` | DHCP lease info |
| `connections.rs` | Active connections |
| `system.rs` | CPU, memory, uptime |

### CLI (`src/main.rs`)

Entry point with clap argument parsing. Orchestrates startup: parse args → init → load config → apply → start API server.

---

## Apply Pipeline

```
routerd startup
    → load config.yml
    → validate (only enabled components)
    → detect changes (diff old vs new)
    → render changed configs
    → syntax check (nft -j -c -f required, others optional)
    → write configs (atomic: write .tmp, rename)
    → restart changed services
        - nftables: nft -j -f <staged JSON> (not systemctl, no file persisted)
        - systemd-networkd: networkctl reload (fallback: systemctl restart)
        - others: systemctl restart
```

### nftables Layout

The renderer emits a single JSON ruleset (`flush ruleset` + add objects) with four tables:

| Table | Chains | Purpose |
|-------|--------|---------|
| `inet filter` | input, forward, output + named sets | firewall rules; implicit `ct state established,related accept` when policy is drop; implicit `iifname "lo" accept` in input |
| `ip nat` | prerouting (DNAT), postrouting | port forwards + masquerade; auto hairpin masquerade for forwards into the LAN subnet |
| `inet mangle` | prerouting (prio -150) | tproxy rules (mark + tproxy + accept) |
| `inet blackhole` | input, forward (prio -5) | `blocked` set, drop saddr/daddr matches |

Address conventions: `@setname` references a named set (protocol picked from the set's type), `@local` compiles to a `fib ... type local` match.

Every rule's comment is `[<id>] <comment>` — `/api/firewall/stats` parses the ID out of `nft -j list chain` output to attach per-rule counters.

## Init Setup (first run)

When `config.yml` doesn't exist:

```
routerd -c /etc/router
    │
    ├── check systemd-networkd.service exists (bail if not)
    ├── detect interfaces from /sys/class/net/
    ├── detect WAN: interface with default route
    ├── detect LAN: bridge or group ethernet ports
    ├── detect WAN method: DHCP lease file → dhcp, else static IP → static
    ├── disable networking.service (ifupdown)
    ├── write .network/.netdev files to /etc/systemd/network/
    ├── enable + start systemd-networkd.service
    ├── write config.yml
    └── apply full config
        - nftables: empty accept-all ruleset (init mode)
        - other components: skip if not installed
```

## Repository Layout

```
router/
├── Cargo.toml
├── config/                 # runtime config (gitignored; default -c target)
├── sing-box/               # user-managed sing-box files (gitignored)
├── src/
│   ├── main.rs             # CLI entry + init flow
│   ├── config/             # schema, store, validator, diff, init
│   ├── renderer/           # nftables, kea, interfaces, ppp, wireguard, sysctl
│   ├── service/            # apply pipeline, manager, rollback, hooks, singbox installer
│   ├── api/                # axum server, handlers, auth middleware
│   ├── monitor/            # system/interface/traffic/lease/connection monitoring
│   └── auth/               # JWT + password hashing
└── web/                    # Svelte 5 SPA; dist/ embedded in binary
```

## Tech Stack

| Component | Choice |
|-----------|--------|
| Language | Rust |
| Web framework | axum |
| Config | serde + serde_yaml |
| Async runtime | tokio |
| CLI | clap |
| Logging | tracing + tracing-subscriber |
| Auth | jsonwebtoken + bcrypt |
| Network backend | systemd-networkd |
| Firewall | nftables |
| Embedded assets | rust-embed |
| SPA | Svelte 5 + Vite + TypeScript |

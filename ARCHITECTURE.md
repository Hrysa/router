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
                nftables    kea-dhcp4  unbound   systemd-     wireguard
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
│  config.yml, systemd services, nftables, kea, unbound       │
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
| Firewall | `nftables` | `/etc/nftables.conf` | `nft -c` |
| Network | `systemd-networkd` | `/etc/systemd/network/50-routerd-*.network` | — |

#### Optional (via `enabled` field)

| Component | systemd unit | Config file | `enabled` field |
|-----------|--------------|-------------|-----------------|
| DHCP | `kea-dhcp4` | `/etc/kea/kea-dhcp4.conf` | `dhcp.enabled` |
| DNS | `unbound` | `/etc/unbound/unbound.conf.d/router.conf` | `dns.enabled` |
| VPN | `wg-quick@wg0` | `/etc/wireguard/wg0.conf` | `vpn.wireguard.enabled` |
| PPPoE | `pppd` | `/etc/ppp/peers/isp` | `interfaces.wan.method` (implicit) |
| Traffic | `vnstat` | — | `monitoring.vnstat` |
| NTP | `chrony` | — | `system.ntp.enabled` |

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
| `schema.rs` | Serde structs for `config.yml` (852 lines) |
| `store.rs` | Atomic read/write with backup |
| `validator.rs` | Validation logic for config values |
| `diff.rs` | Change detection between old/new config |
| `init.rs` | First-run auto-detect setup |

### Renderers (`src/renderer/`)

Transform abstract config into concrete service files:

| Module | Output |
|--------|--------|
| `nftables.rs` | `/etc/nftables.conf` (758 lines) |
| `interfaces.rs` | `50-routerd-*.network`/`.netdev` files |
| `kea.rs` | `/etc/kea/kea-dhcp4.conf` |
| `unbound.rs` | `/etc/unbound/unbound.conf.d/router.conf` |
| `ppp.rs` | `/etc/ppp/peers/isp` |
| `wireguard.rs` | `/etc/wireguard/wg0.conf` |
| `sysctl.rs` | Sysctl settings |

### Service Management (`src/service/`)

| Module | Purpose |
|--------|---------|
| `apply.rs` | Render → validate → write → restart pipeline (505 lines) |
| `manager.rs` | Systemd lifecycle (start/stop/restart) |
| `hooks.rs` | User-defined lifecycle hooks |
| `rollback.rs` | Config rollback on failure |

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
|--------|---------|
| `server.rs` | Axum HTTP/HTTPS server + SPA serving |
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
    → syntax check (nft -c required, others optional)
    → write configs (atomic: write .tmp, rename)
    → restart changed services
        - nftables: nft -f (not systemctl)
        - systemd-networkd: networkctl reload (fallback: systemctl restart)
        - others: systemctl restart
```

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

## Project Structure

```
router/
├── Cargo.toml
├── config/
│   ├── config.yml              # Main config (default for -c)
│   └── backups/                # Timestamped backups
├── src/
│   ├── main.rs                 # CLI args + init flow
│   ├── config/
│   │   ├── mod.rs
│   │   ├── schema.rs           # serde structs for config.yml
│   │   ├── store.rs            # atomic read/write + backup
│   │   ├── validator.rs        # validation logic
│   │   ├── diff.rs             # change detection
│   │   └── init.rs             # first-run auto-detect setup
│   ├── renderer/
│   │   ├── mod.rs
│   │   ├── nftables.rs
│   │   ├── kea.rs              # kea-dhcp4 JSON config
│   │   ├── unbound.rs
│   │   ├── ppp.rs
│   │   ├── interfaces.rs       # systemd-networkd .network/.netdev
│   │   └── wireguard.rs
│   ├── service/
│   │   ├── mod.rs
│   │   ├── manager.rs          # systemd lifecycle + networkctl
│   │   ├── apply.rs            # render → validate → write → restart
│   │   └── rollback.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── server.rs           # axum router + SPA serving
│   │   ├── middleware/
│   │   │   └── auth.rs
│   │   ├── handlers/
│   │   │   ├── config.rs
│   │   │   ├── service.rs
│   │   │   ├── status.rs
│   │   │   └── monitor.rs
│   │   └── error.rs
│   ├── monitor/
│   │   ├── mod.rs
│   │   ├── interfaces.rs
│   │   ├── traffic.rs
│   │   ├── leases.rs
│   │   ├── connections.rs
│   │   └── system.rs
│   └── auth/
│       ├── jwt.rs
│       └── password.rs
├── web/                        # SPA (Svelte 5, embedded in binary)
└── scripts/
    ├── install.sh
    └── systemd/routerd.service
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

# Architecture

## System Overview

routerd is a Linux router daemon that manages network services through a unified YAML configuration. It uses **systemd-networkd** for interface management. Router-managed service files are generated from `config.yml`; sing-box's JSONC file is managed separately by the user.

```
┌─────────────┐        ┌────────────────────────────────────────┐
│  SPA WebUI  │───────→│          API Server (routerd)          │
└─────────────┘  REST  │                                        │
                       │  ┌──────────┐  ┌───────────────────┐   │
┌─────────────┐        │  │ Config   │  │  Config Renderer  │   │
│ API client  │───────→│  │ Store    │  │                   │   │
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

#### Conditional services

| Component | systemd unit | Config file | `enabled` field |
|-----------|--------------|-------------|-----------------|
| DHCP | `kea-dhcp4-server` | `/etc/kea/kea-dhcp4.conf` | Any `dhcp.pools[].enabled` |
| VPN | `wg-quick@wg0` | `/etc/wireguard/wg0.conf` | `vpn.wireguard.enabled` |
| PPPoE | `pppd` | `/etc/ppp/peers/isp`, `/etc/ppp/chap-secrets` | WAN `interfaces.items[].method: pppoe` with nonempty username |
| Proxy | `sing-box` | `/etc/sing-box/config.jsonc` (user-managed) | Start/restart attempted on every apply |

Disabled DHCP/PPP/WireGuard services are stopped if active, not started from stale on-disk configuration. `vnstat` has manual API service controls, but `monitoring.vnstat` is not wired into the apply pipeline.

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
| `50-routerd-vlan<id>.network` | VLAN DHCP/static configuration (filename uses interface name) |

---

## Layer 2: Business Logic

Core modules that transform config into service configurations and manage their lifecycle.

### Config Management (`src/config/`)

| Module | Purpose |
|--------|---------|
| `schema.rs` | Serde structs for `config.yml` |
| `store.rs` | Atomic read/write with backup |
| `validator.rs` | Validation logic for config values |
| `diff.rs` | ChangeSet flags; rendered-content comparison is in `service/apply.rs` |
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

### Service Management (`src/service/`)

| Module | Purpose |
|--------|--------|
| `apply.rs` | Render → validate → write → restart pipeline |
| `manager.rs` | Systemd lifecycle (start/stop/restart) |
| `hooks.rs` | User-defined lifecycle hooks |
| `rollback.rs` | Explicit restore of a saved backup, followed by forced apply |
| `files.rs` | Exclusive random staging files/directories, atomic replacement, permissions |
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

### Monitoring

`src/metrics/mod.rs` samples interface and firewall counters every five seconds and retains up to 360 samples (30 minutes). `/api/metrics` supplies aligned series for the uPlot charts; `/api/metrics/current` returns the latest sample.

System/interface details and Kea CSV lease reads live in `src/api/handlers/monitor.rs` and `src/api/handlers/status.rs`. `/api/monitor/traffic` and `/api/monitor/connections` are placeholders. The files in `src/monitor/` are currently module stubs, not separate collectors.

### CLI (`src/main.rs`)

Entry point with clap argument parsing. Orchestrates startup: parse args → init if needed → load config → apply unless `--init` → start API server. With `--init`, offload changes and startup hooks are also skipped.

---

## Apply Pipeline

```
normal startup / POST /api/config/apply / explicit backup restore
    → validate schema
    → render all service configs
    → stage syntax checks: nft -j -c -f required; kea-dhcp4 -t if installed
    → detect rendered content differences against disk and last successful in-memory config
    → write changed configs (exclusive random staging file + rename)
    → start enabled services if inactive; reload/restart changed services
        - nftables: nft -j -f <staged JSON> (not systemctl, no file persisted)
        - systemd-networkd: networkctl reload (fallback: systemctl restart)
        - others: systemctl restart
    → reconcile IPv4 TPROXY policy routing
```

API mutations, service controls, apply, and restore share an operation lock. Read-modify-write requests cannot overwrite one another, and service applies cannot overlap. Individual config saves also hold the store's write lock through disk replacement and in-memory publication. Backups use unique timestamp/UUID IDs, and restore rejects IDs containing path separators.

Only nftables and optional Kea checks invoke external syntax validators before apply. PPP, WireGuard, networkd, and sysctl rely on `src/config/validator.rs`. Service command failures, sysctl failures, and TPROXY setup failures propagate instead of reporting a successful apply. A missing/unconfigured sing-box remains an optional warning; if its config file exists, start/restart failures propagate.

There is no automatic transactional rollback after failure: earlier file writes and service changes may persist. The in-memory last-successful snapshot is not a durable applied-state journal; it is initialized from the saved configuration at process startup. Keep console access and review configuration before applying network changes.

### nftables Layout

The renderer emits a single JSON transaction. It resets only the four table names it owns (add-if-absent, delete, then recreate as needed), preserving all other tables. `inet filter` is always recreated with the configured policies, even when there are no explicit rules. The other tables are conditional:

| Table | Chains | Purpose |
|-------|--------|---------|
| `inet filter` | input, forward, output + named sets | firewall rules; implicit `ct state established,related accept` when policy is drop; implicit `iifname "lo" accept` in input |
| `ip nat` | prerouting (DNAT), postrouting | port forwards + masquerade; auto hairpin masquerade for forwards into the LAN subnet |
| `inet mangle` | prerouting (prio -150) | tproxy rules (mark + tproxy + accept) |
| `inet blackhole` | input, forward (prio -5) | `blocked` set, drop saddr/daddr matches |

Address conventions: `@setname` references a named set (protocol picked from the set's type), `@local` compiles to a `fib ... type local` match.

Every rule's comment is `[<id>] <comment>` — `/api/firewall/stats` parses the ID out of `nft -j list chain` output to attach per-rule counters.

Do not share these four tables with other tools: their contents are replaced on every apply. TPROXY marks select dedicated routing tables; reserved IDs 0, 253, 254, and 255 are rejected. Cleanup removes the matching local route/rule, not the entire routing table.

### Authentication and secrets

Public routes are `/api/auth/status`, `/api/auth/setup`, `/api/auth/login`, and SPA assets. Setup succeeds only while the password hash is empty, under the same operation lock as configuration updates. An unset password does not grant API access or allow token issuance. Bcrypt work runs off the async executor; password input is limited to bcrypt's 72-byte maximum.

JWTs expire after 24 hours. Middleware reads the current password state and signing secret on every request, so restoring/replacing a secret takes effect immediately. The management API exposes secrets to authenticated administrators, and hooks execute shell commands by design; it is not a multi-user or restricted-privilege API.

`config.yml`, backups, PPP peers/secrets, WireGuard files, and sing-box API writes use mode `0600`. Temporary secret files start private and are removed on normal cleanup. Kea staging files use `0644` for its privilege-dropping validation. TLS is optional, but the certificate and key CLI flags must be specified together; first-time setup requires a trusted management connection.

## Init Setup (first run)

When `config.yml` doesn't exist, `--init` is required:

```
routerd --init -c /etc/router
    │
    ├── detect interfaces from /sys/class/net/
    ├── detect WAN: interface with default route
    ├── select first other interface as draft LAN (192.168.1.1/24)
    ├── detect WAN method: DHCP lease file → dhcp, else static IP → static
    ├── write draft config.yml (keep existing file if present)
    ├── skip offload changes, startup hooks, and automatic apply
    └── start web UI/API for review and explicit apply
```

Initialization leaves network managers, service configs, addresses, routes, and firewall rules untouched. This also holds for repeated starts with `--init`. Starting without `--init` uses the normal apply pipeline above. The generated configuration is a router draft, not a complete import of the existing network setup.

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
└── web/                    # React SPA; dist/ embedded in binary
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
| SPA | React + Vite + TypeScript + React Query; Yacd-meta-inspired UI |

## Web UI

The frontend reimplements the Yacd-meta React shell, responsive sidebar, card-based overview, and light/dark theme approach for routerd. It does not include the reference project's Clash controllers, backend selector, or service worker. The ignored `git-repos/Yacd-meta/` checkout is a design reference only; production builds do not depend on it.

`web/src/App.tsx` provides hash navigation, authentication gating, live Apply confirmation, and theme preferences. Remote data uses React Query and an abortable same-origin fetch client; logout, token changes, and HTTP 401 clear cached configuration and unmount sensitive editors. Editor drafts remain independent of background queries. Password limits use UTF-8 byte counts, and raw sing-box JSONC is never reformatted by the frontend.

The overview and monitoring pages graph a selected interface rather than summing overlapping bridge/physical counters. `rx_bps` and `tx_bps` from the API are bytes/s. Configuration editors save without applying; startup hooks activate on normal startup. Service controls and backup restores are explicitly confirmed live operations. The pending-saves indicator only records this browser's actions, not authoritative configuration drift.

Frontend regression tests live in `web/tests/` and use Bun's built-in runner. Build assets with Bun before compiling Rust; `web/dist/` is generated and ignored. See `web/README.md` for commands and `web/THIRD_PARTY_NOTICES.md` for reference attribution.

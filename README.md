# routerd — Linux Router Daemon

A Linux-based router system built with Rust, nftables, and Debian. API-centric architecture where a single `config.yml` manages all network services.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system overview and component documentation.

## Features

- **systemd-networkd** — network interface management (bridge, VLAN, DHCP, static)
- **nftables** — firewall, NAT, port forwarding, blackhole lists
- **Kea DHCPv4** — multiple address pools and static leases
- **PPPoE** — WAN connection with auto-reconnect
- **WireGuard** — VPN with peer management
- **Monitoring** — interface/firewall time series, system resources, and DHCP leases
- **Backup/Restore** — automatic config backups with rollback
- **REST API** — full CRUD on all config sections
- **SPA Web UI** — responsive React dashboard inspired by Yacd-meta, with light/dark/system themes, embedded in the Rust binary
- **sing-box integration** — user-managed JSONC configuration and service control

There is no managed DNS resolver. `/api/monitor/traffic` and `/api/monitor/connections` currently return placeholders; use `/api/metrics` for collected interface/firewall traffic.

## Quick Start

### Build

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build the embedded UI first (Bun 1.4.1+ required)
cd web
bun install --frozen-lockfile
bun run test
bun run check
bun run build
cd ..

# Build the daemon
cargo build --release
```

### Run

```bash
# With existing config directory
sudo ./target/release/routerd -c /etc/router --listen 127.0.0.1:8443

# First run (creates a draft config and starts the UI, preserving host networking)
sudo ./target/release/routerd --init -c /etc/router --listen 127.0.0.1:8443

# Development (uses ./config/ as default)
cargo run -- --init --listen 127.0.0.1:8443
```

### Init Setup (first run)

Run with `--init` to create `config.yml` if missing and start the web UI/API while preserving the current networking setup. Without `--init`, a missing config is an error.

Initialization detects interfaces and saves a **draft** router configuration. It does not write system service configs, switch network managers, change NIC offloads, run startup hooks, or apply firewall/routing changes. Existing `config.yml` files are kept when `--init` is used again.

Review the draft before using `POST /api/config/apply`: the generated LAN address is `192.168.1.1/24` and the default firewall/NAT rules are router defaults, not a full import of the host's current setup. Applying changes explicitly takes over the configured services.

Keep `--init` on subsequent starts to continue skipping startup changes. Starting without `--init` applies the saved configuration automatically.

Normal startup and explicit apply require root and the configured service binaries. `nft` is mandatory; Kea's syntax check runs only when `kea-dhcp4` is installed. Initialization needs at least two available network interfaces to generate its WAN/LAN draft.

### Security and transport

Without TLS flags the server uses **HTTP**, even on port 8443. Both `--tls-cert` and `--tls-key` must be supplied together for HTTPS. The default listen address is `0.0.0.0:8443`; use loopback with an SSH tunnel/reverse proxy, or configure TLS and restrict management access to trusted clients.

On first use, create an admin password in the UI or through `/api/auth/setup`. Setup is public until a password exists: bootstrap only on a trusted, isolated management connection. Login and protected API access are denied until setup completes. Tokens expire after 24 hours; changing the saved JWT secret invalidates existing tokens immediately.

The API is a privileged administration interface: configuration includes credentials, and lifecycle hooks intentionally execute shell commands as the daemon user. Do not expose it to the public Internet. `config.yml`, new backups, PPP credentials, and WireGuard private keys are written with mode `0600`; protect any older copies separately.

Apply is **not a transactional host rollback**. Service failures return an error, but files and earlier service changes may already be in place. Keep console access when changing network or firewall settings. Backup restore applies a saved configuration; it does not restore arbitrary external files or prior kernel state.

### Configure via API

```bash
# First use only: set a strong admin password (example uses loopback HTTP)
curl --fail-with-body -X POST http://127.0.0.1:8443/api/auth/setup \
  -H "Content-Type: application/json" \
  -d '{"password": "replace-with-a-strong-password"}'

# Login; copy the returned token into TOKEN
curl --fail-with-body -X POST http://127.0.0.1:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "replace-with-a-strong-password"}'
TOKEN='<returned token>'

# Get current config
curl --fail-with-body -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/config

# Update one existing interface (replace eth0 with its actual name)
curl --fail-with-body -X PUT http://127.0.0.1:8443/api/config/interfaces/eth0 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "eth0",
    "label": "WAN",
    "method": "pppoe",
    "pppoe": {
      "username": "user@isp",
      "password": "replace-with-isp-password",
      "mtu": 1492
    }
  }'

# Apply config (renders all service configs + restarts services)
curl --fail-with-body -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/config/apply

# Check service status
curl --fail-with-body -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/services
```

## CLI Options

```
routerd [OPTIONS]

Options:
  -c, --config-dir <DIR>   Config directory [default: config]
      --listen <ADDR>      API server listen address [default: 0.0.0.0:8443]
      --log-level <LEVEL>  Log level: trace, debug, info, warn, error [default: info]
      --log-format <FMT>   Log format: text, json [default: text]
      --init               Create config if missing; start UI/API without changing networking
      --tls-cert <PATH>    TLS certificate (PEM)
      --tls-key <PATH>     TLS private key (PEM)
      --install-singbox    Download/install sing-box from GitHub releases, then exit
  -h, --help               Print help
```

## API Endpoints

All routes listed below require `Authorization: Bearer <token>`, except the three authentication routes. Saving configuration does not apply it; use `/api/config/apply` explicitly.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth/status` | Whether an admin password exists |
| POST | `/api/auth/setup` | First-time password setup (only while unset) |
| POST | `/api/auth/login` | Verify password and issue JWT |

### Status
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/status` | Aggregated system status |
| GET | `/api/status/system` | CPU, memory, uptime |

### Config
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/config` | Get full config |
| PUT | `/api/config` | Replace full config |
| GET / POST | `/api/config/interfaces` | List / create an interface |
| PUT / DELETE | `/api/config/interfaces/:name` | Update / delete an interface |
| POST | `/api/config/firewall` | Update firewall rules |
| GET / POST | `/api/config/firewall/rules` | List / create input or forward rules |
| PUT / DELETE | `/api/config/firewall/rules/:id` | Update / delete a rule |
| POST | `/api/config/firewall/rules/:id/move` | Move rule up or down |
| GET | `/api/config/firewall/nat` | List NAT configuration |
| POST | `/api/config/firewall/nat/port-forward` | Create a port forward |
| PUT / DELETE | `/api/config/firewall/nat/port-forward/:id` | Update / delete a port forward |
| GET / POST | `/api/config/firewall/sets` | List / create named sets |
| PUT / DELETE | `/api/config/firewall/sets/:name` | Update / delete a named set |
| POST | `/api/config/dhcp` | Update DHCP config |
| GET / POST | `/api/config/dhcp/leases` | List / create static DHCP leases |
| DELETE | `/api/config/dhcp/leases/:mac` | Delete a static lease |
| POST | `/api/config/hooks` | Replace lifecycle hooks |
| GET / PUT | `/api/singbox/config` | Read / write raw sing-box JSONC (not a JSON wrapper) |
| POST | `/api/config/validate` | Validate config |
| POST | `/api/config/apply` | Apply config |
| POST | `/api/config/rollback` | Rollback to last backup |
| GET | `/api/config/backups` | List backups |
| POST | `/api/config/backups/:id/restore` | Restore backup |

### Services
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/services` | List all services |
| GET | `/api/service/:name/status` | Service status |
| POST | `/api/service/:name/start` | Start service |
| POST | `/api/service/:name/stop` | Stop service |
| POST | `/api/service/:name/restart` | Restart service |

### Monitoring
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/monitor/system` | System stats |
| GET | `/api/monitor/interfaces` | Interface status |
| GET | `/api/monitor/traffic` | Traffic stats |
| GET | `/api/monitor/connections` | Conntrack table |
| GET | `/api/monitor/leases` | DHCP leases |
| GET | `/api/metrics` | Interface/firewall time series (up to 30 minutes) |
| GET | `/api/metrics/current` | Latest collected sample |
| GET | `/api/firewall/stats` | Per-rule nftables counters |

## Config Directory

All configuration lives in a directory (default: `./config/` or `/etc/router/`):

```
config/
├── config.yml      # Main config (API server owns this)
└── backups/        # Automatic timestamped backups
```

Service configs generated from `config.yml`:
- `/etc/systemd/network/50-routerd-*.network` — systemd-networkd
- `/etc/systemd/network/50-routerd-*.netdev` — bridges and VLANs
- `/etc/kea/kea-dhcp4.conf` — Kea DHCPv4 (`kea-dhcp4-server`)
- `/etc/ppp/peers/isp` and `/etc/ppp/chap-secrets` — PPPoE
- `/etc/wireguard/wg0.conf` — WireGuard
- `/etc/sysctl.d/90-routerd.conf` — kernel network settings

nftables is rendered as JSON and applied with `nft -j -f`; no `/etc/nftables.conf` is generated. Routerd replaces only its four owned tables (`inet filter`, `ip nat`, `inet mangle`, `inet blackhole`); do not place unrelated rules in those tables. Other nftables tables are preserved.

`/etc/sing-box/config.jsonc` is user-managed, not generated from `config.yml`. The API checks writes with `sing-box check` when installed. Every apply attempts to start/restart sing-box; failures are fatal when its configuration exists and otherwise logged as optional-service warnings.

The authoritative schema is `src/config/schema.rs`; validation lives in `src/config/validator.rs`. The runtime `config/` directory is gitignored, not a checked-in schema/example. Section updates replace that section rather than merging individual fields.

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --init -c config --listen 127.0.0.1:8443

# Check code
cargo clippy

# UI validation and embedded asset refresh after web changes
cd web && bun run test && bun run check && bun run build
```

The development Vite proxy has a router-specific address in `web/vite.config.ts`; set it to your backend before using `bun run dev`. The dev server binds to loopback by default. See `web/README.md` for the frontend workflow and Yacd-meta design attribution.

## License

MIT

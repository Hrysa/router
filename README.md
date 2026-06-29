# routerd — Linux Router Daemon

A Linux-based router system built with Rust, nftables, and Debian. API-centric architecture where a single `config.yml` manages all network services.

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed system overview and component documentation.

## Features

- **systemd-networkd** — network interface management (bridge, VLAN, DHCP, static)
- **nftables** — firewall, NAT, port forwarding, blackhole lists
- **ISC DHCP** — DHCP server with static leases
- **Unbound** — recursive/forwarding DNS, DNSSEC, local zones, ad blocking
- **PPPoE** — WAN connection with auto-reconnect
- **WireGuard** — VPN with peer management
- **Monitoring** — interface stats, traffic, conntrack, system resources
- **Backup/Restore** — automatic config backups with rollback
- **REST API** — full CRUD on all config sections
- **SPA Web UI** — Svelte 5 dashboard (coming soon)

## Quick Start

### Build

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Build
cargo build --release
```

### Run

```bash
# With existing config directory
./target/release/routerd -c /etc/router

# First run (auto-detects interfaces, writes config.yml, enables systemd-networkd)
sudo ./target/release/routerd -c /etc/router

# Development (uses ./config/ as default)
cargo run
```

### Init Setup (first run)

When `config.yml` doesn't exist in the config directory, routerd will:

1. Check that `systemd-networkd.service` is available
2. Detect current network interfaces from the running system
3. Disable `networking.service` (ifupdown) if present
4. Write `.network`/`.netdev` config files to `/etc/systemd/network/`
5. Enable and start `systemd-networkd.service`
6. Write `config.yml` with detected configuration

### Configure via API

```bash
# Login (returns JWT token)
curl -k -X POST https://localhost:8443/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"password": "admin123"}'

# Get current config
curl -k -H "Authorization: Bearer <token>" https://localhost:8443/api/config

# Update PPPoE credentials
curl -k -X POST https://localhost:8443/api/config/interfaces \
  -H "Content-Type: application/json" \
  -d '{
    "wan": {
      "name": "eth0",
      "method": "pppoe",
      "pppoe": {
        "username": "user@isp",
        "password": "secret",
        "mtu": 1492,
        "mss_clamp": true,
        "keepalive_interval": 10,
        "keepalive_failure": 3
      }
    },
    "lan": {
      "name": "br-lan",
      "bridge_ports": ["eth1", "eth2", "eth3", "eth4"],
      "method": "static",
      "static_config": {
        "address": "192.168.1.1/24"
      }
    },
    "vlans": []
  }'

# Apply config (renders all service configs + restarts services)
curl -k -X POST -H "Authorization: Bearer <token>" https://localhost:8443/api/config/apply

# Check service status
curl -k -H "Authorization: Bearer <token>" https://localhost:8443/api/services
```

## CLI Options

```
routerd [OPTIONS]

Options:
  -c, --config-dir <DIR>   Config directory [default: config]
      --listen <ADDR>      API server listen address [default: 0.0.0.0:8443]
      --log-level <LEVEL>  Log level: trace, debug, info, warn, error [default: info]
      --log-format <FMT>   Log format: text, json [default: text]
      --init               Allow first-boot initialization when config.yml is missing
      --tls-cert <PATH>    TLS certificate (PEM)
      --tls-key <PATH>     TLS private key (PEM)
  -h, --help               Print help
```

## API Endpoints

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
| POST | `/api/config/system` | Update system section |
| POST | `/api/config/interfaces` | Update interfaces |
| POST | `/api/config/firewall` | Update firewall rules |
| POST | `/api/config/dhcp` | Update DHCP config |
| POST | `/api/config/dns` | Update DNS config |
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

## Config Directory

All configuration lives in a directory (default: `./config/` or `/etc/router/`):

```
config/
├── config.yml      # Main config (API server owns this)
└── backups/        # Automatic timestamped backups
```

All service configs are **generated** from `config.yml`:
- `/etc/systemd/network/50-routerd-*.network` — systemd-networkd
- `/etc/nftables.conf` — nftables
- `/etc/dhcp/dhcpd.conf` — ISC DHCP
- `/etc/unbound/unbound.conf.d/router.conf` — Unbound
- `/etc/ppp/peers/isp` — PPPoE
- `/etc/wireguard/wg0.conf` — WireGuard

See `config/config.yml` for the full schema with documentation.

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- -c config

# Check code
cargo clippy
```

## License

MIT

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

## System routes

The **Routes** page manages persistent IPv4 and IPv6 routes by destination, gateway,
configured interface, routing table and metric. It also shows a read-only view of
live kernel routes across all tables. This view includes routes from other tools;
routerd only edits its saved route declarations. Saving, disabling or deleting a
route changes configuration only; use **Apply** to activate the change. Normal
startup reapplies saved routes through systemd-networkd.

Use **Main (254)** for ordinary system routing, affecting both router-originated
connections and LAN forwarding that uses system routing. A more-specific route
wins over a default route; lower metrics win among equally specific routes in the
same table. **Route via WAN** uses the WAN's own table, so add gateway overrides
there when traffic is explicitly assigned to that WAN. Choosing a custom numeric
table does not create a policy rule to select it. IPv6 static routes do not add
IPv6 WAN policy routing.

For example, this configuration fragment sends one destination through an existing
configured `enp3s0` interface and reachable gateway:

```yaml
routing:
  routes:
    - id: 1
      destination: 198.51.100.10/32
      interface: enp3s0
      gateway: 192.0.2.1
      table: 254
      metric: 100
      enabled: true
```

Bare destination IPs are accepted as host routes. Omit `gateway` for a directly
connected route; set `on_link: true` only when an otherwise off-subnet gateway is
directly reachable. For PPPoE, select the configured physical interface; the route
is attached to `ppp0`. Only configured interfaces are supported. Gateways must
match the destination family. Tables 0, 253, 255 and active TPROXY tables are
reserved; 254 is the main table. Enabled routes with duplicate prefix/table/metric
keys and known metric-0 collisions with automatically generated routes are rejected.
Avoid duplicating routes already managed by other tools. Existing default routes
can have metric 0, so a new default with metric 100 will not override them.
Multipath routes, policy-rule editing and importing/deleting foreign live routes
are not supported by this page. Apply remains nontransactional.

## Multi-WAN return routing and hairpin NAT

IPv4 WAN return routing is enabled by default for static, DHCP and PPPoE WANs.
Each WAN receives a stable table ID derived from its interface name (10000–59999).
**Interfaces → WAN return routing table** provides an optional explicit override.
The corresponding interface field is `return_route_table`, for example:

```yaml
name: enp3s0
method: static
static_config:
  address: 203.0.113.2/29
  gateway: 203.0.113.1
return_route_table: 100
```

This is an interface fragment, not a complete configuration. Preserve the other
interface fields when updating it. Save, review, then explicitly Apply. Routerd
renders networkd routes and policy rules plus nftables connection marking; a
separate startup script is not needed for this feature. It does not change which
main-table default route ordinary outbound traffic uses or pair LANs with WANs.
Only destinations in configured static internal IPv4 subnets (including LANs,
bridges and VLANs without a gateway) may consult non-default main-table routes
first. Other destinations go directly to the selected WAN table, so a more-specific
route through another WAN or VPN cannot override the return policy. Unmarked
traffic that does not match the WAN source-address policy keeps normal routing.

Static WANs require an IPv4 address and an on-subnet IPv4 gateway. DHCP return
routes follow the leased gateway; PPPoE routes follow the managed `ppp0` tunnel
(including reconnects). Only one managed PPPoE connection is supported. IPv6
return routing is not implemented; use `return_routing: false` to opt out, including
for IPv6-only static WANs. Automatic ID collisions fail validation: assign a unique
manual override when necessary. IDs
must be 1–65535, excluding 253–255, and cannot overlap TPROXY routing tables.
Reserve policy priorities 100 and 110 and the upper 16 packet/connection mark
bits for this feature. When enabled, TPROXY marks must fit in the lower 16 bits.
Choose tables not used by other host tooling. Changing a table ID can interrupt
existing connections; verify with new connections after applying.

To choose an outbound WAN, set **Firewall → Forward rules → Accept → Route via WAN**.
“System routing” leaves route selection unchanged. The optional `route_via` field
names the configured WAN interface (the PPPoE physical interface name, not `ppp0`):

```yaml
id: 20
action: accept
interfaces: [br-lan]
saddr: 192.168.2.0/24
route_via: enp3s0
```

Add this rule to `firewall.rules.forward`; preserve existing rules and unique IDs.
The first matching enabled WAN-selection rule selects a WAN for each new IPv4
outbound connection. Filter verdicts still follow normal forward-rule order;
choosing a WAN does not bypass a drop rule. Existing marked connections retain
their WAN when selectors are reordered or retargeted. Local/router destinations,
WAN ingress and DNAT/hairpin traffic are excluded; TPROXY takes precedence.
**Preserve internal routes** defaults to enabled: configured LAN/VLAN subnets
keep normal routing. Disable it to apply the rule's full destination match,
including internal subnets. The saved field is `preserve_internal_routes: false`.
Those connections use the selected WAN table before `main`'s internal exceptions:
its default gateway is used unless that table has a more-specific route. Add an
appropriate route to that WAN table to keep a LAN destination directly reachable.
Router-owned addresses, DNAT/hairpin and TPROXY remain excluded in either mode.
The mode is pinned per connection; test changes with a new connection. Replies
route normally back to clients.

Targets must have WAN return routing enabled. WAN selection cannot be combined
with an egress-interface match or rate limit; a connection-state filter must include
`new` or be empty. Address filters must use IPv4 addresses/subnets or IPv4 named
sets. An existing `oif` is only an egress match and never selects a route.
Masquerade remains a separate NAT setting; PPPoE egress masquerade uses `ppp0`.
The rule editor and forward-rules page warn when a selected WAN lacks masquerading.
For private LAN Internet access, enable the actual WAN egress under **Policies & NAT
→ Masquerade egress interfaces**, retaining other WANs. Routed upstream networks
can intentionally operate without NAT; the warning does not block saving.
If the selected route disappears, an egress guard before established-connection
acceptance drops packets that would leave another interface; there is no automatic
failover. With internal-route preservation disabled, global policy rules at
priorities 90/91 select the WAN table or return unreachable if it has no route;
there is no fallback to `main`. More-specific routes in that WAN table may use a
LAN interface. These rules use distinct upper-bit marks, preserving low mark bits,
and remain independent of WAN link state. Reserve priorities 90 and 91 as well.
Removing all WAN-selection rules disables outbound pinning and its guards.
This feature does not select routes for router-generated traffic or IPv6.

Hairpin masquerading covers all configured static internal IPv4 subnets,
including VLANs and bridges. It is restricted to DNAT traffic from the server's
own subnet leaving through that subnet's interface; external and routed
cross-subnet clients retain their source addresses unless another masquerade rule
applies. Port forwards must explicitly include the permitted LAN/VLAN ingress
interfaces and public destination address; routerd does not expand ingress
permissions automatically. Forward-chain policy must also allow the traffic.

Previously installed custom nftables tables and policy rules are not removed by
routerd. Review old workaround scripts/rules separately when migrating, with
console access available; applying network configuration is not transactional.

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
| GET / PUT | `/api/config/routing` | Get route settings/resolved WAN tables / replace routing section |
| POST | `/api/config/routing/routes` | Create a route (server assigns ID) |
| PUT / DELETE | `/api/config/routing/routes/:id` | Update / delete a saved route |
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
| GET | `/api/monitor/routes` | Read live IPv4/IPv6 routes across all kernel tables |
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

Interface MTU and TCP MSS settings are independent of WAN/LAN role. Optional
`interfaces.items[].mtu` sets the device MTU through networkd, including bridge
and VLAN creation MTUs; PPPoE keeps its separate `pppoe.mtu` tunnel MTU. Explicit
values range from 1280 to 9216 bytes. Hardware and parent/member link limits still
apply. An unset device MTU leaves networkd/kernel defaults in control; removing
an override does not guarantee an immediate reset of an existing link's MTU.

Optional `mss_clamp_mtu` caps TCP MSS using a configured path MTU: IPv4 subtracts
40 bytes and IPv6 subtracts 60. For example, 1492 yields MSS 1452/1432. Rules only
lower existing MSS options on SYN/SYN-ACK packets and apply on device ingress and
egress, including router-local and routed traffic. Pure bridge switching is not
covered; MSS does not resize UDP packets or replace path MTU discovery. Blank
means off, except the existing PPPoE `mss_clamp` default still derives a cap from
its tunnel MTU; an explicit `mss_clamp_mtu` overrides that cap and targets `ppp0`.
Clamping is rendered as nftables JSON rather than pppd options. A PPPoE parent
with an explicit device MTU is managed by networkd without DHCP or link-local
addressing so that the MTU can be applied. WebUI settings are under Interfaces →
Edit; Save and Apply remain separate. No MTU or MSS value is inferred from WAN role.

### Traffic shaping

The **Traffic shaping** page configures CAKE shared upload/download rates per
interface, with NAT-aware per-IP/flow fairness. New profiles are disabled. Enter
90–95% of the measured sustained capacity, save, then Apply. One active IP can
use spare capacity; multiple busy IPs share it instead of receiving fixed caps.
Rates are shown in decimal Mbit/s and stored as `upload_kbit` / `download_kbit`.
Zero disables a direction. Optional overhead, minimum packet size, and ATM/PTM
framing account for the access link; defaults do not guess modem encapsulation.

`GET /api/config/shaper` reads `shaper.profiles`; `PUT /api/config/shaper`
replaces that section and saves without applying. Each profile has a stable,
nonzero unique `id`, a configured `interface`, and an `enabled` flag. `side: wan`
means upload is egress and download is ingress; `side: lan` reverses those roles
for client-facing shaping. PPPoE names resolve to `ppp0`. Only one enabled
profile may target each device. `GET /api/monitor/shaper` reports owned live
queues, cumulative bytes/packets, backlog, drops, ECN marks, queue delay, and the
last shaper error; the WebUI derives throughput from successive samples.

The service uses Linux rtnetlink directly, with no `tc` runtime dependency. The
kernel must provide CAKE, IFB, ingress, matchall, and mirred support. WAN ingress
uses a managed IFB; WAN egress uses `nat dual-srchost`, and download uses
`nat dual-dsthost`, in best-effort mode. Existing custom traffic control is a
conflict, not silently replaced. Disabling or deleting a profile removes only
its owned resources on Apply; kernel defaults resume afterward. Missing devices
remain pending and are retried every five seconds after successful Apply.

Fairness is per IP and per profile, not a global quota across multiple WANs.
Upstream NAT and router proxies can conceal original clients; use a LAN-facing
profile for client fairness across proxy traffic, accounting for double shaping
if WAN profiles are also enabled. A bridge profile does not automatically cover
all traffic switched between its member ports. A configured download rate cannot
prevent packets from consuming capacity on the upstream link before arrival.

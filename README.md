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
- **sing-box integration** — raw JSONC stored in routerd configuration, deployed on Apply

DHCP reclaimed-lease retention is editable in **DHCP & leases → Lease reclamation**.
`dhcp.hold_reclaimed_time` defaults to 3600 seconds (1 hour); 0 disables retention.
It renders as Kea’s server-wide `expired-leases-processing.hold-reclaimed-time`.
Save preserves pools and reservations; Apply activates the setting.

Active lease rows offer **Delete**, with confirmation. This takes effect immediately,
without Apply, and preserves saved reservations. Disconnect the client first:
deleting the server record does not revoke the client's address, which Kea can
then assign elsewhere. The renderer loads `libdhcp_lease_cmds.so` when installed
in standard Kea hooks directories (`/usr/lib/{x86_64-linux-gnu,aarch64-linux-gnu}/kea/hooks`,
`/usr/lib/kea/hooks`, `/usr/lib64/kea/hooks`, or `/usr/local/lib/kea/hooks`).
After installing that hook, Apply to load it. Deletion reports an error when the
hook or `/run/kea/kea-dhcp4.sock` is unavailable; routerd never edits live lease CSV files.


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

### Automated builds and releases

[Build and release](.github/workflows/release.yml) runs on pull requests, pushes
to `main`, and version tags (`v*` starting with a digit). It installs frontend
dependencies from the frozen Bun lockfile, runs frontend tests/type checks,
builds `web/dist/`, then runs Rust tests, Clippy, and formatting checks. Binary
jobs download that exact UI build before compiling it into the release binaries.

Successful builds produce Linux x86-64 and ARM64 musl archives with embedded UI,
README/architecture documentation, and SHA-256 checksums. Download them from the
workflow's artifacts; no separate web directory is needed. The archives contain
no runtime configuration, credentials, sing-box binary, or system service changes.
The GitHub-hosted ARM64 runner requires a public repository or a plan supporting
that runner. Rust remains on the stable channel; dependency lockfiles are enforced.

To publish a GitHub Release after committing and pushing your changes:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Choose a new version tag for each release and update the Cargo package version
when appropriate. A tag containing `-`, such as `v0.2.0-rc.1`, publishes a
prerelease. Publication waits for checks and both binary builds, then verifies
archive checksums and uploads assets using the built-in `GITHUB_TOKEN`; no
additional publishing secret is required. Manual **Run workflow** builds artifacts
without publishing a release. The workflow never deploys to a router.

### Run

```bash
# Normal startup: other network setup, but no nftables or sing-box apply
sudo ./target/release/routerd -c /etc/router --listen 127.0.0.1:8443

# Firewall-only startup, then serve the UI/API; sing-box is left to systemd
sudo ./target/release/routerd --boot -c /etc/router --listen 127.0.0.1:8443

# First run (creates a draft config and starts the UI, preserving host networking)
sudo ./target/release/routerd --init -c /etc/router --listen 127.0.0.1:8443

# Development (uses ./config/ as default)
cargo run -- --init --listen 127.0.0.1:8443
```

### Init Setup (first run)

Run with `--init` to create `config.yml` if missing and start the web UI/API while preserving the current networking setup. Without `--init`, a missing config is an error.

Initialization detects interfaces and saves a **draft** router configuration. It does not write system service configs, switch network managers, change NIC offloads, run startup hooks, or apply firewall/routing changes. Existing `config.yml` files are kept when `--init` is used again.

Review the draft before using `POST /api/config/apply`: the generated LAN address is `192.168.1.1/24` and the default firewall/NAT rules are router defaults, not a full import of the host's current setup. Applying changes explicitly takes over the configured services.

Keep `--init` on subsequent starts to continue skipping startup changes. Normal startup reconciles saved interface, DHCP, PPP, WireGuard, sysctl, routing, and shaping configuration, changes NIC offloads, and runs startup hooks, but does not check/install nftables rules or read/control sing-box. Manage sing-box startup with systemd.

`--boot` instead validates the saved configuration, checks and installs only its nftables JSON, then serves the UI/API. It skips other service reconciliation, generated-file writes, sysctl, routes, shaping, NIC offloads, and startup hooks; it never controls sing-box. It requires an existing config and cannot be combined with `--init` or `--install-singbox`. This is a running daemon mode, not a one-shot command. TPROXY/WAN policy routes and other non-firewall setup must already be provisioned separately or through an explicit full Apply.

Normal startup, `--boot`, and explicit Apply require root for their host changes. `nft` is mandatory for `--boot` and explicit Apply, but not normal startup; Kea's syntax check runs only when `kea-dhcp4` is installed during normal startup or full Apply. Initialization needs at least two available network interfaces to generate its WAN/LAN draft.

### sing-box config/unit setup

After saving JSONC under `singbox.config` in your routerd configuration:

```bash
sudo ./target/release/routerd --install-singbox -c /etc/router
```

This reads `/etc/router/config.yml` and **always overwrites both** `/etc/sing-box/config.jsonc` (`0600`) and `/etc/systemd/system/sing-box.service` (`0644`), even when the files already exist or have identical contents. Comments and whitespace in saved JSONC are preserved. Missing or empty `singbox.config`, unreadable configuration, and invalid YAML fail before either destination is changed. The source configuration, backups, and authentication state are not modified. Each replacement is atomic, but the two-file operation is not transactional: a later write failure can leave the config replaced without the unit.

After both writes succeed, setup runs `systemctl daemon-reload` with a 30-second timeout. A nonzero exit, execution error, or timeout fails the command and reports that the files are already installed; no reload is attempted after input/write failures. It does not enable, start, or restart sing-box.

No sing-box binary is downloaded, installed, replaced, or executed. Install it separately at `/usr/local/bin/sing-box`, which the generated unit uses. Setup does not run `sing-box check`, startup hooks, networking changes, or the API server. Validation with `sing-box check` remains part of editor Save and full Apply when the binary is installed. Enable/start the unit separately when ready. `--install-singbox` cannot be combined with `--init` or `--boot`.

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

## Proxy eligibility before transparent proxying

TPROXY candidates now pass the ordered forward access policy before interception.
Accept rules permit proxy processing. Drop, Reject, and a Drop default instead
bypass interception so the normal forward chain performs the actual filtering,
logging, and counting. The existing established/related shortcut under a drop
policy is preserved. TPROXY rules select traffic;
they do not grant access by themselves.

The eligibility check emits no Drop or Reject verdicts. Its nftables Accept
verdict exits only the prerouting base chain; it does not grant forwarding access.
The normal forward chain drops or rejects the unproxied packet. Rules with
an outgoing-interface match or a rate limit also defer to normal forwarding,
without interception, so their routing-dependent matches and token buckets stay
in the original chain. Prerouting checks use the original destination before DNAT.
Router-owned destinations retain input policy. Proxy selectors support IPv4 TCP/
UDP; outgoing-interface matches and rate limits belong in forward policy rules,
not TPROXY selectors.

Admitted non-local proxy traffic receives a narrow input exception requiring its
configured packet mark and a transparent socket. Other local traffic keeps the
normal input rules. Counters sum ordinary forwarding and proxy admission under
the same rule IDs. Sing-box's new outbound connections still traverse output;
this change does not add local-output WAN selection or failover.

## CLI Options

```
routerd [OPTIONS]

Options:
  -c, --config-dir <DIR>   Config directory [default: config]
      --listen <ADDR>      API server listen address [default: 0.0.0.0:8443]
      --log-level <LEVEL>  Log level: trace, debug, info, warn, error [default: info]
      --log-format <FMT>   Log format: text, json [default: text]
      --init               Create config if missing; start UI/API without changing networking
      --boot               Check/install only nftables, then start UI/API
      --tls-cert <PATH>    TLS certificate (PEM)
      --tls-key <PATH>     TLS private key (PEM)
      --install-singbox    Overwrite sing-box config/unit, run daemon-reload, then exit; no download
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
| GET | `/api/status/system` | Cumulative CPU counters and memory usage |

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
| GET / PUT | `/api/singbox/config` | GET saved `{raw}`; PUT raw JSONC into `config.yml` without deploying |
| POST | `/api/config/validate` | Validate config |
| GET | `/api/config/apply/status` | Read saved-versus-applied status (`pending`) |
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
| DELETE | `/api/dhcp/leases/:address` | Immediately delete an active IPv4 lease through Kea |
| GET | `/api/metrics` | Interface/firewall time series (2-second samples, up to 30 minutes) |
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
- `/etc/ppp/ip-up.d/50-routerd-wan-routing` — executable PPP IPv4 return-route hook (`0700`)
- `/etc/ppp/peers/isp` and `/etc/ppp/chap-secrets` — PPPoE, managed through `ppp@isp.service` (requires the distribution’s `ppp@.service` template)
- `/etc/wireguard/wg0.conf` — WireGuard
- `/etc/sysctl.d/90-routerd.conf` — kernel network settings
- `/etc/sing-box/config.jsonc` — raw `singbox.config` JSONC, written on explicit full Apply or `--install-singbox` setup

nftables is rendered as JSON and applied with `nft -j -f`; no `/etc/nftables.conf` is generated. Routerd replaces only its four owned tables (`inet filter`, `ip nat`, `inet mangle`, `inet blackhole`); do not place unrelated rules in those tables. Other nftables tables are preserved. Normal startup leaves live rules untouched; use `--boot` to restore saved rules after reboot. After a successful full Apply, unchanged rendered rules are skipped on subsequent applies, preserving their counters. `--boot`, the first explicit full Apply in a process (regardless of startup mode), and forced backup restores always install the rules. Required syntax validation runs for each of these firewall operations. This in-memory comparison does not detect external modifications to live nftables tables.

sing-box JSONC is stored verbatim in `config.yml` under `singbox.config`, preserving comments and whitespace and including it in routerd backups/restores:

```yaml
singbox:
  config: |
    {
      // Preserved in the deployed file
      "log": { "level": "info" }
    }
```

`GET /api/singbox/config` reads this saved value, not `/etc/sing-box/config.jsonc`. `PUT` accepts raw JSONC, checks it with `sing-box check` when installed, and saves only `config.yml`; neither the deployed file nor the service changes until explicit full Apply. Full Apply validates again, compares the saved JSONC with the deployed file and last successful snapshot, atomically writes `/etc/sing-box/config.jsonc` at `0600` when needed, then restarts an active service on change or first/forced Apply, or starts it if inactive. Missing deployed files are recreated; other read errors and all configured-service failures propagate. Direct deployed-file edits are overwritten by the saved value on explicit Apply, not imported into routerd.

Existing configurations without a `singbox` section remain valid and leave the deployed file/service unmanaged. To migrate, paste the existing `/etc/sing-box/config.jsonc` contents into the WebUI sing-box editor and Save before Apply; there is no automatic import. Empty `singbox.config` is rejected. Omitting the whole section leaves existing deployed files/services untouched, including when restoring an older backup without that section. All startup modes still skip sing-box deployment/control; systemd manages its boot lifecycle. The service-content snapshot is published only after complete full-Apply success; failures/cancellation leave retry available. Neither normal startup nor firewall-only `--boot` publishes a full-Apply snapshot.

The authoritative schema is `src/config/schema.rs`; validation lives in `src/config/validator.rs`. The runtime `config/` directory is gitignored, not a checked-in schema/example. Section updates replace that section rather than merging individual fields.

The WebUI polls `GET /api/config/apply/status` every five seconds and refreshes it after writes. The read-only endpoint compares saved typed configuration, including `singbox.config`, with the last successful in-process Apply. It does not read the deployed JSONC file. Apply is disabled when unchanged, while checking status, or if status cannot be read; first applies and retries after failed applies remain available. Same-content saves and saved reversions do not require Apply. This tracks saved-versus-applied configuration, not unsaved editor drafts, external edits to generated service files, or live service/kernel health; use explicit API Apply to reconcile generated-file drift and service controls for live recovery. Startup hooks still require normal daemon startup. The API Apply endpoint remains available for explicit reconciliation.

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- --init -c config --listen 127.0.0.1:8443

# Check code
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check

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

PPPoE start/restart requests use `systemctl --no-block` for `ppp@isp`. Apply and
manual service controls wait only for job submission, not for dialing or reconnects.
Submission errors still fail the request; later connection failures are reported by
service status and the PPP journal. Successful Apply does not imply PPP connectivity.

### WAN groups

The **WAN Groups** page combines tiered failover with weighted source-IP modulo selection
for IPv4 forwarded traffic. Members reference configured WAN interface names
(including the physical name for PPPoE), require WAN return routing, and have a
positive tier and a weight from 1 to 100. The lowest tier containing healthy
members is active. Weights apply only within that tier: weights 3 and 1 produce
75% and 25% of the 256 source-IP slots. Selection uses `numeric_source_IP % 256`
(the last IPv4 octet), with weighted slots interleaved across the cycle. Two equal
WANs alternate even/odd addresses. Weight shares that do not divide 256 are
rounded using largest remainders; three equal WANs get 86/85/85 slots. Consecutive
addresses balance predictably, but arbitrary active addresses and bandwidth may
still be uneven. No per-client assignment state is stored.
Select `Group: <name>` in a forward Accept rule's **Route via WAN** control.
Existing individual-WAN rules continue to work. Masquerade is configured separately
for every member's egress device; PPPoE uses `ppp0`.

Groups are saved in the optional top-level `wan_groups` list. For example:

```yaml
wan_groups:
  - id: 1
    name: Internet
    members:
      - { interface: wan0, tier: 1, weight: 3 }
      - { interface: wan1, tier: 1, weight: 1 }
      - { interface: wan2, tier: 2, weight: 1 }
    targets: [1.1.1.1, 8.8.8.8]
    interval_seconds: 5
    timeout_seconds: 2
    failure_threshold: 3
    recovery_threshold: 2
    recovery_delay_seconds: 10
```

A firewall rule references the group with `route_via: "group:1"`. Save and then
Apply; saving alone never activates monitoring or changes networking. Each member
is probed through its marked IPv4 routing table and bound egress interface; any
one target answering ICMP makes a probe round successful. Install `ip` and `ping`
and choose reachable ICMP targets. A round waits for each target only until one
answers; the configured interval follows completion of the round. Failure and
recovery thresholds plus the recovery delay prevent rapid switching.

Monitoring activates after successful full Apply or nftables installation with
`--boot`; normal startup and `--init` do not activate it. WAN addresses and policy
routes must already exist for boot-mode probes to succeed; `--boot` does not set
up routing. New maps block matching traffic until probes establish a healthy tier.
When all members are unavailable, new matching connections are blocked. Existing
connections retain their WAN even after tier changes; a failed WAN's connections
usually need to reconnect because their public address changes. IPv6 and
router-originated group selection are not implemented.

- `GET /api/config/wan-groups`: saved group list.
- `PUT /api/config/wan-groups`: replace the full list, save only. Group IDs are
  nonzero and unique; remove firewall references before deleting a group.
- `GET /api/monitor/wan-groups`: active monitoring, errors, installed group tiers,
  member health, and installed bucket shares. These shares describe the last
  successful map update, not measured traffic or live kernel drift.

PPPoE peers carry `ipparam routerd-isp`. The managed
`/etc/ppp/ip-up.d/50-routerd-wan-routing` hook restores `default dev ppp0` in the
configured WAN return table after IPv4 negotiation and every reconnect. This
avoids relying solely on routes installed before pppd finishes configuring its
address. The hook requires the standard `/etc/ppp/ip-up` dispatcher to run
`ip-up.d` scripts (the Debian default); a custom `ip-up.local` override must also
run this dispatcher or hook. It only handles the tagged `ppp0` connection and
leaves the main default route and other table prefixes unchanged. With PPP WAN
return routing disabled, the generated hook is a no-op. A connected PPP interface
without its dedicated-table default remains unavailable to WAN groups.

Shaper profiles can move between interfaces, including to/from PPPoE. Apply
validates the previous ownership record, removes the old owned shaping state,
and recreates it on the selected interface. PPP interface-index changes follow
the same cleanup path. Unjournalled IFBs and foreign queues/filters remain
conflicts and are never adopted merely by matching a name.

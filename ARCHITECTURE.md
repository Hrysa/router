# Architecture

## System Overview

routerd is a Linux router daemon that manages network services through a unified YAML configuration. It uses **systemd-networkd** for interface management. Router-managed service files are generated from `config.yml`; sing-box JSONC is stored verbatim in `singbox.config` and deployed on explicit full Apply or `--install-singbox` setup.

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
| PPPoE | `ppp@isp` | `/etc/ppp/peers/isp`, `/etc/ppp/chap-secrets`, `/etc/ppp/ip-up.d/50-routerd-wan-routing` | WAN `interfaces.items[].method: pppoe` with nonempty username |
| Proxy | `sing-box` | `/etc/sing-box/config.jsonc` from `singbox.config` | Full Apply only, when `singbox` exists: start if inactive; restart on change or first/forced Apply |

Disabled DHCP/PPP/WireGuard services are stopped if active, not started from stale on-disk configuration. `vnstat` has manual API service controls, but `monitoring.vnstat` is not wired into the apply pipeline.

DHCP reclaimed-lease retention is editable in **DHCP & leases → Lease reclamation**.
`dhcp.hold_reclaimed_time` defaults to 3600 seconds (1 hour); 0 disables retention.
It renders as Kea’s server-wide `expired-leases-processing.hold-reclaimed-time`.
Save preserves pools and reservations; Apply activates the setting.

Kea rendering discovers the optional installed `libdhcp_lease_cmds.so` in standard
multiarch, `/usr/lib`, `/usr/lib64`, and `/usr/local/lib` Kea hooks directories and
includes it in `hooks-libraries`. Active lease deletion uses the authenticated
`DELETE /api/dhcp/leases/:address` route, validates IPv4 input, and holds the store
operation lock while sending `lease4-del` to `/run/kea/kea-dhcp4.sock`. Socket I/O
has a five-second timeout and a 64 KiB response limit; failed, unsupported, empty,
and malformed replies never report success. This is an immediate runtime action;
it does not save config, delete reservations, restart Kea, or edit lease files.
The CSV reader applies the last record per address before filtering, so deletion
tombstones, reclaimed records, and shortened leases supersede older active rows.

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
| `routes.rs` | Saved static `[Route]` sections appended to managed `.network` files |
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
| `singbox.rs` | Config/unit installation and systemd daemon reload; staged JSONC validation and private atomic deployment |

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

`src/metrics/mod.rs` samples interface and firewall counters every two seconds and retains up to 900 samples (30 minutes). The Overview and Monitoring pages refresh metrics and live interface counters every two seconds; Overview refreshes CPU and memory statistics at the same cadence. `/api/status/system` returns cumulative CPU counters: idle includes I/O wait, and total excludes the guest fields already included in user/nice time. Overview computes CPU utilization from successive counter deltas, normalized across all cores; it waits for two valid samples and clears the percentage for failed requests, missing/unchanged counters, or counter resets. `/api/metrics` supplies aligned series for the uPlot charts; `/api/metrics/current` returns the latest sample.

System/interface details and Kea CSV lease reads live in `src/api/handlers/monitor.rs` and `src/api/handlers/status.rs`. `/api/monitor/traffic` and `/api/monitor/connections` remain placeholders. The empty, unused `src/monitor/` module tree has been removed; live collection stays in the metrics module and API handlers.

### CLI (`src/main.rs`)

`--install-singbox` exits through a separate config/unit setup path before store initialization or daemon startup. It reads `<config-dir>/config.yml`, requires nonempty `singbox.config`, and unconditionally atomically replaces `/etc/sing-box/config.jsonc` at `0600` and `/etc/systemd/system/sing-box.service` at `0644`. Only after both writes succeed does it run `systemctl daemon-reload`, with a 30-second timeout and cancellation-safe child cleanup. Execution failures, nonzero exits, and timeouts propagate with a warning in the error that files are already installed. Source/write failures skip reload, and the two replacements are not a transaction. It neither downloads nor executes/replaces the sing-box binary, creates backups/authentication state, starts the API, nor changes networking. The unit expects an independently installed `/usr/local/bin/sing-box`; enable/start/restart remains an administrator operation. JSONC external validation remains on editor Save/full Apply, not this installer. Install mode conflicts with `--init` and `--boot`. Regression tests inject a fake systemctl executable and temporary source/destination paths, never a live systemd reload.

Entry point with clap argument parsing. Orchestrates startup: parse args → init if needed → load and validate config → selected startup mode → start API server. Normal startup reconciles other saved service/network configuration, NIC offloads, and hooks, but skips nftables checks/install and all sing-box reads/status/control. `--init` skips all startup host changes. `--boot` checks and installs only nftables from the existing saved config, then starts the API; it conflicts with `--init` and `--install-singbox`. Boot mode does not write generated service files, reconcile other services, apply sysctl, restore TPROXY/WAN policy routes or shaping, change offloads, or run hooks. These non-firewall dependencies must be provisioned separately. All modes leave sing-box startup to systemd; explicit API Apply and restore retain full reconciliation.

---

## Apply Pipeline

```
POST /api/config/apply / explicit backup restore (full Apply)
    → validate schema
    → render all service configs
    → stage syntax checks: nft -j -c -f required; kea-dhcp4 -t if installed
    → detect rendered content differences against disk and last successful in-memory config
    → compare nftables JSON and saved sing-box JSONC against last successful service-content snapshot
    → compare saved sing-box JSONC with its deployed file when configured
    → write changed configs (exclusive random staging file + rename)
    → start enabled services if inactive; reload/restart changed services
        - nftables: nft -j -f <staged JSON> only when changed or first/forced apply
        - systemd-networkd: networkctl reload (fallback: systemctl restart)
        - others: systemctl restart
    → reconcile IPv4 TPROXY policy routing
```

Normal startup shares the full pipeline's other service/network steps, but skips the external nftables syntax check, nftables installation, and all sing-box reconciliation. Firewall-only `--boot` uses a separate schema validation → nftables render → required `nft -j -c -f` → `nft -j -f` path, without the rest of the pipeline. Neither partial startup path publishes a full-Apply service-content snapshot.

API mutations, service controls, apply, and restore share an operation lock. Read-modify-write requests cannot overwrite one another, and service applies cannot overlap. Individual config saves also hold the store's write lock through disk replacement and in-memory publication. Backups use unique timestamp/UUID IDs, and restore rejects IDs containing path separators.

External syntax validators are required nftables, optional-when-absent Kea, and optional-when-absent `sing-box check -c <staged JSONC>` for configured sing-box on full Apply. PPP, WireGuard, networkd, and sysctl rely on `src/config/validator.rs`. Service command failures, sysctl failures, and TPROXY setup failures propagate instead of reporting a successful apply. An absent `singbox` section means its deployed file and service are left unmanaged; configured sing-box validation/write/start/restart failures propagate.

There is no automatic transactional rollback after failure: earlier file writes and service changes may persist. The in-memory last-successful configuration snapshot is not a durable applied-state journal; it is initialized from the saved configuration at process startup. Separate service-content snapshots for nftables JSON and saved sing-box JSONC start unknown, so the first explicit full Apply always reconciles nftables and configured sing-box, regardless of startup mode. They are invalidated when an apply attempt begins and published only after all full-Apply steps succeed; failed or cancelled attempts therefore cannot skip reconciliation on retry, including after a config revert. Forced backup restore bypasses these content comparisons. Unchanged running sing-box is left alone; configured inactive sing-box is started. Missing/drifted JSONC is replaced from saved configuration, and read errors other than absence propagate. nftables syntax checking still runs on full Apply even when its rules are unchanged; no live kernel-ruleset comparison is performed, so external modifications to owned tables require `--boot` or forced restore to reinstall unchanged rules. Normal startup never restores those tables. Keep console access and review configuration before applying network changes.

The sing-box API preserves raw JSONC in `singbox.config`: GET returns the saved text, and PUT validates an isolated `0600` staging file when the binary exists, then saves only routerd configuration under the operation lock. Save creates normal config backups; restore includes this text. Full Apply stages validation again, then atomically deploys the exact text at `0600` before service reconciliation. Empty text is rejected. Existing deployed JSONC is not automatically imported: paste it into the WebUI and Save to migrate. An absent section, including an older backup, leaves existing external files/services untouched. Startup modes never read or write the deployed sing-box file, validate it externally, or control its service.

### nftables Layout

The renderer emits a single JSON transaction. It resets only the four table names it owns (add-if-absent, delete, then recreate as needed), preserving all other tables. `inet filter` is always recreated with the configured policies, even when there are no explicit rules. The other tables are conditional:

| Table | Chains | Purpose |
|-------|--------|---------|
| `inet filter` | input, forward, output, optional tproxy_prerouting (prio -150), tproxy_gate/policy/dispatch + named sets | firewall rules; implicit `ct state established,related accept` when policy is drop; implicit `iifname "lo" accept` in input |
| `ip nat` | prerouting (DNAT), postrouting | port forwards + masquerade; same-subnet hairpin masquerade across all static internal networks, including VLANs |
| `inet mangle` | MSS ingress/egress, wan_return (prio -140), wan_return_output, wan_outbound | MSS caps and optional WAN connection/reply marking and selection |
| `inet blackhole` | input, forward (prio -5) | `blocked` set, drop saddr/daddr matches |

Address conventions: `@setname` references a named set (protocol picked from the set's type), `@local` compiles to a `fib ... type local` match.

Every rule's comment is `[<id>] <comment>` — `/api/firewall/stats` parses the ID out of `nft -j list chain` output to attach per-rule counters.

Do not share these four tables with other tools: their contents are replaced whenever nftables changes are applied. TPROXY marks select dedicated routing tables; reserved IDs 0, 253, 254, and 255 are rejected. Cleanup removes the matching local route/rule, not the entire routing table.

### TPROXY eligibility

`inet filter/tproxy_prerouting` matches IPv4 proxy candidates and enters a shared
`tproxy_gate`. Router-owned destinations go directly to `tproxy_dispatch` and
retain input policy. Non-local candidates jump to `tproxy_policy`, which mirrors
ordered enabled non-TPROXY forward rules and the forward default/established
behavior. Accept returns to the caller and enters dispatch. Drop, Reject, a Drop
default, and potential egress/rate matches accept the prerouting base chain without
entering dispatch, leaving final filtering, denial logging, and denial counters to
the real forward chain. No Drop or Reject statement is emitted in this eligibility
chain; Accept there does not grant forwarding access. This conservative deferral
can bypass proxying even when a later outgoing-interface/rate check would not match.

Dispatch applies the configured mark, transparent listener port, counters, and
logging. Match construction shares inversion, named-set, and connection-state
handling with normal firewall rules. Selectors cannot contain egress/rate matches
or non-TCP/UDP protocols. Admission sees the destination before DNAT. A generated
input exception requires IPv4, a non-local destination, an exact TPROXY mark, and
`socket transparent 1`; ordinary input rules continue governing local services.
The rule-counter reader aggregates protocol variants and forward/proxy-policy
counters before calculating deltas, while retaining legacy mangle-chain collection
until the next Apply. No extra mark bits or policy routes are allocated. This
changes client admission, not sing-box's local-output WAN selection.

### System route management

`routing.routes` stores static IPv4/IPv6 routes with server-assigned immutable IDs,
destination, configured interface, optional gateway, numeric table (default 254),
metric (default 100), gateway-on-link and enablement. `src/config/static_routes.rs`
canonicalizes prefixes (bare IPs become host routes), validates gateway families,
configured interfaces, IDs, duplicate enabled prefix/table/metric keys, reserved
and active TPROXY tables, and known collisions with metric-0 automatic routes.
Interface deletion validates references before saving. No live route is imported
into configuration or edited through the monitoring API.

`src/renderer/routes.rs` appends enabled `[Route]` sections to the existing managed
interface `.network` files, resolving a PPPoE physical interface to `ppp0`. There
is no separate route daemon, unit or prefix-cleanup mechanism. Rendering an empty
or disabled route removes its declaration. Routes participate in the existing
network-file comparisons against both disk and the last successful snapshot,
atomic writes and networkd reconciliation, so Save stays separate from Apply.
Networkd handles the route lifecycle and persistence across link reconnects.
Validation uses the schema, without adding an external networkd syntax check.
Actual gateway reachability and live link behavior still depend on the host.

The routing API holds `ConfigStore::lock_operation()` before reading for every
mutation and holds it through validated persistence. Creation allocates a unique
ID under this lock. A routing-section PUT replaces the entire section; individual
CRUD preserves unrelated routes and configuration. `GET /api/config/routing`
returns saved routes and resolved WAN table IDs for the editor. Normal config
serialization keeps this derived table metadata out of persistence.

`src/service/routing.rs` reads live kernel routes with fixed `ip -j -4/-6 route
show table all` arguments, a timeout and propagated failures. It preserves route
and multipath metadata and adds the address family, with `main` as the omitted-table
default. The UI displays this separately from saved routes; it does not claim a
route's enabled setting proves installation. This feature does not add policy rules,
multipath declarations, arbitrary unmanaged-link takeover or IPv6 WAN selection.

### WAN return routing

IPv4 WAN return routing defaults to enabled for static, DHCP and PPPoE WANs,
without changing ordinary main-table default-route selection. Set
`interfaces.items[].return_routing: false` to opt out. `return_route_table` overrides
a stable FNV-1a interface-name-derived table ID in 10000–59999; collisions are
validation errors requiring an explicit override.
`src/config/routing.rs` validates unique table IDs and WAN addresses, on-subnet
gateways, and TPROXY mark/table conflicts. IPv6 return routing is not supported.
Static and DHCP VLAN WANs are supported. Only one managed PPPoE connection
is supported; its fixed tunnel name `ppp0` is reserved.

The existing managed `.network` file gains a connected WAN route and default
route in the selected table, plus IPv4 source and masked-fwmark policy rules.
DHCP instead gains a `Gateway=_dhcp4` route in its table, maintained by networkd
with the lease while ordinary DHCP routes remain in `main`. PPPoE gains a
link-scoped default route on `ppp0`, installed by networkd when the tunnel exists.
Dynamic WANs use masked-fwmark policies without fixed source-address selectors.
PPP rendering and service enablement select the PPPoE interface independently
of the first WAN.
At priority 100, each source/mark selector may query `main` with
`SuppressPrefixLength=0` only when `To=` matches a configured static internal
IPv4 subnet. These canonical subnet exceptions include bridges and VLANs without
a gateway, exclude WANs and dynamic interfaces, and are deduplicated. All other
destinations go directly to the WAN table at priority 110: more-specific routes
through another WAN or VPN in `main` cannot steal external replies. Networkd owns
these declarations through the existing
file reconciliation/reload path; no table-wide route flush is issued. These
priorities and tables must not conflict with administrator-managed rules.

The nftables `wan_return` prerouting chain runs after TPROXY and before DNAT.
New IPv4 original-direction connections arriving on the WAN interface store
`table << 16` in the connection mark's upper 16 bits. Replies with a configured
connection mark restore those bits to the packet mark before route lookup. An
output route chain restores marks for router-hosted service replies, including
on dynamic WANs. Low mark bits are preserved. Static WANs also have source-address
policy rules. Enabling this feature reserves the upper mark bits;
TPROXY marks must then fit in the lower 16 bits and use different routing tables.

Forward Accept rules may set `route_via` to a configured WAN name with return
routing enabled. `wan_outbound` runs at prerouting priority -90, after TPROXY
(-150), inbound affinity (-140), and DNAT (-100). It excludes WAN ingress,
reply-direction packets, router-local destinations and DNAT traffic, and skips
packets with low mark bits already set (including TPROXY). For existing connections
it restores the WAN mark before evaluating selectors. For new unmarked connections,
the first matching selector stores its upper-bit WAN/mode mark in both the connection
and packet marks and returns. `preserve_internal_routes` defaults to true and adds
the configured internal-subnet exclusions to that selector. False omits them.
Preserved and strict connections use distinct marks even on the same WAN; restoring
the connection mark retains both the chosen WAN and preservation mode. Named sets are also declared in `inet mangle`.
Prerouting shares the forward-rule matcher, without counters, logging or verdicts;
user ID comments and counters remain in `inet filter` for existing stats APIs.

`src/config/routing.rs` allocates disjoint strict-mode upper-16-bit marks separately
from ordinary `table << 16` marks. Allocation sorts WAN names and probes around
collisions with all WAN and strict marks, so rule/interface reordering does not
change it. It does not consume TPROXY's low bits or allocate extra route tables.
Changes to WAN topology/table IDs can change this derived namespace; verify new
connections after such changes.

`src/service/wan_policy.rs` installs global strict-mark policy pairs: priority 90
looks up the selected WAN table, and priority 91 returns unreachable if that table
has no matching route. These precede the regular priority-100 internal exceptions.
An explicit more-specific LAN route in the selected table is honored. Policies are
not attached to WAN links and use protocol `kernel`, which networkd excludes from
foreign-policy cleanup, so WAN/link loss cannot expose a fallback to `main`.
The renderer excludes router-owned destinations regardless of preservation mode.

After staged syntax checks and comparison, Apply prepares all terminal guards
before lookup rules and before nftables can emit strict marks. These policies are
maintained for all configured WANs while any outbound selector is enabled, retaining
old pinned flows when a rule changes mode or target. After service reconciliation,
only exact previously-owned obsolete rules are removed. Matching includes priority,
mark, mask, protocol, action/table and absence of additional selectors. Conflicting
administrator rules fail Apply; no table or policy-rule collection is flushed.
Native ip-rule reads use detailed numeric JSON so protocol ownership is explicit.
Normal startup reconciles these ephemeral policies too. As with other apply state,
there is no durable ownership journal beyond the saved config/in-memory snapshot.

Validation restricts `route_via` to forward Accept rules, IPv4 matches and configured
WANs; egress-interface matches and rate limits are rejected, and nonempty state
filters must include `new`. Disabling preservation is valid only on a forward
Accept rule with a WAN selector. `ppp0` is resolved from the configured PPPoE interface.
Normal filtering remains independent; selecting a WAN cannot bypass a drop verdict.

While outbound selection is enabled, forward-chain guards for every WAN precede
the implicit established/related Accept rule. Original-direction, non-DNAT packets
from non-WAN ingress to external destinations with a WAN connection mark are dropped
if their actual egress differs from that WAN. This prevents fallback through another
interface if networkd removes a WAN's table/policy rules on link loss, including for
already established flows and old flows after a selector changes target. These egress guards apply to preserved-mode marks. Strict marks rely on the
global lookup/unreachable pair so explicit LAN exits in the WAN table remain valid.
No table-wide flush is issued. Disabling/removing all
WAN-selection rules removes outbound restoration and guards. WAN-ingress replies
do not restore preserved outbound marks; strict reply marks are not restored by
the inbound-WAN affinity renderer, so they use normal client/LAN routing. NAT remains
explicit and independent. Router-originated outbound selection, IPv6 and automatic
failover are not implemented.

Hairpin SNAT does not use the legacy first-LAN accessor: it considers every
static interface without a gateway, including VLANs. Rules require a source in
the target server's subnet, its egress interface, and `ct status dnat`, avoiding
the old broad masquerading of unrelated traffic to the server. DNAT ingress
remains explicitly controlled by each port forward.

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

Initialization leaves network managers, service configs, addresses, routes, and firewall rules untouched. This also holds for repeated starts with `--init`. Starting without `--init` or `--boot` uses the partial normal-startup pipeline above; `--boot` instead restores only nftables. The generated configuration is a router draft, not a complete import of the existing network setup.

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
│   ├── metrics/            # interface/firewall collection and rolling history
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

The overview and monitoring pages graph a selected interface rather than summing overlapping bridge/physical counters. `rx_bps` and `tx_bps` from the API are bytes/s. Configuration editors save without applying; startup hooks activate on normal startup. Service controls and backup restores are explicitly confirmed live operations.

`GET /api/config/apply/status` takes the configuration operation lock and compares saved typed configuration, including `singbox.config`, with the last-successful configuration snapshot. Without a successful service snapshot, including first Apply under any startup mode or after a failed/cancelled attempt, it returns `pending: true`. The endpoint only reads in-memory state; it does not read deployed files, render, run syntax checks, control services, or inspect live networking. Same-content saves and saved reversions return `pending: false`. External generated-file or kernel drift and service inactivity are not tracked by this endpoint. The authenticated UI polls every five seconds and invalidates status after successful or failed writes, so other clients' saved changes are detected too. Apply is unavailable for unchanged, loading, refreshing, or failed status checks; explicit API Apply and service controls remain available. Browser-local pending flags are no longer used.

Frontend regression tests live in `web/tests/` and use Bun's built-in runner. Build assets with Bun before compiling Rust; `web/dist/` is generated and ignored. See `web/README.md` for commands and `web/THIRD_PARTY_NOTICES.md` for reference attribution.

`.github/workflows/release.yml` builds and checks the frontend first, then passes
that run's generated assets to native x86-64 and ARM64 musl release-build jobs.
Pull requests, main-branch pushes, and manual runs produce downloadable artifacts.
Version-tag pushes also publish GitHub Releases after all checks/builds succeed,
with archive checksums and generated release notes. CI does not bundle runtime
configuration or deploy binaries, control services, or apply router state.

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

### Shaper service

`src/service/shaper/` implements CAKE traffic control over a bounded, synchronous
NETLINK_ROUTE transport, run on Tokio blocking workers. Netlink message lengths,
attribute padding, kernel origin, sequence numbers, multipart completion/errors,
and interrupted dumps are checked. No dependency or shell-command wrapper is
needed for production TC operations. `src/config/shaper.rs` validates profiles;
API section writes use the configuration operation lock and never apply.

Apply suspends reconnect repairs, then reconciles shaping after service/routing
operations. Required netlink failures propagate and are exposed by shaper status;
only successful Apply activates the background reconciler. Every five seconds it
uses the last successful configuration under the same operation lock, repairing
missing/recreated links without activating saved drafts. `--init` alone never
activates it. Like other Apply operations, shaping is not transactional: partial
changes may remain on failure, and a new explicit Apply is needed to resume
background repairs after an Apply failure.

Egress CAKE lives at an owned root handle, with best-effort classification,
NAT-aware source/destination host isolation, and GSO splitting. Ingress uses an
owned ingress qdisc with a software matchall/mirred redirect into an IFB running
CAKE in ingress mode; its MTU follows the selected device. LAN-facing profiles reverse source/destination isolation.
PPPoE resolves the configured parent to `ppp0`; traffic marks used by WAN policy
routing and TPROXY are untouched.

`/run/routerd-shaper/ownership.json` is a private atomic journal, written before
mutations and retained across daemon restarts. It records device indices, profile
IDs, directions, and IFB identities; IFB aliases and redirect action cookies add
kernel identity checks. Preflight checks all intended changes and cleanup
records before mutation. Only implicit default qdiscs or previously owned queues
may be replaced. Custom roots, custom multi-queue children, pre-existing ingress
hooks/filters, and unjournalled IFB name collisions are conflicts. Cleanup rechecks ownership,
never flushes device filters globally, and will refuse ambiguous administrator
changes. If ownership metadata is lost or a crash leaves an untagged IFB, manual
review may be required; unrelated traffic control is never adopted merely by name.

The ignored native shaper test always enters an isolated network namespace. It
exercises CAKE/IFB creation, cookies and aliases, foreign-filter protection,
cleanup, reconnects, two source IPs behind actual SNAT with four versus one flow,
download reverse-NAT host fairness, spare-capacity reuse, and latency under load.

PPPoE start/restart requests use `systemctl --no-block` for `ppp@isp`. Apply and
manual service controls wait only for job submission, not for dialing or reconnects.
Submission errors still fail the request; later connection failures are reported by
service status and the PPP journal. Successful Apply does not imply PPP connectivity.

### WAN-group health and selection

`src/config/wan_groups.rs` defines the optional `wan_groups` list and validates
members against the existing IPv4 WAN return-routing model. Groups use stable
numeric IDs; firewall `route_via` values prefixed with `group:` select a group.
The existing per-WAN marks, internal-route preservation, strict routing guards,
TPROXY exclusions, inbound symmetry, and NAT behavior are retained.

`src/renderer/nftables.rs` creates two owned maps per group in `inet mangle`:
`wg_<id>_normal` and `wg_<id>_strict`. Each has 256 source-IP slots and initially maps
to zero. The key is `ip saddr & 0.0.0.255`, equivalent to numeric IPv4 modulo
256, stored in an `ipv4_addr : mark` map to preserve network byte order.
Ports and destinations do not
affect selection, so one client uses one WAN while membership is unchanged. A group chain commits its selected WAN's constant upper-bit mark,
preserving low conntrack bits. Zero or unknown selections drop immediately.
Connection restoration precedes new selection, so membership/health/tier changes
do not migrate existing flows. Group-policy fingerprints in map comments ensure
weight, tier, and probe-policy edits invalidate full-Apply content snapshots.

`src/service/wan_groups.rs` runs asynchronous, bounded ICMP probes. Before each
probe it verifies a marked FIB lookup resolves through the member's routing table,
interface, and IPv4 source address; ping uses that strict mark and binds to the
egress device. Missing routes/addresses (including a dialing PPP tunnel) count as
failed rounds. A member becomes healthy only after consecutive successes and the
recovery delay; consecutive failed rounds withdraw it. Targets are tried until any
answers. Largest-remainder apportionment rounds weights to 256 slots, then smooth weighted
interleaving spreads the slots across the cycle using only healthy members in the
lowest tier. Equal pairs alternate even/odd client addresses.
Shares are quantized to 256 slots. Consecutive source addresses balance evenly
for equal pairs; arbitrary address populations may be skewed. No per-client
assignment table is maintained.

The runtime captures installed configuration, never saved drafts. Only successful
full Apply or `--boot` nftables installation activates it; normal startup and
`--init` do not. Boot-mode probing relies on existing WAN policy rules and routes.
Full Apply suspends it before runtime changes; generation checks discard probes
that finish after a suspend or reconfiguration. Slow probes hold neither the
operation lock nor the runtime mutex. Publication takes the operation lock and
updates only the group's maps with one atomic nft JSON batch (flush map plus add
elements), leaving other rules/counters untouched. Update errors retain the last
published map snapshot, surface in status, and are retried. A full Apply that fails after suspension
leaves monitoring suspended until a successful retry. This does not make Apply
transactional. Runtime status reports installed bucket shares separately from
observed health; it does not inspect external kernel drift.

PPP return defaults are additionally rendered as a fixed managed `ip-up.d` hook
(`0700`). Its content participates in PPP file comparison against disk and the
previous successful configuration. Normal startup/full Apply atomically install
it before requesting a PPP start/restart; boot/init skip installation. The peer's
`ipparam routerd-isp` scopes execution to the managed `ppp0` connection. The hook
replaces only the configured table's interface default (`proto static`, scope
link), after IPCP address setup and on reconnect, retaining other prefixes and the
main table. It becomes a no-op when PPP return routing is disabled. This relies
on the system PPP ip-up dispatcher; it does not replace administrator dispatchers
or add a new daemon. PPP dialing remains asynchronous. Group health still checks
for a usable dedicated-table route and a successful WAN-bound ICMP probe.

Moving a saved shaper profile to another interface, or reconnecting PPP with a new
link index, can retain the old profile IFB until reconciliation. Preflight accepts
that name only when an ingress ownership journal record with the same profile ID
and IFB name exists, after validating the recorded IFB identity, qdiscs and source
filters. It then removes the obsolete owned state before creating the replacement.
A matching name or alias without the journal remains insufficient for adoption.

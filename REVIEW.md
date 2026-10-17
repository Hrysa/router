# Code Review — 2026-10-15

## Scope

Source review of authentication and API routes, configuration persistence/restore, startup, service apply/lifecycle handling, renderers, metrics/monitoring, frontend forms/API integration, and project documentation. Existing working-tree changes are preserved. Runtime files in `config/` are not edited.

This is a source-level review with automated regression checks, not a penetration test or certification of a deployed router. No live firewall rules, network interfaces, service configurations, or system services are changed during validation.

## Validation results

- `cargo test --locked`: **81 passed**, none failed. A writable temporary Cargo target directory was used because the checkout's existing target directory is not writable in this environment.
- `cargo clippy --locked --all-targets`: succeeds; existing style suggestions remain (23 production warnings, 26 including tests).
- `bun run check` in `web/`: **0 errors, 0 warnings**. Bun runs the package scripts because npm is unavailable in this environment.
- `bun run build` in `web/`: succeeds and refreshes local embedded assets.
- `git diff --check`: clean.
- Native `nft`/`kea-dhcp4` checks, live service apply, and browser end-to-end tests are not run. The native binaries are unavailable here; their required/optional pre-apply behavior remains enforced in code.

## Critical and high-priority fixes

| Finding | Fix |
|---------|-----|
| An unset password allowed unrestricted JWT issuance, including tokens usable after setup. | Deny login and protected API access until a password is configured. |
| Concurrent public setup requests could replace the first administrator's password. | Serialize setup with all configuration mutations and recheck state under that lock. |
| Middleware cached a signing secret while login used the saved secret, breaking rotation and restore semantics. | Validate against current authentication state on every protected request. |
| Predictable, truncating `/tmp` writes and installer extraction paths were unsafe for a privileged daemon. | Use exclusive random staging files and private extraction directories with scoped cleanup; atomically replace destinations. |
| Configuration/backup/PPP writes could expose credentials through default permissions. | Create replacement files privately; use `0600` for secrets and backups. |
| Empty firewall rule lists overrode configured drop policies with accept policies. | Always render configured chain policies, including empty rule lists. |
| Global `flush ruleset` deleted rules belonging to other applications. | Reset only routerd's four owned table names; preserve unrelated tables. |
| Configuration mutations could lose unrelated concurrent changes, race file writes, or overlap applies. | Serialize API mutations, applies, restores, and manual service controls; hold the config write lock through persistence. |
| Same-second backups overwrote each other, and restore backed up twice. | Use timestamp/UUID backup names and exactly one backup per restore. |
| Backup IDs were joined into paths without validation. | Reject empty IDs, separators, and other non-identifier characters before filesystem access. |
| Service, sysctl, and TPROXY failures could be logged while apply still reported success. | Propagate required-operation failures, retain the last-successful snapshot, and retry changes relative to that snapshot. |
| Apply started disabled WireGuard or unconfigured PPP services from stale files. | Derive lifecycle decisions from configuration; stop disabled optional services and start enabled inactive ones. |
| TPROXY cleanup flushed entire routing tables and could target reserved system tables. | Reject reserved marks; remove only matching routes/rules instead of flushing tables. |
| Line-oriented network/PPP/WireGuard output accepted directive injection and invalid filenames. | Validate interface identifiers, rendered single-line fields, addresses and keys; escape quoted PPP credentials. |
| DHCP duration multiplication could overflow or panic. | Use shared checked duration parsing and reject invalid/oversized lifetimes before rendering. |
| A lone TLS certificate/key flag silently selected plaintext HTTP. | Require the certificate/key flags together during CLI parsing. |

## Other corrections

- Preserve firewall/NAT rule IDs on update and reject duplicate firewall IDs.
- Validate static DHCP leases before saving them.
- Accept the systemd service names returned by the service-list API in service-control routes.
- Render DHCP/static VLAN network files once, and insert parent VLAN directives into the correct networkd section.
- Base WireGuard enablement on typed configuration rather than searching generated text for words such as “disabled”.
- Preserve counters on logged firewall rules when counters are requested.
- Select sing-box release assets for the detected architecture and atomically replace the installed binary.
- Move bcrypt work off the async executor and reject password inputs longer than 72 UTF-8 bytes.
- Fix firewall form types/IDs, missing static-lease reload calls, and stale DHCP state that could restore deleted leases during a later pool save.
- Remove nested selector buttons and the empty form label identified by frontend checks.
- Correct obsolete DHCP/DNS/API examples, document first-time setup and transport safety, describe actual apply/restore guarantees, and replace frontend template documentation.

## Remaining limitations and operational cautions

- Apply is not transactional across kernel state, generated files, and services. Failure can leave partial changes; keep console access. The last-successful snapshot is in memory, not a durable applied-state journal.
- First-time setup is intentionally public until configured. Bootstrap over loopback, an SSH tunnel, or an isolated trusted management network. The default listener is all interfaces, and HTTP is used unless both TLS flags are supplied.
- Login has no built-in per-client rate limit or lockout. Restrict management access and enforce rate limits at a trusted reverse proxy when needed.
- Hooks intentionally provide administrator-level shell execution. Authenticated configuration access includes credentials; this is not a multi-user authorization boundary.
- Routerd owns the contents of `inet filter`, `ip nat`, `inet mangle`, and `inet blackhole`. Other tools must use different table names. TPROXY marks require dedicated IPv4 routing tables; IPv6 policy routing is not implemented here.
- Old backups and files created before this change are not retroactively chmodded or removed. Audit their permissions separately.
- sing-box installation trusts release assets delivered from GitHub over HTTPS; independent signature/checksum verification is not implemented. The installer can select prereleases.
- `/api/monitor/traffic` and `/api/monitor/connections` remain placeholders; `src/monitor/` contains stubs. Use the implemented interface/firewall metrics endpoints. `monitoring.vnstat` is not automatically reconciled during apply.
- Although repository guidance describes `web/dist/` as committed, this checkout ignores it in both root and frontend Git rules and has no tracked dist assets. Build it locally before compiling Rust; ignore rules are left unchanged.
- Live privileged apply, distro-specific service units, and native nftables/Kea integration still need verification on a disposable router or isolated network namespace. Unit tests do not establish those deployment guarantees.

### 2026-10-17 — WAN groups

Added IPv4 forwarded-traffic WAN groups with tiered fallback, weighted source-IP
hashing, asynchronous ICMP health checks, saved-only API editing and a WAN Groups
page. Health-driven nft map updates preserve established WAN marks and expose
last-installed shares. Limits: 32 groups, 16 members per group, 64 total member
entries, 256 buckets per group. No IPv6/router-originated group selection, seamless
public-IP session migration, connection deletion, or external kernel-drift repair.
ICMP filtering can classify an otherwise usable WAN as down; choose probe targets
accordingly. An Apply failure after runtime suspension leaves monitoring suspended until a successful retry.
Boot activation relies on pre-existing WAN routing; it does not install routes.
Validation: Rust and Bun unit suites, TypeScript checks, production frontend build,
Clippy and formatting passed. A real-kernel regression in fresh network namespaces
verified weighted hashing, connection stickiness, both routing modes, atomic map
updates, all-down blocking and no main-route leakage. Mocked browser coverage was
added; execution was unavailable because Chromium downloads stalled/timed out.
No live configuration Apply or service installation was performed.

### 2026-10-17 — PPP WAN-group route lifecycle

Read-only diagnostics found connected `ppp0` with an IPv4 address and an empty
configured WAN table. Added a tagged, fixed-path PPP IP-up hook to restore the
dedicated-table default after IPCP and each reconnect. The standard distribution
PPP ip-up dispatcher must run `ip-up.d`; custom local dispatcher overrides must
invoke the hook. Hook scope and disabled behavior are unit-tested; a real-kernel
namespace test verifies route recreation and preservation of the main default and
unrelated routes. No live PPP restart, hook installation or Apply was performed.

### 2026-10-17 — Client affinity for WAN groups

Changed selection from symmetric per-flow hashing to `jhash ip saddr`, seeded
with the stable group ID. Ports and destinations no longer affect the WAN chosen
for a client's new connections while the active bucket map is unchanged. Weights
now describe approximate client-IP shares. Existing connection marks survive;
health, tier, weight or membership changes can move subsequent new connections.
The isolated kernel regression passed for both routing modes, checking affinity
across 100 varied connections, distribution across 400 source addresses, existing
flow pinning, all-down blocking and no main-table leakage. Rust/Bun unit suites,
frontend checks/build, Clippy and formatting passed; no live Apply was performed.

### 2026-10-17 — Stateless modulo selection

Replaced source-IP hashing with low-octet modulo-256 selection in IPv4-typed
slot maps, without per-client assignments. Largest-remainder apportionment and
smooth interleaving make weighted slot allocation deterministic and closest to
configured shares. Equal pairs alternate even/odd addresses; three equal members
receive 86/85/85 slots. This balances consecutive addresses, not arbitrary active
IP sets or traffic volume. Existing connections keep their marks across policy
changes. Native packet checks cover exact 200/200 and 300/100 splits across 400
consecutive clients, subnet boundaries, per-client affinity and failover.

### 2026-10-17 — Shaper profile migration and PPP reconnects

Fixed preflight incorrectly rejecting a journalled IFB when its profile moves to
a different device or PPP returns with a new link index. The old record must
still validate exact IFB identity and foreign-qdisc/filter protections before
cleanup/recreation. A namespace regression verified physical-WAN to PPP migration,
PPP link recreation, rejection without a journal, rejection with a foreign old
filter, and final cleanup. Live ownership state and shaping were left unchanged.

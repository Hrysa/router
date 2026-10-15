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

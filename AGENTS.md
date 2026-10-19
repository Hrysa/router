# AGENTS.md

## Safety and scope

- **Do not modify anything in the repository-root `config/` directory unless explicitly asked.** This includes `config.yml` and `backups/`. It is gitignored runtime state, not a schema or test fixture. This restriction does not apply to Rust source under `src/config/`.
- Preserve existing working-tree changes. Keep patches focused; do not sweep unrelated Clippy/style warnings or change dependency lockfiles without a task-related reason.
- Do not apply configuration, control host services, install binaries, or run network-changing commands merely to validate a patch. Use temporary directories and isolated test fixtures, not runtime configuration or `/etc/`.
- Normal startup reconciles saved configuration except nftables and sing-box, changes NIC offloads, and runs startup hooks. It must not run nftables checks/install, read/write deployed sing-box JSONC, or query/control sing-box. `--boot` instead validates/renders/checks/installs only nftables, then serves the API, skipping other service/file/network changes, routes, shaping, offloads, and hooks; it conflicts with `--init` and `--install-singbox`. `--init` skips all those startup changes even with an existing config, but can create a missing draft config and persist authentication state. It is not a read-only mode: explicit API Apply still changes the host.
- Apply is **not transactional across files, services, and kernel state**. Failure can leave partial changes. Backup restore is explicit, not automatic recovery after a failed apply.

## Source of truth

- `src/config/schema.rs`: configuration types, defaults, and interface-role inference. Interfaces use `interfaces.items`; DHCP uses `dhcp.pools` and `dhcp.static_leases`.
- `src/config/validator.rs`: schema validation. `src/config/store.rs`: persistence, backups, mutation serialization, and the last-successful in-memory applied snapshot.
- `src/service/apply.rs`: rendering, syntax checks, change detection, service reconciliation, and IPv4 TPROXY routing. `src/service/manager.rs`: command execution and systemd unit names.
- `src/api/server.rs`: registered routes and embedded SPA. Check this file before documenting endpoints; section updates replace sections, not individual fields.
- `src/metrics/mod.rs`: interface/firewall collection and rolling history. System/interface details and Kea lease reads live in API handlers. `/api/monitor/traffic` and `/api/monitor/connections` are placeholders; the unused `src/monitor/` stubs have been removed.

## Rendering and apply invariants

- Pipeline: schema validation → render all configs → staged syntax checks → content comparison → atomic writes → service reconciliation → TPROXY routing. Compare rendered files against both disk and the last-successful in-memory snapshot; do not substitute a diff of the already-saved YAML file. The snapshot is initialized from saved config at startup, not a durable applied-state journal.
- **Required syntax check:** `nft -j -c -f <staged JSON>`. Apply must fail if this check cannot run or fails. **Optional only when absent:** `kea-dhcp4 -t <staged config>` and `sing-box check -c <staged JSONC>` for configured sing-box on full Apply; failures must propagate when the binary is installed. PPP, WireGuard, networkd, and sysctl rely on `src/config/validator.rs`, not additional external pre-apply syntax checks.
- **nftables is JSON, not a text config.** `src/renderer/nftables.rs` uses the `nftables` crate; apply uses `nft -j -f`, never `systemctl restart nftables`. No `/etc/nftables.conf` is generated. Normal startup leaves rules untouched; `--boot` always checks/installs them. Skip unchanged rendered rules after a successful full Apply in this process; first/forced full Apply always installs them. Service-content snapshots start unknown, are invalidated before attempting runtime changes, and are published only after the entire full Apply succeeds, so failed/cancelled applies cannot cause an unsafe skip on retry. Partial normal/boot startup does not publish these snapshots. They do not inspect live kernel drift.
- Own only `inet filter` (firewall), `ip nat` (DNAT/masquerade), `inet mangle` (WAN marking/MSS), and `inet blackhole` (blocked set). Reset these tables only; never emit a global `flush ruleset`. Honor configured policies even when rule lists are empty. TPROXY eligibility/interception live in `inet filter` prerouting; Drop/Reject/default Drop bypass interception for actual filtering in forward.
- User-defined firewall rule comments carry `[<id>] <comment>` or just `[<id>]`. `/api/firewall/stats` and the metrics collector parse these IDs. Preserve the format and unique IDs across input/forward chains.
- **DHCP is Kea DHCPv4**, not ISC DHCP. `src/renderer/kea.rs` generates `/etc/kea/kea-dhcp4.conf` (JSON); the unit is `kea-dhcp4-server`. Service-control aliases include `dhcpd`, `kea-dhcp4`, and `dhcp`, as well as the canonical unit name. There is no managed DNS resolver.
- **networkd files use `50-routerd-`**, with interface-based filenames such as `50-routerd-eth0.network`. Stale managed files are removed when network configs are reconciled. This is the only prefix-based generated-file cleanup; Kea, PPP, WireGuard, and sysctl use fixed paths. Reload networkd with `networkctl reload`, falling back to restart on failure.
- Start enabled DHCP/PPP/WireGuard services when inactive; reload/restart changed active services; stop disabled optional services rather than starting stale configs. Derive enablement from typed configuration, never sentinel strings in generated content. Do not swallow required-operation failures or report false apply success.
- **sing-box JSONC lives in `config.yml` under optional `singbox.config`.** GET `/api/singbox/config` reads saved text; PUT accepts raw JSONC and saves only routerd config/backups under the operation lock. Preserve comments/whitespace. Check staged JSONC on Save and full Apply with `sing-box check` when installed; failures propagate. Explicit full Apply compares saved text with the successful snapshot and deployed file, atomically writes `/etc/sing-box/config.jsonc` at `0600`, then restarts on change/first/forced Apply or starts if inactive. Deployed-file drift is overwritten, never imported; non-NotFound read errors propagate. Absent `singbox` leaves existing files/services unmanaged, even on restore; empty configured text is rejected. Existing files require manual import through the editor. All daemon startup modes skip deployed-file reads/writes, external sing-box validation, and service queries/controls. Configured-service failures are fatal.
- **`--install-singbox` sets up config/unit files, not the binary.** Read `<config-dir>/config.yml` directly before store/auth/API initialization; require saved, nonempty `singbox.config`. Always atomically overwrite `/etc/sing-box/config.jsonc` (`0600`) and `/etc/systemd/system/sing-box.service` (`0644`), then run `systemctl daemon-reload` only after both writes succeed and exit. Enforce the 30-second timeout, propagate execution/nonzero/timeout errors, and report that files are already installed on reload failure. Never enable/start/restart services, download/execute/replace the sing-box binary, or change networking/run hooks. The unit expects separately installed `/usr/local/bin/sing-box`; enable/start/restart is manual. Leave source config/backups untouched. Detect input errors before writes, propagate write failures, and acknowledge that the two-file operation is not transactional. It conflicts with `--init` and `--boot`. Tests must inject temporary source/destination paths and fake systemctl, never install into `/etc/` or run a live daemon-reload.
- TPROXY marks select dedicated IPv4 routing tables. Reject reserved IDs `0`, `253`, `254`, and `255`; remove only matching policy rules/local routes, never flush entire routing tables. IPv6 policy routing is not implemented.

## Persistence and authentication

- Acquire `ConfigStore::lock_operation()` **before reading** config for API read-modify-write operations, setup, apply/restore, and manual service controls. Hold it through completion; avoid nested reacquisition. Individual saves also hold the store write lock through disk replacement and memory publication.
- Reuse `src/service/files.rs` for exclusive random staging and atomic replacement. Never use predictable shared `/tmp` filenames or truncating writes for privileged staging. Keep config, backups, PPP peers/secrets, WireGuard private keys, and sing-box staging/deployment at `0600`; Kea staging uses `0644` for validation after privilege dropping.
- Preserve unique timestamp/UUID backups and backup-ID validation before filesystem access. Restore creates one backup of the current configuration before replacing it.
- An unset password permits first-time setup only, not login/token issuance or protected API access. Setup must recheck password state under the operation lock. Middleware reads current authentication state so JWT-secret replacement/restore takes effect immediately.
- Keep bcrypt off the async executor and enforce its 72-byte input limit. Hooks intentionally execute administrator shell commands; authenticated config includes secrets. Bootstrap only over trusted management access. The default listener is `0.0.0.0:8443`, using HTTP unless both TLS flags are supplied.

## Frontend workflow

- The React SPA is embedded with rust-embed from `web/dist/`. **This checkout ignores `web/dist/`; it is not tracked.** A clean checkout needs the frontend build before compiling Rust. Rebuild frontend sources before rebuilding the binary to avoid stale UI.
- `web/src/App.tsx` owns hash navigation, authentication, theme selection, and the responsive shell. `web/src/lib/api.ts` is the same-origin bearer client; keep session-change response rejection and cache clearing on logout/401. `getConfig()` normalizes fields Rust omits when empty. React Query owns remote data; editor drafts must not reset on background refetch.
- The UI follows Yacd-meta's React/sidebar/card/theme foundation, but uses routerd APIs, not Clash endpoints. `git-repos/` is an ignored reference checkout, not a build dependency. See `web/THIRD_PARTY_NOTICES.md`.
- Preserve save-versus-apply semantics. Startup hooks activate on normal daemon startup, not API Apply. Restoring a backup **applies immediately** and requires explicit confirmation, as do live service controls. Apply availability and the pending indicator use `/api/config/apply/status`, comparing saved config (including `singbox.config`) with the last successful in-process Apply without reading deployed files; this is not live service/kernel health or generated-file drift detection. First/failed applies must remain available; unchanged saves and saved reversions must not enable Apply.
- Metrics `rx_bps`/`tx_bps` are **bytes per second**, despite their names. Do not label them bits/s or aggregate bridge and physical interfaces into a misleading total. CPU snapshots are cumulative counters, not percentages; Overview derives utilization from successive deltas, waiting for valid samples and resetting on missing counters, counter resets, and failed requests.
- Section writes replace the entire section. Fetch fresh configuration before changing pools, policies, or masquerade; preserve unrelated fields and especially current static leases. Preserve rule IDs, represent connection states as arrays, encode path components, and send sing-box files as raw JSONC.
- Run both frontend checks and the production build after changing frontend source. Do not introduce untrusted HTML rendering: bearer tokens are stored in browser local storage.
- Browser regressions use Playwright with a real Node.js 22+ runtime and an installed Chromium build. Keep all `/api` requests intercepted in browser fixtures; never pass them through to a live router or start the daemon for smoke tests.
- `web/vite.config.ts` proxies `/api` to a hard-coded router address. Change it only when the task requires a different target. Development binds to loopback by default; exposing the proxy exposes management access.

## Validation commands

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
(cd web && bun install --frozen-lockfile) # when dependencies need installation
(cd web && bun run test)       # isolated frontend regression tests
(cd web && bun run check)      # strict TypeScript checks
(cd web && bun run build)      # refresh embedded assets before Cargo builds
git diff --check
```

Rust tests are inline `#[test]`/`#[tokio::test]` modules under `src/`; there is no root `tests/` directory. Frontend tests are in `web/tests/`, with mocked browser coverage in `web/e2e/`. Use Bun and the committed `web/bun.lock`; do not mix package-manager lockfiles. Prefer focused regression tests, then broader suites. Use a writable `CARGO_TARGET_DIR` if the existing target directory is not writable.

For manual development only, use an explicit scratch config directory and loopback listener, for example `RUST_LOG=debug cargo run -- --init -c /tmp/routerd-dev --listen 127.0.0.1:8443`. Do not invoke it automatically as a test. Report unavailable native checks and untested live apply behavior separately from unit-test results.

## Documentation

Keep `README.md` (setup/API), `ARCHITECTURE.md` (runtime behavior), and `web/README.md` (frontend workflow) aligned with code changes. `REVIEW.md` records the dated review and known limitations; it is not a substitute for checking current source. Avoid duplicating the full schema or route list in this file.

# routerd Web UI

A new React + TypeScript management console built around Yacd-meta's responsive sidebar, card-based layout, and light/dark theme approach. It uses routerd's existing APIs, not Clash endpoints. React Query manages server data; Radix supplies accessible dialogs. Fonts are bundled locally. See `THIRD_PARTY_NOTICES.md` for design provenance.

## Development

Use Bun 1.4.1 or newer. From `web/`:

```bash
bun install --frozen-lockfile
bun run dev
```

Set the `/api` target in `vite.config.ts` to your routerd backend before development. It currently contains a router-specific IP address, not automatic discovery. The frontend always uses same-origin `/api` requests. Use HTTP unless the backend has both TLS flags configured. The dev server binds to `127.0.0.1` by default; exposing the development proxy also exposes management access.

For manual backend development only, use an explicit scratch directory from the repository root:

```bash
cargo run -- --init -c /tmp/routerd-dev --listen 127.0.0.1:8443
```

`--init` skips startup network changes, but can create a draft and persist authentication. **Clicking Apply still changes host networking.** Never launch the daemon as a frontend smoke test. Use mocked browser APIs instead, and bootstrap passwords only over trusted management access or HTTPS.

`routerd --install-singbox -c <config-dir>` is a separate config/unit setup command: it requires saved `singbox.config`, overwrites both the deployed JSONC and systemd unit even when they exist, runs `systemctl daemon-reload` after both writes succeed, then exits. Reload failures/timeouts fail setup but leave the installed files in place. It does not download/install a binary, enable/start/restart services, change networking, or run the API. The unit expects `/usr/local/bin/sing-box` installed separately; enable/start/restart remains manual. It does not modify routerd configuration or mark a full Apply successful. Missing/empty saved JSONC is an error, not a request to invent a default config.

Normal daemon startup reconciles other saved network setup and runs startup hooks, but leaves nftables and sing-box untouched. `--boot` instead checks/installs only saved nftables rules, then serves the UI/API; it skips other services, routes, shaping, offloads, and hooks. Systemd manages sing-box startup. Neither mode marks the full configuration applied, so the first explicit Apply remains available and retains full service reconciliation, including sing-box. Boot mode is not a replacement for provisioning TPROXY/WAN policy routes or other network dependencies.

## Validation and production

```bash
bun run test
bun run check
bun run build
```

The Bun tests cover port parsing, UTF-8 password limits, authentication/error handling, raw JSONC, stable rule IDs, interface editing, and preservation of current DHCP reservations during pool saves. `check` runs strict TypeScript checks, including unused-local and unused-parameter checks for application code and mocked browser tests. There is no separate ESLint or frontend formatter configuration in this checkout. `build` type-checks and replaces generated `dist/` assets.

**Build the frontend before compiling Rust.** Rust embeds `web/dist/` into the binary, so a clean checkout requires these assets and rebuilding Rust without rebuilding the frontend can serve stale UI. `dist/` is ignored, not committed. `bun run preview` previews the built assets without an API proxy; use the dev server or a same-origin reverse proxy for real API access.

### Mocked browser regression tests

```bash
bun x playwright install chromium --only-shell
bun run test:e2e
```

Browser tests require a real Node.js 22+ runtime for Playwright; do not force its runner through Bun's Node compatibility layer. They start a loopback-only preview server for the production build. All `/api` requests are intercepted, with no passthrough to a real router. They cover desktop/mobile navigation, themes, saves, confirmation boundaries, raw JSONC, and session expiry. Run `bun run build` first. On systems without writable browser caches, set `PLAYWRIGHT_BROWSERS_PATH` to a writable temporary directory for both installation and tests. Playwright's Chromium also requires the usual host browser libraries.

## Pages and safety

The top bar identifies the current page. Content panels omit decorative page titles and taglines; page actions remain in a compact toolbar, with headings retained for screen readers.

- **Overview:** selected-interface traffic, CPU utilization, memory, uptime (whole days and hours, without minutes), configured links, and service health. Traffic samples, live interface counters, and CPU/memory statistics refresh every two seconds. Traffic is bytes/s; physical and bridge traffic are not summed. CPU utilization uses successive cumulative-counter deltas across all cores, not the lifetime counter ratio. The CPU card waits for two valid samples and clears unavailable, unchanged, reset, or failed samples rather than displaying an invented percentage.
- **Interfaces:** static/DHCP/PPPoE, bridges and VLANs, plus live read-only link counters. Device names are immutable on update. All interface selectors and interface summaries (firewall/NAT rules, routes, shaping, traffic charts/counters, and WAN warnings) display configured labels, falling back to device names for unlabeled or unknown interfaces (including the managed PPPoE label for `ppp0`). Saved values remain device names. Interface diagnostics and pickers retain device names as secondary details; focusing a picker's text field exposes raw device names for manual editing. Bridge members, firewall/NAT ingress, and masquerade support quick multi-selection. Custom device names remain editable, including interfaces not currently detected.
- **WAN return routing:** enabled by default for static IPv4, DHCP and PPPoE WANs, with a stable automatic table ID derived from the interface name. The editor offers an enable toggle and optional table override (1–65535 except 253–255, distinct from TPROXY and other host tables). Automatic collisions require a manual override. Policy priorities 100/110 and upper 16 mark bits are reserved. Only one PPPoE connection (`ppp0`) is managed; IPv6 return routing is not implemented. Save and Apply remain separate operations.
- **Routes:** persistent IPv4/IPv6 destination routes with configured interface, optional gateway, Main/WAN/custom table, metric, gateway-on-link and enablement. Individual CRUD preserves other routes; drafts stay local across refetches. Saved changes require Apply. A separate read-only view shows live kernel routes across all tables, including routes from other tools. Main controls ordinary LAN/router system routing; explicit WAN selection uses its own table. Custom tables require a matching policy rule. PPPoE routes select the physical config interface and use `ppp0`. No policy-rule editor, foreign-route import/deletion or IPv6 WAN selection is added.
- **Firewall:** input/forward rules with ordering, named sets, port forwarding, default policies, masquerade and blocklists. Forward Accept rules offer **Route via WAN** (default: System routing) for new IPv4 outbound connections. Eligible configured WANs require return routing enabled; `route_via` saves their configured name, including for PPPoE. The first matching WAN selector pins the connection; filtering remains independent. **Preserve internal routes** defaults on, keeping configured internal subnets on normal routing. Turning it off includes internal destinations in the WAN selection; a warning explains that the WAN table needs a more-specific LAN route to keep that destination directly reachable. The mode is stored per connection and the saved flag is `preserve_internal_routes`. Router-local, WAN-ingress, DNAT/hairpin and TPROXY traffic keep their existing behavior. Preserved mode uses an egress guard; strict mode uses a global lookup/unreachable policy pair at priorities 90/91, blocking fallback to main while honoring routes in the selected table. Egress matches and rate limits cannot be combined with WAN selection; nonempty connection states must include `new`. Masquerade remains explicit. The editor and forward-rules page warn when the selected WAN has no masquerade entry, resolving PPPoE to `ppp0`; routed networks without NAT remain allowed. Connection states are arrays; rule IDs survive editing.
- **DHCP & leases:** pools, reservations, and active Kea leases. Pool mutations fetch fresh configuration to avoid restoring deleted reservations.
- **Monitoring / Services:** real metric histories with two-second interface/firewall samples and a 30-minute history (up to 900 samples), plus confirmed live service controls. Monitoring refreshes metrics and live interface counters every two seconds. No placeholder connections or log views.
- **sing-box:** raw JSONC editor preserving comments and whitespace in `config.yml` under `singbox.config`. Save validates when the binary exists and updates routerd configuration/backups only. Full Apply validates again, writes `/etc/sing-box/config.jsonc` at `0600`, and restarts on change or first/forced Apply, or starts if inactive. Unchanged running sing-box and unchanged nftables rules are skipped after successful full Apply; failures invalidate that snapshot for safe retries. Existing external JSONC is not imported automatically: paste it into the editor and Save before Apply. An absent `singbox` section leaves external files/services unmanaged; empty configured text is rejected.
- **Startup hooks:** privileged shell scripts executed at normal startup, not each API Apply.
- **Configuration:** schema validation and backups. **Restore immediately replaces and applies configuration**, with confirmation and possible loss of access.

Firewall tabs are stored in the hash URL (for example, `#/firewall?tab=forward`) and survive refresh and browser back/forward navigation.

Save and Apply are distinct. The top-bar indicator uses `GET /api/config/apply/status`, polled every five seconds and refreshed after writes. The server compares saved typed configuration, including `singbox.config`, against the last successful in-process Apply, including saves by other clients; it does not read deployed JSONC. Apply is disabled when unchanged or while status is loading, refreshing, or unavailable. Same-content saves and saved reversions clear pending status; a first Apply or retry after failure remains available. This is not live service/kernel health or generated-file drift detection, and unsaved drafts do not count. Explicit API Apply and service controls remain available for recovery. Apply is not transactional; failure can leave partial changes. Hooks need normal startup rather than Apply. Unsaved editor drafts are protected against page navigation and reload, and background refetches do not overwrite drafts.

## Code layout

- `src/App.tsx`: session boundary, hash routing, responsive shell, themes, Apply confirmation.
- `src/pages/`: router-specific screens and editors.
- `src/components/`: structured form dialog, firewall editors, SVG time-series chart.
- `src/lib/api.ts`: abortable fetch, bearer token lifecycle, structured validation errors, normalization of omitted config fields.
- `src/lib/queries.ts`: query keys and polling intervals.
- `src/lib/ui.tsx`: dialogs, notifications, mutation invalidation, shared presentation.
- `src/lib/types.ts` and `src/lib/format.ts`: API contracts and pure formatting/parsing.
- `src/app.css`: Yacd-meta-inspired design tokens, layouts, accessibility and responsive styling.
- `tests/`: isolated Bun regressions. `e2e/`: mocked browser regression coverage.

Tokens use the existing `routerd_token` local-storage key. Logout, HTTP 401, and token changes clear query caches and unmount protected pages. Never render untrusted HTML: authenticated config contains secrets and any script running on the management origin can access the browser token. Section endpoints replace whole sections, so preserve unrelated fresh fields. See the root `README.md` and `ARCHITECTURE.md` for backend contracts and deployment cautions.

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

Traffic shaping lives at `#/shaper`. Profiles support WAN- or LAN-facing devices,
upload/download rates in decimal Mbit/s, NAT-aware host fairness, and optional
link overhead/framing. New profiles start disabled. Editors fetch the latest
configuration before replacing `/config/shaper`, retaining other profiles;
Save never applies. Rates should start below measured sustained link capacity.
The live card polls `/monitor/shaper` every five seconds and derives Mbit/s from
byte-counter deltas, skipping missing baselines and counter resets. Saved enable
state is labeled separately from live queues. Proxy-created WAN flows can hide
clients, so the editor offers LAN-facing shaping; bridge-only switching is not
automatically covered. The browser fixture intercepts both shaper endpoints.

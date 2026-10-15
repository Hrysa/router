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

## Validation and production

```bash
bun run test
bun run check
bun run build
```

The Bun tests cover port parsing, UTF-8 password limits, authentication/error handling, raw JSONC, stable rule IDs, interface editing, and preservation of current DHCP reservations during pool saves. `check` runs strict TypeScript checks. `build` type-checks and replaces generated `dist/` assets.

**Build the frontend before compiling Rust.** Rust embeds `web/dist/` into the binary, so a clean checkout requires these assets and rebuilding Rust without rebuilding the frontend can serve stale UI. `dist/` is ignored, not committed. `bun run preview` previews the built assets without an API proxy; use the dev server or a same-origin reverse proxy for real API access.

### Mocked browser regression tests

```bash
bun x playwright install chromium --only-shell
bun run test:e2e
```

Browser tests require a real Node.js 22+ runtime for Playwright; do not force its runner through Bun's Node compatibility layer. They start a loopback-only preview server for the production build. All `/api` requests are intercepted, with no passthrough to a real router. They cover desktop/mobile navigation, themes, saves, confirmation boundaries, raw JSONC, and session expiry. Run `bun run build` first. On systems without writable browser caches, set `PLAYWRIGHT_BROWSERS_PATH` to a writable temporary directory for both installation and tests. Playwright's Chromium also requires the usual host browser libraries.

## Pages and safety

- **Overview:** selected-interface traffic, memory, uptime, configured links, and service health. Traffic is bytes/s; physical and bridge traffic are not summed. Cumulative CPU counters are not displayed as invented percentages.
- **Interfaces:** static/DHCP/PPPoE, bridges and VLANs, plus live read-only link counters. Names are immutable on update. Interface fields offer configured/detected names with labels and link status; bridge members, firewall/NAT ingress, and masquerade support quick multi-selection. Custom names remain editable, including interfaces not currently detected.
- **Firewall:** input/forward rules with ordering, named sets, port forwarding, default policies, masquerade and blocklists. Connection states are arrays; rule IDs survive editing.
- **DHCP & leases:** pools, reservations, and active Kea leases. Pool mutations fetch fresh configuration to avoid restoring deleted reservations.
- **Monitoring / Services:** real metric histories and confirmed live service controls. No placeholder connections or log views.
- **sing-box:** raw JSONC editor preserving comments. Saving does not restart the process; Apply attempts to restart sing-box.
- **Startup hooks:** privileged shell scripts executed at normal startup, not each API Apply.
- **Configuration:** schema validation and backups. **Restore immediately replaces and applies configuration**, with confirmation and possible loss of access.

Save and Apply are distinct. The top-bar indicator records saves in this browser only; it cannot prove server synchronization or detect another client's changes. Apply is not transactional; failure can leave partial changes. Hooks need normal startup rather than Apply. Unsaved editor drafts are protected against page navigation and reload, and background refetches do not overwrite drafts.

## Code layout

- `src/App.tsx`: session boundary, hash routing, responsive shell, themes, Apply confirmation.
- `src/pages/`: router-specific screens and editors.
- `src/components/`: structured form dialog, firewall editors, SVG time-series chart.
- `src/lib/api.ts`: abortable fetch, bearer token lifecycle, structured validation errors, normalization of omitted config fields.
- `src/lib/queries.ts`: query keys and polling intervals.
- `src/lib/ui.tsx`: dialogs, notifications, mutation invalidation, pending-save tracking, shared presentation.
- `src/lib/types.ts` and `src/lib/format.ts`: API contracts and pure formatting/parsing.
- `src/app.css`: Yacd-meta-inspired design tokens, layouts, accessibility and responsive styling.
- `tests/`: isolated Bun regressions. `e2e/`: mocked browser regression coverage.

Tokens use the existing `routerd_token` local-storage key. Logout, HTTP 401, and token changes clear query caches and unmount protected pages. Never render untrusted HTML: authenticated config contains secrets and any script running on the management origin can access the browser token. Section endpoints replace whole sections, so preserve unrelated fresh fields. See the root `README.md` and `ARCHITECTURE.md` for backend contracts and deployment cautions.

# AGENTS.md

## Important Notices

**DO NOT modify anything in `config/` folder unless explicitly asked.** This includes `config.yml` and `backups/`. Note `/config/` is gitignored — the real schema reference is `src/config/schema.rs`.

**Pre-apply syntax validation:** `nft -j -c -f` on the staged JSON ruleset is the only *required* check (apply fails without it). `kea-dhcp4 -t` runs only if the binary is installed, otherwise skipped. Everything else (ppp, wireguard, networkd, sysctl) relies on schema validation in `src/config/validator.rs` only.

**systemd-networkd configs use a `50-routerd-` prefix** (e.g., `50-routerd-wan.network`). These are the only auto-generated files with prefix-based cleanup — stale prefixed files are deleted on each apply. Other services (kea, ppp, wireguard, sysctl) write to fixed paths and overwrite atomically (`.tmp` + rename).

## Architecture facts that aren't obvious

- **DHCP is kea-dhcp4.** Renderer is `src/renderer/kea.rs` → `/etc/kea/kea-dhcp4.conf` (JSON). systemd unit is `kea-dhcp4-server`. API accepts service aliases `dhcpd|kea-dhcp4|dhcp`.
- **nftables is rendered as JSON, not a text config.** `src/renderer/nftables.rs` builds a ruleset with the `nftables` crate and it is applied via `nft -j -f` — nothing is written to `/etc/nftables.conf`. Tables: `inet filter` (rules), `ip nat` (DNAT/masquerade), `inet mangle` (tproxy), `inet blackhole` (blocked set). Every rule's comment is `[<id>] <comment>`; `/api/firewall/stats` parses those IDs out of `nft -j list chain` output to match counters — keep the format if you touch the renderer.
- **sing-box is user-managed, not rendered.** `/etc/sing-box/config.jsonc` is edited directly via `PUT /api/singbox/config` (validated with `sing-box check`). It is restarted on *every* apply regardless of changeset. `routerd --install-singbox` downloads the binary and exits.
- **Apply pipeline** (`src/service/apply.rs`): render → staged syntax check → atomic write → restart *only changed* services (file-content diff; nftables always considered changed). Exceptions: nftables is applied via `nft -j -f` (never `systemctl restart nftables`), networkd via `networkctl reload`, and sing-box always restarts (above).
- **SPA is embedded in the binary** via rust-embed (`#[folder = "web/dist/"]` in `src/api/server.rs`). `web/dist/` is committed; after changing `web/`, run `npm run build` there or the binary serves stale UI. Vite dev server proxies `/api` to a hard-coded router IP (`web/vite.config.ts`) — edit it for your target.

## Commands

```bash
cargo test                    # tests are inline #[test]/#[tokio::test] in src/, no tests/ dir
cargo clippy
cd web && npm run check       # svelte-check + tsc; run after touching web/
cd web && npm run build       # required before cargo build to refresh embedded UI
RUST_LOG=debug cargo run      # dev run uses ./config/ by default
```

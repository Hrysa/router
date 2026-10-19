# Project review — 2026-10-19

## Scope

Reviewed startup modes, authentication, API mutations, persistence/backups,
rendering and Apply, routing/TPROXY, WAN-group health, PPP lifecycle, native CAKE
ownership, DHCP lease handling, metrics, the React editors/session lifecycle,
release automation, and the setup/architecture/frontend documentation.

Validation uses temporary files, fake command/socket fixtures, intercepted browser
APIs, and fresh network namespaces. Runtime `config/`, deployed configuration,
host interfaces/firewall, and live services were not changed. This review is not
a penetration test or proof of a production deployment.

## Corrections

| Finding | Result |
| --- | --- |
| Release packaging invoked `routerd --version`, but the CLI did not expose it. | Added Clap package-version support and an early-exit regression test. |
| Kea listeners excluded static VLAN LANs; empty gateway overrides used the first LAN even for another subnet. | Bind all static internal interfaces and prefer a gateway address within each pool subnet. Explicit overrides remain intact. |
| DHCPv4 validation accepted IPv6, reversed/out-of-subnet ranges, and unsuitable DNS/gateway values. | Validate IPv4 pool/reservation data and ordered in-subnet ranges before saving. |
| Reservation identity checks treated MAC case/separator variants as different devices. | Normalize identities consistently for duplicate detection, deletion, and Kea rendering. |
| Default `reject` policies silently rendered as Drop. | Render a terminal Reject rule over a fail-closed Drop base policy, including the existing TPROXY deferral path. |
| Named-set updates could rename a referenced set; deletion checks missed bare port-set references. | Keep names immutable and recognize both `name` and `@name` port references. |
| TPROXY cleanup discarded command failures and removed at most one duplicate rule. | Plan from live IPv4 snapshots, remove all matching unscoped rules, refuse ambiguous/foreign selectors, preserve unrelated routes, and propagate required-operation failures. |
| Some routing, sysctl, and counter commands could run without bounds. | Reuse kill-on-drop 30-second command timeouts for routing/sysctl; bound each firewall-counter read to three seconds. |
| Firewall editors advertised unsupported port-forward protocols and retained incompatible fields when switching to TPROXY. | Offer TCP/UDP/TCP+UDP for DNAT; hide/clear TPROXY egress/rate conditions and expose supported Reject defaults. |
| Browser coverage was not a release prerequisite, and a chart assertion became ambiguous after a second chart was added. | Run mocked desktop/mobile tests as a release dependency; scope the assertion to the traffic card. |
| Documentation contained outdated installer/stub claims, generic network filenames, unsafe development examples, and feature sections after the license. | Reorganize the current setup/runtime documentation and replace the old review status with this dated report. |

NAT source/destination filters accept IPv4 addresses/subnets, `@local` (the
router's own addresses), or configured IPv4 sets;
the translated destination remains a single IPv4 address. JWT-secret initialization
also takes the configuration operation lock. Save-versus-Apply, startup isolation,
secret-file permissions, snapshot publication, and explicit restore semantics
remain unchanged.

## Verification

- Rust: `cargo test --locked` passed 184 tests; the nine ignored native tests
  also passed in isolated network namespaces, including real Kea/nftables
  validation and routing, PPP, WAN-group, and CAKE lifecycle checks.
- Frontend: 44 Bun tests, strict TypeScript checks, and the production build
  passed. Playwright passed all 84 mocked desktop/mobile browser cases using
  Node.js 22 and Chromium.
- `cargo clippy --locked --all-targets -- -D warnings`, Rust formatting,
  release-workflow Actionlint, and `git diff --check` passed.

No live Apply or production service reconciliation was performed. The native
musl build matrix and GitHub release publication require the hosted workflow.

## Remaining limits

- Apply spans files, services, and kernel state and is not transactional. Failure
  can leave partial changes. Backup restore is an explicit forced Apply, not
  automatic recovery or a restore of arbitrary external files/kernel state.
- Applied snapshots are in memory. Startup does not prove the saved state was
  successfully applied; status and service-content snapshots do not detect live
  kernel drift. Failed Apply can suspend WAN/shaper background reconciliation
  until a successful retry.
- First-time setup is public until configured. The default listener is
  `0.0.0.0:8443`, over HTTP unless both TLS flags are supplied. Login has no built-in
  per-client rate limit. Bootstrap and manage over trusted access.
- Hooks intentionally execute administrator shell commands. Authenticated config
  includes secrets, JWTs last 24 hours, and restoration can replace auth state.
  Current middleware observes secret changes; this is one administrator trust
  boundary rather than separate user roles.
- Routerd replaces only its four owned nftables tables. Other tools need distinct
  table names. TPROXY is IPv4 TCP/UDP; eligibility sees pre-DNAT addresses and
  conservatively defers egress/rate-dependent decisions to normal forwarding.
  Established-flow shortcuts are retained, not immediate access revocation.
- WAN groups select IPv4 forwarded connections, not sing-box's locally created
  outbound sockets. ICMP filtering can mark a working WAN unhealthy. Existing
  connections cannot migrate seamlessly between public IPs. Static routes alone
  have no active health-based failover. Only one PPPoE tunnel (`ppp0`) is managed.
- CAKE requires appropriate kernel support and ownership records; it does not
  shape pure bridge switching as routed traffic. Namespace tests do not establish
  throughput or NIC-specific behavior on a deployed router.
- Active leases are read from Kea memfile CSV snapshots; unavailable files can
  appear as an empty list. Live deletion requires the optional lease-command hook
  installed in a supported directory and loaded through Apply. Deleting a lease
  does not revoke the address from an already connected client.
- sing-box JSONC is administrator-managed text. Save/full Apply use its external
  validator when installed. Startup modes leave deployed sing-box files/services
  alone; `--install-singbox` installs config/unit files, never the binary.
- `/api/monitor/traffic` and `/api/monitor/connections` remain placeholders;
  `monitoring.vnstat` has no automatic Apply lifecycle. Use implemented metrics
  and explicit service controls.
- Native integration tests and browser mocks do not replace a disposable-router
  deployment check. GitHub-hosted x86-64/ARM64 musl release builds and actual
  GitHub publication are not executed by this local review.

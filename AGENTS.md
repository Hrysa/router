# AGENTS.md

## Important Notices

**DO NOT modify anything in `config/` folder unless explicitly asked.** This includes `config.yml` and `backups/`.

**Pre-apply syntax validation exists for: nftables (`nft -c`), dhcpd (`dhcpd -t`), unbound (`unbound-checkconf`).** Schema-level validation on input config exists in `config/validator.rs`. Other services (ppp, wireguard, networkd, chrony) rely on schema validation only.

**systemd-networkd configs use a `50-routerd-` prefix** (e.g., `50-routerd-wan.network`). These are the only auto-generated files with prefix-based cleanup — stale prefixed files are deleted on each apply. Other services (nftables, dhcpd, unbound, ppp, wireguard) write to fixed paths and simply overwrite.

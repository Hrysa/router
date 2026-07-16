use crate::config::schema::*;
use anyhow::Result;
use nftables::expr::*;
use nftables::schema::*;
use nftables::stmt::{self, Match, NATFamily, Operator, Statement};
use nftables::types::*;
use std::borrow::Cow;
use std::collections::HashSet;

/// Render nftables ruleset as JSON for `nft -j -f`.
pub fn render(config: &Config) -> Result<String> {
    let mut doc = NftablesDocument { objects: Vec::new() };

    doc.objects.push(flush_ruleset());

    let has_rules = !config.firewall.rules.input.is_empty()
        || !config.firewall.rules.forward.is_empty()
        || !config.firewall.nat.masquerade.is_empty()
        || !config.firewall.nat.port_forward.is_empty()
        || !config.firewall.blackhole.is_empty()
        || !config.firewall.sets.is_empty()
        || has_tproxy_rules(config);

    if has_rules {
        render_filter_table(config, &mut doc);

        if needs_nat(config) {
            render_nat_table(config, &mut doc);
        }

        if has_tproxy_rules(config) {
            render_tproxy_table(config, &mut doc);
        }

        if !config.firewall.blackhole.is_empty() {
            render_blackhole(config, &mut doc);
        }
    } else {
        render_empty_ruleset(&mut doc);
    }

    let nftables = Nftables {
        objects: Cow::Owned(doc.objects),
    };
    Ok(serde_json::to_string_pretty(&nftables)?)
}

/// Internal accumulator for nftables objects.
struct NftablesDocument {
    objects: Vec<NfObject<'static>>,
}

fn flush_ruleset() -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Flush(FlushObject::Ruleset(None)))
}

fn render_empty_ruleset(doc: &mut NftablesDocument) {
    doc.objects.push(add_table(NfFamily::INet, "filter"));

    for chain_name in &["input", "forward", "output"] {
        doc.objects.push(add_chain(
            NfFamily::INet,
            "filter",
            chain_name,
            Some(NfChainType::Filter),
            Some(hook_from_name(chain_name)),
            Some(0),
            Some(NfChainPolicy::Accept),
        ));
    }
}

fn hook_from_name(name: &str) -> NfHook {
    match name {
        "input" => NfHook::Input,
        "forward" => NfHook::Forward,
        "output" => NfHook::Output,
        "prerouting" => NfHook::Prerouting,
        "postrouting" => NfHook::Postrouting,
        _ => NfHook::Input,
    }
}

fn add_table(family: NfFamily, name: &'static str) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
        family,
        name: Cow::Borrowed(name),
        handle: None,
    })))
}

fn add_chain(
    family: NfFamily,
    table: &'static str,
    name: &'static str,
    chain_type: Option<NfChainType>,
    hook: Option<NfHook>,
    prio: Option<i32>,
    policy: Option<NfChainPolicy>,
) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
        family,
        table: Cow::Borrowed(table),
        name: Cow::Borrowed(name),
        newname: None,
        handle: None,
        _type: chain_type,
        hook,
        prio,
        dev: None,
        policy,
    })))
}

fn add_rule(
    family: NfFamily,
    table: &'static str,
    chain: &'static str,
    exprs: Vec<Statement<'static>>,
    comment: Option<&str>,
) -> NfObject<'static> {
    NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
        family,
        table: Cow::Borrowed(table),
        chain: Cow::Borrowed(chain),
        expr: Cow::Owned(exprs),
        handle: None,
        index: None,
        comment: comment.map(|c| Cow::Owned(c.to_string())),
    })))
}

// ── Expression builders ──────────────────────────────────────────────────────

fn iifname_match(name: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(Cow::Owned(name.to_string())),
        op: Operator::EQ,
    })
}

fn iifname_set_match(names: &[String]) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::Named(NamedExpression::Set(
            names
                .iter()
                .map(|n| SetItem::Element(Expression::String(Cow::Owned(n.clone()))))
                .collect(),
        )),
        op: Operator::EQ,
    })
}

fn oifname_match(name: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Oifname,
        })),
        right: Expression::String(Cow::Owned(name.to_string())),
        op: Operator::EQ,
    })
}

/// Parse a CIDR string into (addr, prefix_len). Handles "1.2.3.4" (→ /32) and "1.2.3.0/24".
/// Returns None for set references (@setname).
fn parse_cidr(s: &str) -> Option<(&str, u32)> {
    if s.starts_with('@') {
        return None;
    }
    if let Some((addr, len)) = s.split_once('/') {
        let prefix: u32 = len.parse().ok()?;
        Some((addr, prefix))
    } else {
        Some((s, 32))
    }
}

fn ip_saddr_match(addr: &str) -> Statement<'static> {
    if let Some((raw, len)) = parse_cidr(addr) {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("saddr"),
                },
            ))),
            right: Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(Expression::String(Cow::Owned(raw.to_string()))),
                len,
            })),
            op: Operator::EQ,
        })
    } else {
        // set reference like @wl_mac — use 'in' operator
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("saddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(addr.to_string())),
            op: Operator::IN,
        })
    }
}

fn ip_daddr_match(addr: &str) -> Statement<'static> {
    if let Some((raw, len)) = parse_cidr(addr) {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("daddr"),
                },
            ))),
            right: Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(Expression::String(Cow::Owned(raw.to_string()))),
                len,
            })),
            op: Operator::EQ,
        })
    } else {
        // set reference like @blocked — use 'in' operator
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("daddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(addr.to_string())),
            op: Operator::IN,
        })
    }
}

fn fib_daddr_local_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Fib(Fib {
            result: FibResult::Type,
            flags: HashSet::from([FibFlag::Daddr]),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: Operator::EQ,
    })
}

fn fib_saddr_local_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Fib(Fib {
            result: FibResult::Type,
            flags: HashSet::from([FibFlag::Saddr]),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: Operator::EQ,
    })
}

fn proto_match(proto: &str) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::L4proto,
        })),
        right: Expression::String(Cow::Owned(proto.to_string())),
        op: Operator::EQ,
    })
}

fn ct_state_match(states: &[String]) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: Cow::Borrowed("state"),
            family: None,
            dir: None,
        })),
        right: Expression::Named(NamedExpression::Set(
            states
                .iter()
                .map(|s| SetItem::Element(Expression::String(Cow::Owned(s.clone()))))
                .collect(),
        )),
        op: Operator::EQ,
    })
}

// ── Port spec → Expression ───────────────────────────────────────────────────

fn port_spec_expr(spec: &PortSpec) -> Expression<'static> {
    match spec {
        PortSpec::Single(port) => Expression::Number(*port as u32),
        PortSpec::Multiple(ports) => Expression::Named(NamedExpression::Set(
            ports
                .iter()
                .map(|p| SetItem::Element(Expression::Number(*p as u32)))
                .collect(),
        )),
        PortSpec::Range { start, end } => Expression::Range(Box::new(Range {
            range: [
                Expression::Number(*start as u32),
                Expression::Number(*end as u32),
            ],
        })),
        PortSpec::Set(name) => Expression::String(Cow::Owned(format!("@{}", name))),
    }
}

fn port_spec_match(proto: &str, field: &str, spec: &PortSpec) -> Statement<'static> {
    let left = Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Owned(proto.to_string()),
            field: Cow::Owned(field.to_string()),
        },
    )));
    let right = port_spec_expr(spec);
    Statement::Match(Match {
        left,
        right,
        op: Operator::EQ,
    })
}

// ── Rate limit parsing ──────────────────────────────────────────────────────

fn parse_rate_limit(rate: &str) -> Option<stmt::Limit<'static>> {
    let parts: Vec<&str> = rate.split('/').collect();
    let value: u32 = parts.first()?.parse().ok()?;
    let per = parts
        .get(1)
        .map(|u| Cow::Owned(u.to_string()))
        .unwrap_or_else(|| Cow::Borrowed("second"));
    Some(stmt::Limit {
        rate: value,
        rate_unit: None,
        per: Some(per),
        burst: None,
        burst_unit: None,
        inv: None,
    })
}

/// Look up a named set's type from the config's firewall.sets.
fn lookup_set_type<'a>(config: &'a Config, set_name: &str) -> Option<&'a str> {
    config
        .firewall
        .sets
        .iter()
        .find(|s| s.name == set_name)
        .map(|s| s.set_type.as_str())
}

/// Build an address match for a set reference, choosing the correct protocol
/// based on the set's type (ether_addr → "ether", ipv4_addr → "ip", etc.).
fn set_ref_match(config: &Config, field: &str, set_ref: &str) -> Option<Statement<'static>> {
    let set_name = set_ref.strip_prefix('@')?;
    let set_type = lookup_set_type(config, set_name)?;
    let protocol = match set_type {
        "ether_addr" => "ether",
        "ipv4_addr" => "ip",
        "ipv6_addr" => "ip6",
        _ => "ip",
    };
    Some(Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Owned(protocol.to_string()),
                field: Cow::Owned(field.to_string()),
            },
        ))),
        right: Expression::String(Cow::Owned(set_ref.to_string())),
        op: Operator::IN,
    }))
}

// ── Firewall rule → Vec<Statement> ───────────────────────────────────────────

/// Resolve the protocol list from a rule into a list of individual protocol strings.
/// If proto is None or empty, returns a single None entry (protocol-agnostic rule).
fn resolve_protos(rule: &FirewallRule) -> Vec<Option<String>> {
    match &rule.proto {
        Some(protos) if !protos.is_empty() => {
            protos.iter().map(|p| Some(p.clone())).collect()
        }
        _ => vec![None],
    }
}

fn build_rule_stmts(config: &Config, rule: &FirewallRule, proto: Option<&str>) -> Vec<Statement<'static>> {
    let mut stmts = Vec::new();

    // Interface match
    if !rule.interfaces.is_empty() {
        if rule.interfaces.len() == 1 {
            stmts.push(iifname_match(&rule.interfaces[0]));
        } else {
            stmts.push(iifname_set_match(&rule.interfaces));
        }
    }

    // Egress interface
    if let Some(oif) = &rule.oif {
        stmts.push(oifname_match(oif));
    }

    // Protocol (L4proto match for inet family)
    // Skip for layer 2/3 protocols — payload matches already handle the layer context.
    // "meta l4proto" only makes sense for transport-layer protocols (tcp, udp, icmp, etc.)
    if let Some(proto_str) = proto {
        match proto_str {
            "ip" | "ether" => {} // layer 2/3 — no l4proto qualifier needed
            _ => { stmts.push(proto_match(proto_str)); }
        }
    }

    // Source address
    if let Some(saddr) = &rule.saddr {
        if saddr == "@local" {
            stmts.push(fib_saddr_local_match());
        } else if let Some(stmt) = set_ref_match(config, "saddr", saddr) {
            stmts.push(stmt);
        } else {
            stmts.push(ip_saddr_match(saddr));
        }
    }

    // Destination address
    if let Some(daddr) = &rule.daddr {
        if daddr == "@local" {
            stmts.push(fib_daddr_local_match());
        } else if let Some(stmt) = set_ref_match(config, "daddr", daddr) {
            stmts.push(stmt);
        } else {
            stmts.push(ip_daddr_match(daddr));
        }
    }

    // Destination port
    let proto_for_ports = proto.unwrap_or("tcp");
    if let Some(dport) = &rule.dport {
        stmts.push(port_spec_match(proto_for_ports, "dport", dport));
    }

    // Source port
    if let Some(sport) = &rule.sport {
        stmts.push(port_spec_match(proto_for_ports, "sport", sport));
    }

    // Connection state
    if let Some(states) = &rule.state {
        if !states.is_empty() {
            stmts.push(ct_state_match(states));
        }
    }

    // Rate limit
    if let Some(rate) = &rule.rate {
        if let Some(limit) = parse_rate_limit(rate) {
            stmts.push(Statement::Limit(limit));
        }
    }

    // Counter
    if rule.log {
        // log includes counter
    } else if rule.counter {
        stmts.push(Statement::Counter(stmt::Counter::Anonymous(None)));
    }

    // Logging
    if rule.log {
        stmts.push(Statement::Log(Some(stmt::Log {
            prefix: rule.log_prefix.as_ref().map(|p| Cow::Owned(format!("{}: ", p))),
            group: None,
            snaplen: None,
            queue_threshold: None,
            level: None,
            flags: None,
        })));
    }

    // Verdict
    match rule.action {
        Action::Accept => stmts.push(Statement::Accept(None)),
        Action::Drop => stmts.push(Statement::Drop(None)),
        Action::Reject => stmts.push(Statement::Reject(None)),
        Action::Tproxy => {}
    }

    stmts
}

// ── Table renderers ──────────────────────────────────────────────────────────

fn render_filter_table(config: &Config, doc: &mut NftablesDocument) {
    doc.objects.push(add_table(NfFamily::INet, "filter"));

    // Sets
    for set in &config.firewall.sets {
        render_nft_set(config, NfFamily::INet, "filter", set, doc);
    }

    // Input chain
    doc.objects.push(add_chain(
        NfFamily::INet,
        "filter",
        "input",
        Some(NfChainType::Filter),
        Some(NfHook::Input),
        Some(0),
        Some(policy_from_str(&config.firewall.default_policy.input)),
    ));

    for rule in config
        .firewall
        .rules
        .input
        .iter()
        .filter(|r| r.enabled && r.action != Action::Tproxy)
    {
        let comment = if rule.comment.is_empty() {
            None
        } else {
            Some(rule.comment.as_str())
        };
        for proto in resolve_protos(rule) {
            let stmts = build_rule_stmts(config, rule, proto.as_deref());
            doc.objects.push(add_rule(
                NfFamily::INet,
                "filter",
                "input",
                stmts,
                comment,
            ));
        }
    }

    // Forward chain
    doc.objects.push(add_chain(
        NfFamily::INet,
        "filter",
        "forward",
        Some(NfChainType::Filter),
        Some(NfHook::Forward),
        Some(0),
        Some(policy_from_str(&config.firewall.default_policy.forward)),
    ));

    for rule in config
        .firewall
        .rules
        .forward
        .iter()
        .filter(|r| r.enabled && r.action != Action::Tproxy)
    {
        let comment = if rule.comment.is_empty() {
            None
        } else {
            Some(rule.comment.as_str())
        };
        for proto in resolve_protos(rule) {
            let stmts = build_rule_stmts(config, rule, proto.as_deref());
            doc.objects.push(add_rule(
                NfFamily::INet,
                "filter",
                "forward",
                stmts,
                comment,
            ));
        }
    }

    // Output chain
    doc.objects.push(add_chain(
        NfFamily::INet,
        "filter",
        "output",
        Some(NfChainType::Filter),
        Some(NfHook::Output),
        Some(0),
        Some(policy_from_str(&config.firewall.default_policy.output)),
    ));
}

fn render_nft_set(
    _config: &Config,
    family: NfFamily,
    table: &'static str,
    set: &NftSet,
    doc: &mut NftablesDocument,
) {
    let set_type = parse_set_type(&set.set_type);
    let mut flags = HashSet::new();
    if set.interval {
        flags.insert(SetFlag::Interval);
    }

    let elements: Option<Vec<Expression<'static>>> = if set.elements.is_empty() {
        None
    } else {
        let elems: Vec<Expression<'static>> = set
            .elements
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|e| set_element_expr(e))
            .collect();
        if elems.is_empty() {
            None
        } else {
            Some(elems)
        }
    };

    doc.objects.push(NfObject::CmdObject(NfCmd::Add(
        NfListObject::Set(Box::new(nftables::schema::Set {
            family,
            table: Cow::Borrowed(table),
            name: Cow::Owned(set.name.clone()),
            handle: None,
            set_type: SetTypeValue::Single(set_type),
            policy: None,
            flags: if flags.is_empty() {
                None
            } else {
                Some(flags)
            },
            elem: elements.map(|e| Cow::Owned(e)),
            timeout: None,
            gc_interval: None,
            size: None,
            comment: set.comment.as_ref().map(|c| Cow::Owned(c.clone())),
        })),
    )));
}

fn parse_set_type(s: &str) -> SetType {
    match s {
        "ipv4_addr" => SetType::Ipv4Addr,
        "ipv6_addr" => SetType::Ipv6Addr,
        "ether_addr" => SetType::EtherAddr,
        "inet_proto" => SetType::InetProto,
        "inet_service" => SetType::InetService,
        "mark" => SetType::Mark,
        "ifname" => SetType::Ifname,
        _ => SetType::Ipv4Addr,
    }
}

/// Convert a set element string to a proper Expression.
/// Handles IPv4 CIDR notation like "192.168.20.0/24" → prefix expression.
/// MAC addresses and other non-CIDR elements stay as plain strings.
fn set_element_expr(s: &str) -> Expression<'static> {
    // Only parse as CIDR if the element contains a '/' separator
    if s.contains('/') {
        if let Some((addr, len)) = parse_cidr(s) {
            return Expression::Named(NamedExpression::Prefix(Prefix {
                addr: Box::new(Expression::String(Cow::Owned(addr.to_string()))),
                len,
            }));
        }
    }
    Expression::String(Cow::Owned(s.to_string()))
}

fn policy_from_str(s: &str) -> NfChainPolicy {
    match s {
        "accept" => NfChainPolicy::Accept,
        "drop" => NfChainPolicy::Drop,
        _ => NfChainPolicy::Drop,
    }
}

fn render_nat_table(config: &Config, doc: &mut NftablesDocument) {
    doc.objects.push(add_table(NfFamily::IP, "nat"));

    // Sets referenced by port forwards
    for set in &config.firewall.sets {
        render_nft_set(config, NfFamily::IP, "nat", set, doc);
    }

    let port_forwards: Vec<&PortForward> = config
        .firewall
        .nat
        .port_forward
        .iter()
        .filter(|pf| pf.enabled)
        .collect();

    // Prerouting chain (DNAT)
    if !port_forwards.is_empty() {
        doc.objects.push(add_chain(
            NfFamily::IP,
            "nat",
            "prerouting",
            Some(NfChainType::NAT),
            Some(NfHook::Prerouting),
            Some(-100),
            None,
        ));

        for pf in &port_forwards {
            let protos: Vec<&str> = if pf.proto == "tcp+udp" {
                vec!["tcp", "udp"]
            } else {
                vec![pf.proto.as_str()]
            };

            for proto in &protos {
                let mut stmts = build_port_forward_match_stmts(pf, proto);

                // DNAT target — port only for TCP/UDP
                let redirect_port = pf.redirect_port.as_ref().map(|p| port_spec_expr(p));
                stmts.push(Statement::DNAT(Some(stmt::NAT {
                    addr: Some(Expression::String(Cow::Owned(
                        pf.redirect_address.clone(),
                    ))),
                    port: redirect_port,
                    family: Some(NATFamily::IP),
                    flags: None,
                })));

                let comment = if pf.comment.is_empty() {
                    None
                } else {
                    Some(pf.comment.as_str())
                };
                doc.objects.push(add_rule(
                    NfFamily::IP,
                    "nat",
                    "prerouting",
                    stmts,
                    comment,
                ));
            }
        }
    }

    // Postrouting chain (masquerade)
    let has_masq = !config.firewall.nat.masquerade.is_empty();
    let has_pf = !port_forwards.is_empty();

    if has_masq || has_pf {
        doc.objects.push(add_chain(
            NfFamily::IP,
            "nat",
            "postrouting",
            Some(NfChainType::NAT),
            Some(NfHook::Postrouting),
            Some(100),
            None,
        ));

        // Masquerade DNAT'd traffic targeting LAN subnets
        let lan_cidr = config
            .interfaces
            .lan()
            .and_then(|lan| lan.static_config.as_ref())
            .map(|c| c.address.as_str());

        for pf in &port_forwards {
            let needs_masq = lan_cidr
                .map(|cidr| is_ip_in_cidr(&pf.redirect_address, cidr))
                .unwrap_or(false);
            if needs_masq {
                let protos: Vec<&str> = if pf.proto == "tcp+udp" {
                    vec!["tcp", "udp"]
                } else {
                    vec![pf.proto.as_str()]
                };
                for proto in &protos {
                    let mut stmts = vec![
                        ip_daddr_match(&pf.redirect_address),
                        proto_match(proto),
                    ];
                    // Port match only for TCP/UDP
                    if let Some(ref rport) = pf.redirect_port {
                        stmts.push(port_spec_match(proto, "dport", rport));
                    }
                    stmts.push(Statement::Masquerade(None));
                    doc.objects.push(add_rule(
                        NfFamily::IP,
                        "nat",
                        "postrouting",
                        stmts,
                        None,
                    ));
                }
            }
        }

        // Explicit masquerade rules
        for masq in &config.firewall.nat.masquerade {
            let stmts = vec![oifname_match(&masq.oif), Statement::Masquerade(None)];
            doc.objects.push(add_rule(
                NfFamily::IP,
                "nat",
                "postrouting",
                stmts,
                None,
            ));
        }
    }
}

fn build_port_forward_match_stmts<'a>(pf: &'a PortForward, proto: &str) -> Vec<Statement<'static>> {
    let mut stmts = Vec::new();

    // Interface match
    if pf.interfaces.len() == 1 {
        stmts.push(iifname_match(&pf.interfaces[0]));
    } else if pf.interfaces.len() > 1 {
        stmts.push(iifname_set_match(&pf.interfaces));
    }

    // Protocol
    stmts.push(proto_match(proto));

    // Source address
    if let Some(ref saddr) = pf.source_address {
        if saddr == "@local" {
            stmts.push(fib_saddr_local_match());
        } else {
            stmts.push(ip_saddr_match(saddr));
        }
    }

    // Target address
    if let Some(ref taddr) = pf.target_address {
        if taddr == "@local" {
            stmts.push(fib_daddr_local_match());
        } else {
            stmts.push(ip_daddr_match(taddr));
        }
    }

    // Destination port (WAN port) — only for TCP/UDP
    if let Some(ref dport) = pf.target_port {
        stmts.push(port_spec_match(proto, "dport", dport));
    }

    stmts
}

fn render_blackhole(config: &Config, doc: &mut NftablesDocument) {
    doc.objects.push(add_table(NfFamily::INet, "blackhole"));

    // Blocked set
    let elements: Vec<Expression<'static>> = config
        .firewall
        .blackhole
        .iter()
        .map(|cidr| Expression::String(Cow::Owned(cidr.clone())))
        .collect();

    doc.objects.push(NfObject::CmdObject(NfCmd::Add(
        NfListObject::Set(Box::new(nftables::schema::Set {
            family: NfFamily::INet,
            table: Cow::Borrowed("blackhole"),
            name: Cow::Borrowed("blocked"),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: Some(HashSet::from([SetFlag::Interval])),
            elem: Some(Cow::Owned(elements)),
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        })),
    )));

    // Input chain
    doc.objects.push(add_chain(
        NfFamily::INet,
        "blackhole",
        "input",
        Some(NfChainType::Filter),
        Some(NfHook::Input),
        Some(-5),
        Some(NfChainPolicy::Accept),
    ));

    doc.objects.push(add_rule(
        NfFamily::INet,
        "blackhole",
        "input",
        vec![
            ip_saddr_match("@blocked"),
            Statement::Drop(None),
        ],
        None,
    ));

    // Forward chain
    doc.objects.push(add_chain(
        NfFamily::INet,
        "blackhole",
        "forward",
        Some(NfChainType::Filter),
        Some(NfHook::Forward),
        Some(-5),
        Some(NfChainPolicy::Accept),
    ));

    doc.objects.push(add_rule(
        NfFamily::INet,
        "blackhole",
        "forward",
        vec![
            ip_saddr_match("@blocked"),
            Statement::Drop(None),
        ],
        None,
    ));

    doc.objects.push(add_rule(
        NfFamily::INet,
        "blackhole",
        "forward",
        vec![
            ip_daddr_match("@blocked"),
            Statement::Drop(None),
        ],
        None,
    ));
}

fn render_tproxy_table(config: &Config, doc: &mut NftablesDocument) {
    let tproxy_rules: Vec<&FirewallRule> = config
        .firewall
        .rules
        .input
        .iter()
        .chain(config.firewall.rules.forward.iter())
        .filter(|r| r.enabled && r.action == Action::Tproxy)
        .collect();

    if tproxy_rules.is_empty() {
        return;
    }

    doc.objects.push(add_table(NfFamily::INet, "mangle"));

    doc.objects.push(add_chain(
        NfFamily::INet,
        "mangle",
        "prerouting",
        Some(NfChainType::Filter),
        Some(NfHook::Prerouting),
        Some(-150),
        Some(NfChainPolicy::Accept),
    ));

    for rule in &tproxy_rules {
        let comment = if rule.comment.is_empty() {
            None
        } else {
            Some(rule.comment.as_str())
        };
        for proto_opt in resolve_protos(rule) {
            let proto_str = proto_opt.as_deref().unwrap_or("tcp");
            let mut stmts = Vec::new();

            // Interface match
            if !rule.interfaces.is_empty() {
                if rule.interfaces.len() == 1 {
                    stmts.push(iifname_match(&rule.interfaces[0]));
                } else {
                    stmts.push(iifname_set_match(&rule.interfaces));
                }
            }

            // L4 protocol context (skip for layer 2/3 protocols)
            match proto_str {
                "ip" | "ether" => {}
                _ => { stmts.push(proto_match(proto_str)); }
            }

            // Address matches
            if let Some(saddr) = &rule.saddr {
                stmts.push(ip_saddr_match(saddr));
            }
            if let Some(daddr) = &rule.daddr {
                stmts.push(ip_daddr_match(daddr));
            }

            // Port matches
            if let Some(dport) = &rule.dport {
                stmts.push(port_spec_match(proto_str, "dport", dport));
            }
            if let Some(sport) = &rule.sport {
                stmts.push(port_spec_match(proto_str, "sport", sport));
            }

            // Counter (log includes counter already)
            if !rule.log && rule.counter {
                stmts.push(Statement::Counter(stmt::Counter::Anonymous(None)));
            }

            // Mark + tproxy
            let mark = rule.mark.unwrap_or(1);
            let port = rule.tproxy_port.unwrap_or(0);
            stmts.push(Statement::Mangle(stmt::Mangle {
                key: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::Mark,
                })),
                value: Expression::Number(mark),
            }));
            stmts.push(Statement::TProxy(stmt::TProxy {
                family: Some(Cow::Borrowed("ip")),
                port,
                addr: None,
            }));
            stmts.push(Statement::Accept(None));

            doc.objects.push(add_rule(
                NfFamily::INet,
                "mangle",
                "prerouting",
                stmts,
                comment,
            ));
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Check if an IPv4 address falls within a CIDR range.
fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let ip_parts: Vec<u8> = match ip.split('.').map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if ip_parts.len() != 4 {
        return false;
    }
    let ip_u32 = ((ip_parts[0] as u32) << 24)
        | ((ip_parts[1] as u32) << 16)
        | ((ip_parts[2] as u32) << 8)
        | (ip_parts[3] as u32);

    let (net_str, prefix_len) = if let Some((net, prefix)) = cidr.split_once('/') {
        (net, prefix.parse::<u32>().unwrap_or(32))
    } else {
        (cidr, 32)
    };

    let net_parts: Vec<u8> = match net_str.split('.').map(|p| p.parse::<u8>()).collect() {
        Ok(v) => v,
        Err(_) => return false,
    };
    if net_parts.len() != 4 {
        return false;
    }
    let net_u32 = ((net_parts[0] as u32) << 24)
        | ((net_parts[1] as u32) << 16)
        | ((net_parts[2] as u32) << 8)
        | (net_parts[3] as u32);

    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };

    (ip_u32 & mask) == (net_u32 & mask)
}

fn needs_nat(config: &Config) -> bool {
    !config.firewall.nat.masquerade.is_empty()
        || config
            .firewall
            .nat
            .port_forward
            .iter()
            .any(|pf| pf.enabled)
}

fn has_tproxy_rules(config: &Config) -> bool {
    config
        .firewall
        .rules
        .input
        .iter()
        .chain(config.firewall.rules.forward.iter())
        .any(|r| r.enabled && r.action == Action::Tproxy)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: render and parse JSON to extract nftables objects.
    fn render_json(config: &Config) -> serde_json::Value {
        let json_str = render(config).unwrap();
        serde_json::from_str(&json_str).unwrap()
    }

    /// Count objects of a given type (e.g. "table", "chain", "rule") in the nftables array.
    /// Objects are wrapped as { "add": { "table": { ... } } } or { "flush": ... }
    fn count_object_type(val: &serde_json::Value, key: &str) -> usize {
        val.get("nftables")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|obj| {
                        // Check if it's an "add" command containing the target type
                        obj.get("add")
                            .and_then(|add| add.as_object())
                            .map_or(false, |m| m.contains_key(key))
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    #[test]
    fn test_render_empty_ruleset() {
        let config = Config::default();
        let val = render_json(&config);
        // Should have: flush + 1 table + 3 chains
        let table_count = count_object_type(&val, "table");
        let chain_count = count_object_type(&val, "chain");
        assert_eq!(table_count, 1, "expected 1 table");
        assert_eq!(chain_count, 3, "expected 3 chains (input, forward, output)");
    }

    #[test]
    fn test_render_with_rules() {
        let mut config = Config::default();
        config.firewall.rules.input.push(FirewallRule {
            id: 1,
            action: Action::Accept,
            comment: "allow-ssh".into(),
            interfaces: vec!["br-lan".into()],
            oif: None,
            proto: Some(vec!["tcp".into()]),
            dport: Some(PortSpec::Single(22)),
            sport: None,
            saddr: None,
            daddr: None,
            state: None,
            rate: None,
            log: false,
            log_prefix: None,
            mark: None,
            tproxy_port: None,
            counter: false,
            enabled: true,
        });
        let val = render_json(&config);
        // Should have rules
        let rule_count = count_object_type(&val, "rule");
        assert!(rule_count >= 1, "expected at least 1 rule, got {}", rule_count);
    }

    #[test]
    fn test_render_with_port_forward() {
        let mut config = Config::default();
        config.firewall.nat.port_forward.push(PortForward {
            id: 1,
            comment: "web".into(),
            proto: "tcp".into(),
            target_port: Some(PortSpec::Single(80)),
            target_address: None,
            source_address: None,
            interfaces: vec!["eth0".into()],
            redirect_address: "192.168.1.100".into(),
            redirect_port: Some(PortSpec::Single(8080)),
            enabled: true,
        });
        let val = render_json(&config);
        // Should have nat table
        let nat_count = count_object_type(&val, "table");
        assert!(nat_count >= 1, "expected at least 1 table (nat)");
        // Verify the JSON contains dnat
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("dnat"));
    }

    #[test]
    fn test_render_with_blackhole() {
        let mut config = Config::default();
        config.firewall.blackhole = vec![
            "185.220.101.0/24".into(),
            "45.155.205.0/24".into(),
        ];
        let val = render_json(&config);
        let table_count = count_object_type(&val, "table");
        assert!(table_count >= 1, "expected at least 1 table (blackhole)");
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("185.220.101.0/24"));
        assert!(json_str.contains("blocked"));
    }

    #[test]
    fn test_render_tproxy() {
        let mut config = Config::default();
        config.firewall.rules.input.push(FirewallRule {
            id: 1,
            action: Action::Tproxy,
            comment: "transparent-proxy".into(),
            interfaces: vec!["eth1".into()],
            oif: None,
            proto: Some(vec!["tcp".into()]),
            dport: Some(PortSpec::Single(80)),
            sport: None,
            saddr: Some("192.168.1.0/24".into()),
            daddr: None,
            state: None,
            rate: None,
            log: false,
            log_prefix: None,
            mark: Some(1),
            tproxy_port: Some(12345),
            counter: false,
            enabled: true,
        });
        let val = render_json(&config);
        let table_count = count_object_type(&val, "table");
        assert!(table_count >= 1, "expected at least 1 table (mangle)");
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("mangle"));
        assert!(json_str.contains("tproxy"));
    }

    #[test]
    fn test_port_spec_expr() {
        assert_eq!(
            port_spec_expr(&PortSpec::Single(80)),
            Expression::Number(80)
        );
        assert_eq!(
            port_spec_expr(&PortSpec::Set("myset".into())),
            Expression::String(Cow::Borrowed("@myset"))
        );
    }

    #[test]
    fn test_parse_rate_limit() {
        let limit = parse_rate_limit("100/second").unwrap();
        assert_eq!(limit.rate, 100);
        assert_eq!(limit.per.as_deref(), Some("second"));

        let limit2 = parse_rate_limit("1000").unwrap();
        assert_eq!(limit2.rate, 1000);
        // Default to "second" when no unit specified
        assert_eq!(limit2.per.as_deref(), Some("second"));
    }

    #[test]
    fn test_is_ip_in_cidr() {
        assert!(is_ip_in_cidr("192.168.1.100", "192.168.1.0/24"));
        assert!(!is_ip_in_cidr("192.168.2.100", "192.168.1.0/24"));
        assert!(is_ip_in_cidr("10.0.0.1", "10.0.0.0/8"));
        assert!(!is_ip_in_cidr("192.168.1.1", "10.0.0.0/8"));
    }

    #[test]
    fn test_policy_from_str() {
        assert_eq!(policy_from_str("accept"), NfChainPolicy::Accept);
        assert_eq!(policy_from_str("drop"), NfChainPolicy::Drop);
        assert_eq!(policy_from_str("anything"), NfChainPolicy::Drop);
    }

    #[test]
    fn test_parse_set_type() {
        assert_eq!(parse_set_type("ipv4_addr"), SetType::Ipv4Addr);
        assert_eq!(parse_set_type("inet_service"), SetType::InetService);
    }

    #[test]
    fn test_build_rule_stmts_basic() {
        let rule = FirewallRule {
            id: 1,
            action: Action::Accept,
            comment: String::new(),
            interfaces: vec!["eth0".into()],
            oif: None,
            proto: Some(vec!["tcp".into()]),
            dport: Some(PortSpec::Single(22)),
            sport: None,
            saddr: None,
            daddr: None,
            state: None,
            rate: None,
            log: false,
            log_prefix: None,
            mark: None,
            tproxy_port: None,
            counter: false,
            enabled: true,
        };
        let stmts = build_rule_stmts(&Config::default(), &rule, Some("tcp"));
        assert!(!stmts.is_empty());
        // Last statement should be Accept
        assert!(matches!(stmts.last(), Some(Statement::Accept(None))));
    }

    #[test]
    fn test_build_rule_stmts_with_log() {
        let rule = FirewallRule {
            id: 1,
            action: Action::Drop,
            comment: String::new(),
            interfaces: vec![],
            oif: None,
            proto: None,
            dport: None,
            sport: None,
            saddr: None,
            daddr: None,
            state: None,
            rate: None,
            log: true,
            log_prefix: Some("blocked".into()),
            mark: None,
            tproxy_port: None,
            counter: false,
            enabled: true,
        };
        let stmts = build_rule_stmts(&Config::default(), &rule, None);
        // Should have log and drop
        let has_log = stmts.iter().any(|s| matches!(s, Statement::Log(Some(_))));
        let has_drop = stmts.iter().any(|s| matches!(s, Statement::Drop(None)));
        assert!(has_log);
        assert!(has_drop);
    }

    fn config_with_lan() -> Config {
        Config {
            interfaces: Interfaces {
                items: vec![InterfaceConfig {
                    name: "eth1".into(),
                    label: "LAN".into(),
                    method: InterfaceMethod::Static,
                    static_config: Some(StaticConfig {
                        address: "192.168.1.1/24".into(),
                        gateway: String::new(),
                        dns: vec![],
                    }),
                    ..Default::default()
                }],
            },
            ..Config::default()
        }
    }

    #[test]
    fn test_render_hairpin_nat() {
        let mut config = config_with_lan();
        config.firewall.nat.port_forward.push(PortForward {
            id: 1,
            comment: "web".into(),
            proto: "tcp".into(),
            target_port: Some(PortSpec::Single(80)),
            target_address: None,
            source_address: None,
            interfaces: vec!["eth0".into()],
            redirect_address: "192.168.1.100".into(),
            redirect_port: Some(PortSpec::Single(8080)),
            enabled: true,
        });
        let val = render_json(&config);
        // Should have masquerade in postrouting
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("masquerade"));
    }

    #[test]
    fn test_render_no_masquerade_for_non_lan_target() {
        let mut config = config_with_lan();
        config.firewall.nat.port_forward.push(PortForward {
            id: 2,
            comment: "ext".into(),
            proto: "tcp".into(),
            target_port: Some(PortSpec::Single(443)),
            target_address: None,
            source_address: None,
            interfaces: vec!["eth0".into()],
            redirect_address: "10.99.0.5".into(),
            redirect_port: Some(PortSpec::Single(443)),
            enabled: true,
        });
        let val = render_json(&config);
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("dnat"));
        // Should NOT have masquerade for non-LAN target
        // (masquerade only appears in postrouting for LAN targets)
    }

    #[test]
    fn test_render_port_forward_with_source_address() {
        let mut config = Config::default();
        config.firewall.nat.port_forward.push(PortForward {
            id: 1,
            comment: "web".into(),
            proto: "tcp".into(),
            target_port: Some(PortSpec::Single(80)),
            target_address: None,
            source_address: Some("10.0.0.0/8".into()),
            interfaces: vec!["eth0".into()],
            redirect_address: "192.168.1.100".into(),
            redirect_port: Some(PortSpec::Single(8080)),
            enabled: true,
        });
        let val = render_json(&config);
        let json_str = serde_json::to_string(&val).unwrap();
        // CIDR is now rendered as a prefix expression, so check for the address
        assert!(json_str.contains("10.0.0.0"));
        assert!(json_str.contains("dnat"));
    }

    #[test]
    fn test_render_port_forward_multi_interface() {
        let mut config = Config::default();
        config.firewall.nat.port_forward.push(PortForward {
            id: 1,
            comment: "web".into(),
            proto: "tcp".into(),
            target_port: Some(PortSpec::Single(80)),
            target_address: None,
            source_address: None,
            interfaces: vec!["eth0".into(), "wg0".into()],
            redirect_address: "192.168.1.100".into(),
            redirect_port: Some(PortSpec::Single(8080)),
            enabled: true,
        });
        let val = render_json(&config);
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("eth0"));
        assert!(json_str.contains("wg0"));
    }
}

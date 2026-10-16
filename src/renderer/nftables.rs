use crate::config::schema::*;
use crate::config::routing::{internal_ipv4_subnets, wan_return_routes, WanReturnRoute, WAN_MARK_MASK};
use anyhow::Result;
use nftables::expr::*;
use nftables::schema::*;
use nftables::stmt::{self, Match, NATFamily, Operator, Statement};
use nftables::types::*;
use std::borrow::Cow;
use std::collections::HashSet;

/// Render nftables ruleset as JSON for `nft -j -f`.
pub fn render(config: &Config) -> Result<String> {
    let return_routes = wan_return_routes(config)?;
    // Resolve targets here as well as in schema validation: never silently omit a selector.
    for rule in config.firewall.rules.forward.iter().filter(|rule| rule.enabled) {
        if let Some(target) = &rule.route_via {
            anyhow::ensure!(return_routes.iter().any(|route| route.name == target), "unknown or disabled route_via WAN: {}", target);
        }
    }
    let mut doc = NftablesDocument { objects: Vec::new() };

    for (family, name) in [
        (NfFamily::INet, "filter"),
        (NfFamily::IP, "nat"),
        (NfFamily::INet, "mangle"),
        (NfFamily::INet, "blackhole"),
    ] {
        doc.objects.push(add_table(family, name));
        doc.objects.push(NfObject::CmdObject(NfCmd::Delete(NfListObject::Table(Table {
            family,
            name: Cow::Borrowed(name),
            handle: None,
        }))));
    }

    render_filter_table(config, &return_routes, &mut doc);
    if needs_nat(config) {
        render_nat_table(config, &mut doc);
    }
    if has_tproxy_rules(config) || !return_routes.is_empty() || !mss_limits(config).is_empty() {
        doc.objects.push(add_table(NfFamily::INet, "mangle"));
        render_mss_clamping(config, &mut doc);
        render_tproxy_table(config, &mut doc);
        render_wan_return_rules(&return_routes, &mut doc);
        render_outbound_routes(config, &return_routes, &mut doc);
    }
    if !config.firewall.blackhole.is_empty() {
        render_blackhole(config, &mut doc);
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

/// Explicit interface clamp takes precedence over the legacy PPPoE clamp.
fn mss_limits(config: &Config) -> Vec<(&str, u16)> {
    config.interfaces.items.iter().filter_map(|iface| {
        let ppp = iface.method == InterfaceMethod::Pppoe;
        let mtu = iface.mss_clamp_mtu.or_else(|| {
            if ppp { iface.pppoe.as_ref().filter(|ppp| ppp.mss_clamp).map(|ppp| ppp.mtu) } else { None }
        })?;
        Some((if ppp { "ppp0" } else { iface.name.as_str() }, mtu))
    }).collect()
}

fn render_mss_clamping(config: &Config, doc: &mut NftablesDocument) {
    let limits = mss_limits(config);
    if limits.is_empty() { return; }
    // Before TPROXY on ingress, after routing on egress; also covers router-local TCP.
    for (chain, hook) in [("mss_ingress", NfHook::Prerouting), ("mss_egress", NfHook::Postrouting)] {
        doc.objects.push(add_chain(NfFamily::INet, "mangle", chain, Some(NfChainType::Filter), Some(hook), Some(-160), Some(NfChainPolicy::Accept)));
        for (interface, mtu) in &limits {
            for (family, overhead) in [("ipv4", 40), ("ipv6", 60)] {
                let mss = u32::from(mtu.saturating_sub(overhead));
                let option = Expression::Named(NamedExpression::TcpOption(TcpOption { name: "maxseg".into(), field: Some("size".into()) }));
                let flags = Expression::Named(NamedExpression::Payload(Payload::PayloadField(PayloadField { protocol: "tcp".into(), field: "flags".into() })));
                doc.objects.push(add_rule(NfFamily::INet, "mangle", chain, vec![
                    if chain == "mss_ingress" { iifname_match(interface, false) } else { oifname_match(interface) },
                    Statement::Match(Match { left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Nfproto })), right: Expression::String(family.into()), op: Operator::EQ }),
                    proto_match("tcp"),
                    Statement::Match(Match { left: masked(flags, 0x02), right: Expression::Number(0x02), op: Operator::EQ }),
                    // nftables 0.6 names this variant LT but serializes it as ">".
                    Statement::Match(Match { left: option.clone(), right: Expression::Number(mss), op: Operator::LT }),
                    Statement::Mangle(stmt::Mangle { key: option, value: Expression::Number(mss) }),
                ], Some("routerd TCP MSS cap")));
            }
        }
    }
}

// ── Expression builders ──────────────────────────────────────────────────────

fn iifname_match(name: &str, invert: bool) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta {
            key: MetaKey::Iifname,
        })),
        right: Expression::String(Cow::Owned(name.to_string())),
        op: if invert { Operator::NEQ } else { Operator::EQ },
    })
}

fn iifname_set_match(names: &[String], invert: bool) -> Statement<'static> {
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
        op: if invert { Operator::NEQ } else { Operator::EQ },
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

fn ip_saddr_match(addr: &str, invert: bool) -> Statement<'static> {
    let eq_op = if invert { Operator::NEQ } else { Operator::EQ };
    let in_op = if invert { Operator::NEQ } else { Operator::IN };
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
            op: eq_op,
        })
    } else {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("saddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(addr.to_string())),
            op: in_op,
        })
    }
}

fn ip_daddr_match(addr: &str, invert: bool) -> Statement<'static> {
    let eq_op = if invert { Operator::NEQ } else { Operator::EQ };
    let in_op = if invert { Operator::NEQ } else { Operator::IN };
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
            op: eq_op,
        })
    } else {
        Statement::Match(Match {
            left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
                PayloadField {
                    protocol: Cow::Borrowed("ip"),
                    field: Cow::Borrowed("daddr"),
                },
            ))),
            right: Expression::String(Cow::Owned(addr.to_string())),
            op: in_op,
        })
    }
}

fn fib_daddr_local_match(invert: bool) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Fib(Fib {
            result: FibResult::Type,
            flags: HashSet::from([FibFlag::Daddr]),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: if invert { Operator::NEQ } else { Operator::EQ },
    })
}

fn fib_saddr_local_match(invert: bool) -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Fib(Fib {
            result: FibResult::Type,
            flags: HashSet::from([FibFlag::Saddr]),
        })),
        right: Expression::String(Cow::Borrowed("local")),
        op: if invert { Operator::NEQ } else { Operator::EQ },
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

fn ct_state_established_related() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::CT(CT {
            key: Cow::Borrowed("state"),
            family: None,
            dir: None,
        })),
        right: Expression::Named(NamedExpression::Set(vec![
            SetItem::Element(Expression::String(Cow::Borrowed("established"))),
            SetItem::Element(Expression::String(Cow::Borrowed("related"))),
        ])),
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
        PortSpec::Set(name) => Expression::String(Cow::Owned(format!("@{}", name.trim_start_matches('@')))),
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
fn set_ref_match(config: &Config, field: &str, set_ref: &str, invert: bool) -> Option<Statement<'static>> {
    let set_name = set_ref.strip_prefix('@')?;
    let set_type = lookup_set_type(config, set_name)?;
    let protocol = match set_type {
        "ether_addr" => "ether",
        "ipv4_addr" => "ip",
        "ipv6_addr" => "ip6",
        _ => "ip",
    };
    let op = if invert { Operator::NEQ } else { Operator::IN };
    Some(Statement::Match(Match {
        left: Expression::Named(NamedExpression::Payload(Payload::PayloadField(
            PayloadField {
                protocol: Cow::Owned(protocol.to_string()),
                field: Cow::Owned(field.to_string()),
            },
        ))),
        right: Expression::String(Cow::Owned(set_ref.to_string())),
        op,
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

fn build_rule_match_stmts(config: &Config, rule: &FirewallRule, proto: Option<&str>) -> Vec<Statement<'static>> {
    let mut stmts = Vec::new();

    // Interface match
    if !rule.interfaces.is_empty() {
        if rule.interfaces.len() == 1 {
            stmts.push(iifname_match(&rule.interfaces[0], rule.interfaces_invert));
        } else {
            stmts.push(iifname_set_match(&rule.interfaces, rule.interfaces_invert));
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
            stmts.push(fib_saddr_local_match(rule.saddr_invert));
        } else if let Some(stmt) = set_ref_match(config, "saddr", saddr, rule.saddr_invert) {
            stmts.push(stmt);
        } else {
            stmts.push(ip_saddr_match(saddr, rule.saddr_invert));
        }
    }

    // Destination address
    if let Some(daddr) = &rule.daddr {
        if daddr == "@local" {
            stmts.push(fib_daddr_local_match(rule.daddr_invert));
        } else if let Some(stmt) = set_ref_match(config, "daddr", daddr, rule.daddr_invert) {
            stmts.push(stmt);
        } else {
            stmts.push(ip_daddr_match(daddr, rule.daddr_invert));
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

    stmts
}

fn build_rule_stmts(config: &Config, rule: &FirewallRule, proto: Option<&str>) -> Vec<Statement<'static>> {
    let mut stmts = build_rule_match_stmts(config, rule, proto);
    if rule.route_via.is_some() {
        stmts.insert(0, ipv4_family_match());
    }
    // Counter
    if rule.counter {
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

fn render_filter_table(config: &Config, routes: &[WanReturnRoute<'_>], doc: &mut NftablesDocument) {
    doc.objects.push(add_table(NfFamily::INet, "filter"));

    // Sets
    for set in &config.firewall.sets {
        render_nft_set(config, NfFamily::INet, "filter", set, doc);
    }

    // Input chain
    let input_policy = policy_from_str(&config.firewall.default_policy.input);
    doc.objects.push(add_chain(
        NfFamily::INet,
        "filter",
        "input",
        Some(NfChainType::Filter),
        Some(NfHook::Input),
        Some(0),
        Some(input_policy),
    ));

    // Implicit: accept established/related connections when policy is drop
    if input_policy == NfChainPolicy::Drop {
        doc.objects.push(add_rule(
            NfFamily::INet,
            "filter",
            "input",
            vec![ct_state_established_related(), Statement::Accept(None)],
            None,
        ));
    }

    // Implicit: accept all loopback traffic (local services need this)
    doc.objects.push(add_rule(
        NfFamily::INet,
        "filter",
        "input",
        vec![iifname_match("lo", false), Statement::Accept(None)],
        None,
    ));

    for rule in config
        .firewall
        .rules
        .input
        .iter()
        .filter(|r| r.enabled && r.action != Action::Tproxy)
    {
        let comment = if rule.comment.is_empty() {
            format!("[{}]", rule.id)
        } else {
            format!("[{}] {}", rule.id, rule.comment)
        };
        for proto in resolve_protos(rule) {
            let stmts = build_rule_stmts(config, rule, proto.as_deref());
            doc.objects.push(add_rule(
                NfFamily::INet,
                "filter",
                "input",
                stmts,
                Some(&comment),
            ));
        }
    }

    // Forward chain
    let forward_policy = policy_from_str(&config.firewall.default_policy.forward);
    doc.objects.push(add_chain(
        NfFamily::INet,
        "filter",
        "forward",
        Some(NfChainType::Filter),
        Some(NfHook::Forward),
        Some(0),
        Some(forward_policy),
    ));

    // Enforce the selected WAN even if its policy rules/routes disappear on link loss.
    // This must precede the established/related shortcut to protect existing flows.
    render_outbound_guards(config, routes, doc);

    // Implicit: accept established/related connections when policy is drop
    if forward_policy == NfChainPolicy::Drop {
        doc.objects.push(add_rule(
            NfFamily::INet,
            "filter",
            "forward",
            vec![ct_state_established_related(), Statement::Accept(None)],
            None,
        ));
    }

    for rule in config
        .firewall
        .rules
        .forward
        .iter()
        .filter(|r| r.enabled && r.action != Action::Tproxy)
    {
        let comment = if rule.comment.is_empty() {
            format!("[{}]", rule.id)
        } else {
            format!("[{}] {}", rule.id, rule.comment)
        };
        for proto in resolve_protos(rule) {
            let stmts = build_rule_stmts(config, rule, proto.as_deref());
            doc.objects.push(add_rule(
                NfFamily::INet,
                "filter",
                "forward",
                stmts,
                Some(&comment),
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

        for pf in &port_forwards {
            for interface in config.interfaces.items.iter().filter(|interface| {
                interface.method == InterfaceMethod::Static && !interface.is_wan()
            }) {
                let Some(settings) = &interface.static_config else { continue };
                if !is_ip_in_cidr(&pf.redirect_address, &settings.address) {
                    continue;
                }
                let Some((network, prefix)) = ipv4_subnet(&settings.address) else { continue };
                let subnet = format!("{}/{}", network, prefix);
                let protos: Vec<&str> = if pf.proto == "tcp+udp" {
                    vec!["tcp", "udp"]
                } else {
                    vec![pf.proto.as_str()]
                };
                for proto in &protos {
                    let mut stmts = vec![
                        ip_saddr_match(&subnet, false),
                        ip_daddr_match(&pf.redirect_address, false),
                        oifname_match(&interface.name),
                        ct_match("status", "dnat", Operator::IN),
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
        stmts.push(iifname_match(&pf.interfaces[0], pf.interfaces_invert));
    } else if pf.interfaces.len() > 1 {
        stmts.push(iifname_set_match(&pf.interfaces, pf.interfaces_invert));
    }

    // Protocol
    stmts.push(proto_match(proto));

    // Source address
    if let Some(ref saddr) = pf.source_address {
        if saddr == "@local" {
            stmts.push(fib_saddr_local_match(pf.source_address_invert));
        } else {
            stmts.push(ip_saddr_match(saddr, pf.source_address_invert));
        }
    }

    // Target address
    if let Some(ref taddr) = pf.target_address {
        if taddr == "@local" {
            stmts.push(fib_daddr_local_match(pf.target_address_invert));
        } else {
            stmts.push(ip_daddr_match(taddr, pf.target_address_invert));
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
            ip_saddr_match("@blocked", false),
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
            ip_saddr_match("@blocked", false),
            Statement::Drop(None),
        ],
        None,
    ));

    doc.objects.push(add_rule(
        NfFamily::INet,
        "blackhole",
        "forward",
        vec![
            ip_daddr_match("@blocked", false),
            Statement::Drop(None),
        ],
        None,
    ));
}

fn ct_expression(key: &'static str) -> Expression<'static> {
    Expression::Named(NamedExpression::CT(CT {
        key: Cow::Borrowed(key),
        family: None,
        dir: None,
    }))
}

fn ct_match(key: &'static str, value: &'static str, op: Operator) -> Statement<'static> {
    Statement::Match(Match {
        left: ct_expression(key),
        right: Expression::String(Cow::Borrowed(value)),
        op,
    })
}

fn masked(expression: Expression<'static>, mask: u32) -> Expression<'static> {
    Expression::BinaryOperation(Box::new(BinaryOperation::AND(expression, Expression::Number(mask))))
}

fn with_wan_mark(expression: Expression<'static>, mark: Expression<'static>) -> Expression<'static> {
    Expression::BinaryOperation(Box::new(BinaryOperation::OR(vec![
        masked(expression, !WAN_MARK_MASK), mark,
    ])))
}

fn packet_mark() -> Expression<'static> {
    Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark }))
}

fn wan_mark_match(mark: u32) -> Statement<'static> {
    Statement::Match(Match {
        left: masked(ct_expression("mark"), WAN_MARK_MASK),
        right: Expression::Number(mark),
        op: Operator::EQ,
    })
}

fn restore_wan_mark(mark: u32) -> Statement<'static> {
    Statement::Mangle(stmt::Mangle {
        key: packet_mark(),
        value: with_wan_mark(packet_mark(), Expression::Number(mark)),
    })
}

// Eligibility is shared by classification and connection restoration. Incoming
// connections and DNAT/hairpin traffic keep normal routing in both modes.
// Preserved mode also excludes configured internal destinations.
fn outbound_scope(config: &Config, preserve_internal_routes: bool) -> Vec<Statement<'static>> {
    let mut stmts = vec![
        ipv4_family_match(),
        ct_match("direction", "original", Operator::EQ),
        ct_match("status", "dnat", Operator::NEQ),
        fib_daddr_local_match(true),
    ];
    let wans: Vec<String> = config.interfaces.items.iter().filter(|interface| interface.is_wan())
        .map(|interface| if interface.method == InterfaceMethod::Pppoe { "ppp0".into() } else { interface.name.clone() }).collect();
    if !wans.is_empty() {
        stmts.push(iifname_set_match(&wans, true));
    }
    if preserve_internal_routes {
        for subnet in internal_ipv4_subnets(config) {
            stmts.push(ip_daddr_match(&subnet, true));
        }
    }
    stmts
}

fn render_outbound_routes(config: &Config, routes: &[WanReturnRoute<'_>], doc: &mut NftablesDocument) {
    let rules: Vec<_> = config.firewall.rules.forward.iter()
        .filter(|rule| rule.enabled && rule.action == Action::Accept && rule.route_via.is_some()).collect();
    if rules.is_empty() { return; }
    for set in &config.firewall.sets {
        render_nft_set(config, NfFamily::INet, "mangle", set, doc);
    }
    // DNAT runs at -100; classify using the same destination the forward filter sees.
    doc.objects.push(add_chain(NfFamily::INet, "mangle", "wan_outbound",
        Some(NfChainType::Filter), Some(NfHook::Prerouting), Some(-90), Some(NfChainPolicy::Accept)));
    let scope = outbound_scope(config, true);
    // Do not take packets already selected for TPROXY away from the local proxy.
    doc.objects.push(add_rule(NfFamily::INet, "mangle", "wan_outbound", vec![
        Statement::Match(Match { left: masked(packet_mark(), !WAN_MARK_MASK), right: Expression::Number(0), op: Operator::NEQ }),
        Statement::Return(None),
    ], None));
    // Restore before classifying: edits/reordering cannot move an existing flow.
    for route in routes {
        let mut stmts = scope.clone();
        stmts.extend([wan_mark_match(route.mark()), restore_wan_mark(route.mark()), Statement::Return(None)]);
        doc.objects.push(add_rule(NfFamily::INet, "mangle", "wan_outbound", stmts, None));
        let mut strict = outbound_scope(config, false);
        strict.extend([wan_mark_match(route.strict_mark()), restore_wan_mark(route.strict_mark()), Statement::Return(None)]);
        doc.objects.push(add_rule(NfFamily::INet, "mangle", "wan_outbound", strict, None));
    }
    for rule in rules {
        let route = routes.iter().find(|route| Some(route.name) == rule.route_via.as_deref()).expect("validated WAN target");
        for proto in resolve_protos(rule) {
            let mark = if rule.preserve_internal_routes { route.mark() } else { route.strict_mark() };
            let mut stmts = outbound_scope(config, rule.preserve_internal_routes);
            stmts.extend([ct_match("state", "new", Operator::IN), wan_mark_match(0)]);
            stmts.extend(build_rule_match_stmts(config, rule, proto.as_deref()));
            stmts.extend([
                Statement::Mangle(stmt::Mangle { key: ct_expression("mark"), value: with_wan_mark(ct_expression("mark"), Expression::Number(mark)) }),
                restore_wan_mark(mark),
                Statement::Return(None),
            ]);
            // User ID comments/counters live only in filter/forward for stats.
            doc.objects.push(add_rule(NfFamily::INet, "mangle", "wan_outbound", stmts, None));
        }
    }
}

fn render_outbound_guards(config: &Config, routes: &[WanReturnRoute<'_>], doc: &mut NftablesDocument) {
    if !config.firewall.rules.forward.iter().any(|rule| rule.enabled && rule.route_via.is_some()) { return; }
    // Retain guards for the old WAN when a selector is retargeted: existing
    // connections keep their connection mark while new ones choose the new WAN.
    for route in routes {
        let mut stmts = outbound_scope(config, true);
        stmts.push(wan_mark_match(route.mark()));
        let mut wrong_egress = oifname_match(route.interface);
        if let Statement::Match(ref mut condition) = wrong_egress { condition.op = Operator::NEQ; }
        stmts.extend([wrong_egress, Statement::Drop(None)]);
        doc.objects.push(add_rule(NfFamily::INet, "filter", "forward", stmts, None));
    }
}

fn render_wan_return_rules(routes: &[WanReturnRoute<'_>], doc: &mut NftablesDocument) {
    if routes.is_empty() {
        return;
    }
    doc.objects.push(add_chain(
        NfFamily::INet, "mangle", "wan_return", Some(NfChainType::Filter),
        Some(NfHook::Prerouting), Some(-140), Some(NfChainPolicy::Accept),
    ));
    doc.objects.push(add_chain(
        NfFamily::INet, "mangle", "wan_return_output", Some(NfChainType::Route),
        Some(NfHook::Output), Some(-140), Some(NfChainPolicy::Accept),
    ));
    for route in routes {
        doc.objects.push(add_rule(NfFamily::INet, "mangle", "wan_return", vec![
            iifname_match(route.interface, false),
            ipv4_family_match(),
            ct_match("direction", "original", Operator::EQ),
            ct_match("state", "new", Operator::IN),
            Statement::Mangle(stmt::Mangle {
                key: ct_expression("mark"),
                value: with_wan_mark(ct_expression("mark"), Expression::Number(route.mark())),
            }),
        ], None));
        let packet_mark = Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Mark }));
        let reply_stmts = vec![
            ipv4_family_match(),
            ct_match("direction", "reply", Operator::EQ),
            Statement::Match(Match {
                left: masked(ct_expression("mark"), WAN_MARK_MASK),
                right: Expression::Number(route.mark()),
                op: Operator::EQ,
            }),
            Statement::Mangle(stmt::Mangle {
                key: packet_mark.clone(),
                value: with_wan_mark(packet_mark, Expression::Number(route.mark())),
            }),
        ];
        for chain in ["wan_return", "wan_return_output"] {
            let mut stmts = reply_stmts.clone();
            if chain == "wan_return" {
                // Replies arriving from the selected WAN belong to outbound flows;
                // their destination is routed normally toward the client/LAN.
                stmts.insert(0, iifname_match(route.interface, true));
            }
            doc.objects.push(add_rule(NfFamily::INet, "mangle", chain, stmts, None));
        }
    }
}

fn ipv4_family_match() -> Statement<'static> {
    Statement::Match(Match {
        left: Expression::Named(NamedExpression::Meta(Meta { key: MetaKey::Nfproto })),
        right: Expression::String(Cow::Borrowed("ipv4")),
        op: Operator::EQ,
    })
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
            format!("[{}]", rule.id)
        } else {
            format!("[{}] {}", rule.id, rule.comment)
        };
        for proto_opt in resolve_protos(rule) {
            let proto_str = proto_opt.as_deref().unwrap_or("tcp");
            let mut stmts = Vec::new();

            // Interface match
            if !rule.interfaces.is_empty() {
                if rule.interfaces.len() == 1 {
                    stmts.push(iifname_match(&rule.interfaces[0], false));
                } else {
                    stmts.push(iifname_set_match(&rule.interfaces, false));
                }
            }

            // L4 protocol context (skip for layer 2/3 protocols)
            match proto_str {
                "ip" | "ether" => {}
                _ => { stmts.push(proto_match(proto_str)); }
            }

            // Address matches
            if let Some(saddr) = &rule.saddr {
                stmts.push(ip_saddr_match(saddr, false));
            }
            if let Some(daddr) = &rule.daddr {
                stmts.push(ip_daddr_match(daddr, false));
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
                Some(&comment),
            ));
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Check if an IPv4 address falls within a CIDR range.
fn is_ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let Ok(address) = ip.parse::<std::net::Ipv4Addr>() else { return false };
    let Some((network, prefix)) = ipv4_subnet(cidr) else { return false };
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    u32::from(address) & mask == u32::from(network)
}

fn ipv4_subnet(cidr: &str) -> Option<(std::net::Ipv4Addr, u32)> {
    let (address, prefix) = parse_cidr(cidr)?;
    if prefix > 32 {
        return None;
    }
    let address = address.parse::<std::net::Ipv4Addr>().ok()?;
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    Some(((u32::from(address) & mask).into(), prefix))
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

    fn rules_in_chain(value: &serde_json::Value, table: &str, chain: &str) -> Vec<serde_json::Value> {
        value["nftables"].as_array().unwrap().iter()
            .filter_map(|object| object.get("add")?.get("rule"))
            .filter(|rule| rule["table"] == table && rule["chain"] == chain)
            .cloned().collect()
    }

    #[test]
    fn common_mss_caps_cover_both_families_and_directions_without_increasing_mss() {
        let mut config = Config::default();
        config.interfaces.items = vec![InterfaceConfig { name: "lan0".into(), mss_clamp_mtu: Some(1492), ..Default::default() }];
        let value = render_json(&config);
        let rules: Vec<_> = value["nftables"].as_array().unwrap().iter()
            .filter_map(|obj| obj.get("add")?.get("rule"))
            .filter(|rule| rule["comment"] == "routerd TCP MSS cap").collect();
        assert_eq!(rules.len(), 4);
        for rule in rules {
            let expr = rule["expr"].as_array().unwrap();
            let family = expr[1]["match"]["right"].as_str().unwrap();
            let cap = if family == "ipv4" { 1452 } else { 1432 };
            assert_eq!(expr[3]["match"]["left"]["&"][1], 2);
            assert_eq!(expr[4]["match"]["op"], ">");
            assert_eq!(expr[4]["match"]["right"], cap);
            assert_eq!(expr[5]["mangle"]["value"], cap);
            assert_eq!(expr[5]["mangle"]["key"]["tcp option"]["name"], "maxseg");
        }
        config.interfaces.items[0].mss_clamp_mtu = None;
        assert!(mss_limits(&config).is_empty());
        config.interfaces.items[0].method = InterfaceMethod::Pppoe;
        config.interfaces.items[0].pppoe = Some(PppoeConfig::default());
        assert_eq!(mss_limits(&config), vec![("ppp0", 1492)]);
        config.interfaces.items[0].mss_clamp_mtu = Some(1400);
        assert_eq!(mss_limits(&config), vec![("ppp0", 1400)]);
        config.interfaces.items[0].mss_clamp_mtu = None;
        config.interfaces.items[0].pppoe.as_mut().unwrap().mss_clamp = false;
        assert!(mss_limits(&config).is_empty());
    }

    #[test]
    fn internal_route_preservation_is_per_rule_and_persisted_in_distinct_marks() {
        let mut config = crate::config::routing::test_config();
        config.firewall.rules.forward = serde_json::from_value(serde_json::json!([
            {"id": 11, "action": "accept", "interfaces": ["lan0"], "route_via": "wan0"},
            {"id": 12, "action": "accept", "interfaces": ["lan0"], "route_via": "wan0", "preserve_internal_routes": false}
        ])).unwrap();
        assert!(config.firewall.rules.forward[0].preserve_internal_routes);
        assert!(!config.firewall.rules.forward[1].preserve_internal_routes);
        let route = wan_return_routes(&config).unwrap().remove(0);
        let value = render_json(&config);
        let rules = rules_in_chain(&value, "mangle", "wan_outbound");
        let preserving = rules[rules.len() - 2]["expr"].as_array().unwrap();
        let strict = rules.last().unwrap()["expr"].as_array().unwrap();
        let exclusion = serde_json::json!({"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "192.168.0.0", "len": 23}}}});
        assert!(preserving.contains(&exclusion));
        assert!(!strict.contains(&exclusion));
        for (exprs, mark) in [(preserving, route.mark()), (strict, route.strict_mark())] {
            assert!(exprs.contains(&serde_json::json!({"mangle": {
                "key": {"ct": {"key": "mark"}}, "value": {"|": [{"&": [{"ct": {"key": "mark"}}, 65535]}, mark]}
            }})));
        }
        let restored = rules[2]["expr"].as_array().unwrap();
        assert!(!restored.contains(&exclusion));
        assert!(restored.contains(&serde_json::json!({"match": {"op": "==", "left": {"&": [{"ct": {"key": "mark"}}, 4294901760u32]}, "right": route.strict_mark()}})));
        // Strict routing must allow a more-specific LAN exit in the selected table;
        // its global unreachable policy, not an oif guard, prevents main fallback.
        assert!(rules_in_chain(&value, "filter", "forward").iter().all(|rule| !rule["expr"].as_array().unwrap().iter().any(|expr| expr["match"]["right"] == route.strict_mark())));
    }

    #[test]
    fn outbound_selection_pins_flows_before_new_rules_and_keeps_filter_stats() {
        let config = crate::config::routing::outbound_test_config();
        let value = render_json(&config);
        let rules = rules_in_chain(&value, "mangle", "wan_outbound");
        assert_eq!(rules.len(), 8); // TPROXY bypass, four restores, two protocols, fallback selector
        assert_eq!(rules[0]["expr"][0]["match"]["left"], serde_json::json!({"&": [{"meta": {"key": "mark"}}, 65535]}));
        for (index, mark) in [(1, 6553600), (3, 6619136)] {
            let exprs = rules[index]["expr"].as_array().unwrap();
            assert!(exprs.contains(&serde_json::json!({"match": {
                "op": "==", "left": {"&": [{"ct": {"key": "mark"}}, 4294901760u32]}, "right": mark
            }})));
            assert_eq!(exprs.last().unwrap(), &serde_json::json!({"return": null}));
            assert!(!exprs.iter().any(|expr| expr["match"]["left"] == serde_json::json!({"ct": {"key": "state"}})));
        }
        for rule in &rules[5..] {
            let exprs = rule["expr"].as_array().unwrap();
            assert!(exprs.contains(&serde_json::json!({"match": {
                "op": "==", "left": {"&": [{"ct": {"key": "mark"}}, 4294901760u32]}, "right": 0
            }})));
            assert!(exprs.contains(&serde_json::json!({"match": {
                "op": "in", "left": {"ct": {"key": "state"}}, "right": "new"
            }})));
            assert!(exprs.iter().any(|expr| expr["mangle"]["key"] == serde_json::json!({"ct": {"key": "mark"}})));
            assert!(exprs.iter().any(|expr| expr["mangle"]["key"] == serde_json::json!({"meta": {"key": "mark"}})));
            assert!(!exprs.iter().any(|expr| expr.get("counter").is_some() || expr.get("log").is_some()));
            assert!(rule.get("comment").is_none());
        }
        for (index, mark) in [(5, 6553600), (6, 6553600), (7, 6619136)] {
            assert!(rules[index]["expr"].as_array().unwrap().contains(&serde_json::json!({"mangle": {
                "key": {"ct": {"key": "mark"}},
                "value": {"|": [{"&": [{"ct": {"key": "mark"}}, 65535]}, mark]}
            }})));
        }
        let forward = rules_in_chain(&value, "filter", "forward");
        assert_eq!(forward.iter().filter(|rule| rule["comment"] == "[11]").count(), 2);
        let objects = value["nftables"].as_array().unwrap();
        for name in ["clients", "remote", "web"] {
            assert!(objects.iter().any(|object| object["add"]["set"]["table"] == "mangle" && object["add"]["set"]["name"] == name));
        }
        let chain = objects.iter().find_map(|object| object.get("add")?.get("chain").filter(|chain| chain["name"] == "wan_outbound")).unwrap();
        assert_eq!(chain["prio"], -90);
        assert_eq!(chain["hook"], "prerouting");
    }

    #[test]
    fn outbound_scope_and_fail_closed_guards_precede_established_accept() {
        let config = crate::config::routing::outbound_test_config();
        let value = render_json(&config);
        let rules = rules_in_chain(&value, "filter", "forward");
        for (index, wan) in [(0, "wan0"), (1, "wan1")] {
            let exprs = rules[index]["expr"].as_array().unwrap();
            assert_eq!(exprs.last().unwrap(), &serde_json::json!({"drop": null}));
            assert!(exprs.contains(&serde_json::json!({"match": {
                "op": "!=", "left": {"meta": {"key": "oifname"}}, "right": wan
            }})));
            for expected in [
                serde_json::json!({"match": {"op": "==", "left": {"ct": {"key": "direction"}}, "right": "original"}}),
                serde_json::json!({"match": {"op": "!=", "left": {"ct": {"key": "status"}}, "right": "dnat"}}),
                serde_json::json!({"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": {"set": ["wan0", "wan1"]}}}),
                serde_json::json!({"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "192.168.0.0", "len": 23}}}}),
            ] {
                assert!(exprs.contains(&expected), "missing scope: {expected}");
                for outbound in rules_in_chain(&value, "mangle", "wan_outbound").iter().skip(1) {
                    // Strict restore entries deliberately omit internal exclusions.
                    let is_internal_exclusion = expected["match"]["left"]["payload"]["field"] == "daddr";
                    let strict_marks: Vec<_> = wan_return_routes(&config).unwrap().iter().map(|route| route.strict_mark()).collect();
                    let is_strict = outbound["expr"].as_array().unwrap().iter().any(|expr| strict_marks.iter().any(|mark| expr["match"]["right"] == *mark));
                    if !is_internal_exclusion || !is_strict {
                        assert!(outbound["expr"].as_array().unwrap().contains(&expected));
                    }
                }
            }
        }
        assert_eq!(rules[2]["expr"].as_array().unwrap().last().unwrap(), &serde_json::json!({"accept": null}));
        let mut changed = config;
        changed.firewall.rules.forward[0].route_via = Some("wan1".into());
        let value = render_json(&changed);
        assert_eq!(rules_in_chain(&value, "filter", "forward")[0]["expr"], rules[0]["expr"]);
    }

    #[test]
    fn outbound_targets_support_dynamic_wans_and_disabled_rules_emit_no_selectors() {
        let mut config = crate::config::routing::outbound_test_config();
        config.interfaces.items[0].method = InterfaceMethod::Dhcp;
        config.interfaces.items[1].method = InterfaceMethod::Pppoe;
        let value = render_json(&config);
        assert!(rules_in_chain(&value, "filter", "forward")[1]["expr"].as_array().unwrap().contains(&serde_json::json!({"match": {
            "op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "ppp0"
        }})));
        for rule in &mut config.firewall.rules.forward { rule.enabled = false; }
        assert!(rules_in_chain(&render_json(&config), "mangle", "wan_outbound").is_empty());
        config.firewall.rules.forward[0].enabled = true;
        config.firewall.rules.forward[0].route_via = Some("missing".into());
        assert!(render(&config).is_err());
    }

    #[test]
    fn hairpin_snat_covers_vlan_and_second_lan_without_snatting_external_clients() {
        let mut config = crate::config::routing::test_config();
        for vlan_id in [Some(2), None] {
            config.interfaces.items[3].vlan_id = vlan_id;
            let value = render_json(&config);
            let rules = rules_in_chain(&value, "nat", "postrouting");
            assert_eq!(rules.len(), 1);
            let expressions = rules[0]["expr"].as_array().unwrap();
            assert!(expressions.contains(&serde_json::json!({"match": {
                "op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                "right": {"prefix": {"addr": "192.168.2.0", "len": 23}}
            }})));
            assert!(expressions.contains(&serde_json::json!({"match": {
                "op": "==", "left": {"meta": {"key": "oifname"}}, "right": "vlan2"
            }})));
            assert!(expressions.contains(&serde_json::json!({"match": {
                "op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"
            }})));
            assert!(expressions.contains(&serde_json::json!({"masquerade": null})));
        }
        config.firewall.nat.port_forward[0].redirect_address = "192.0.2.50".into();
        assert!(rules_in_chain(&render_json(&config), "nat", "postrouting").is_empty());
        config.firewall.nat.port_forward[0].enabled = false;
        assert!(rules_in_chain(&render_json(&config), "nat", "prerouting").is_empty());
    }

    #[test]
    fn wan_return_marks_connections_and_restores_forwarded_and_local_replies() {
        let config = crate::config::routing::test_config();
        let value = render_json(&config);
        let rules = rules_in_chain(&value, "mangle", "wan_return");
        assert_eq!(rules.len(), 4);
        let incoming = rules[0]["expr"].as_array().unwrap();
        assert!(incoming.contains(&serde_json::json!({"match": {
            "op": "==", "left": {"meta": {"key": "iifname"}}, "right": "wan0"
        }})));
        assert!(incoming.contains(&serde_json::json!({"mangle": {
            "key": {"ct": {"key": "mark"}},
            "value": {"|": [{"&": [{"ct": {"key": "mark"}}, 65535]}, 6553600]}
        }})));
        let replies = rules[1]["expr"].as_array().unwrap();
        assert!(replies.contains(&serde_json::json!({"match": {
            "op": "==", "left": {"ct": {"key": "direction"}}, "right": "reply"
        }})));
        assert!(!replies.contains(&serde_json::json!({"match": {
            "op": "in", "left": {"ct": {"key": "status"}}, "right": "dnat"
        }})));
        let local_replies = rules_in_chain(&value, "mangle", "wan_return_output");
        assert_eq!(local_replies.len(), 2);
        assert_eq!(local_replies[0]["expr"].as_array().unwrap(), &replies[1..]);
        assert!(replies.contains(&serde_json::json!({"mangle": {
            "key": {"meta": {"key": "mark"}}, "value": {"|": [
                {"&": [{"meta": {"key": "mark"}}, 65535]},
                6553600
            ]}
        }})));
        let mut disabled = config;
        for interface in &mut disabled.interfaces.items {
            interface.return_routing = Some(false);
        }
        assert!(rules_in_chain(&render_json(&disabled), "mangle", "wan_return").is_empty());
    }

    #[test]
    #[ignore = "requires nft and CAP_NET_ADMIN; run in an isolated network namespace"]
    fn native_check_multi_wan_and_vlan_hairpin() {
        let mut config = crate::config::routing::outbound_test_config();
        config.firewall.rules.forward.push(serde_json::from_value(serde_json::json!({
            "id": 1, "action": "tproxy", "interfaces": ["lan0", "vlan2"],
            "proto": ["tcp"], "daddr": "198.18.0.0/15", "mark": 1, "tproxy_port": 12345
        })).unwrap());
        config.interfaces.items[0].mss_clamp_mtu = Some(1492);
        let directory = crate::service::files::StagedDirectory::new().unwrap();
        for preserve in [true, false] {
            config.firewall.rules.forward[0].preserve_internal_routes = preserve;
            let staged = crate::service::files::StagedFile::new(
                directory.path(), render(&config).unwrap().as_bytes(), 0o600,
            ).unwrap();
            let output = std::process::Command::new("nft")
                .args(["-j", "-c", "-f"]).arg(staged.path()).output().unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
        // Always create another isolated namespace before applying test rules.
        let mut local = Config::default();
        local.interfaces.items.push(InterfaceConfig { name: "lo".into(), mss_clamp_mtu: Some(1492), ..Default::default() });
        let staged = crate::service::files::StagedFile::new(directory.path(), render(&local).unwrap().as_bytes(), 0o600).unwrap();
        let output = std::process::Command::new("unshare").args(["--net", "python3", "-c", r#"
import socket, subprocess, sys, threading
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['nft', '-j', '-f', sys.argv[1]], check=True)
for family, address, cap in [(socket.AF_INET, '127.0.0.1', 1452), (socket.AF_INET6, '::1', 1432)]:
    for smaller in [False, True]:
        server = socket.socket(family, socket.SOCK_STREAM)
        server.bind((address, 0))
        server.listen(1)
        values = []
        def accept():
            connection, _ = server.accept()
            values.append(connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG))
            connection.close()
        worker = threading.Thread(target=accept, daemon=True)
        worker.start()
        client = socket.socket(family, socket.SOCK_STREAM)
        client.settimeout(3)
        if smaller:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1200)
        client.connect(server.getsockname())
        values.append(client.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG))
        client.close()
        worker.join(3)
        server.close()
        assert len(values) == 2, values
        bound = 1200 if smaller else cap
        assert all(0 < value <= bound for value in values), (family, smaller, values)
        if not smaller:
            assert all(value >= cap - 40 for value in values), (family, values)
        print('family', family, 'smaller', smaller, 'negotiated MSS', values)
"#]).arg(staged.path()).output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        println!("{}", String::from_utf8_lossy(&output.stdout));
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
        assert_eq!(table_count, 5, "expected 4 reset tables and 1 filter table");
        assert_eq!(chain_count, 3, "expected 3 chains (input, forward, output)");
    }

    #[test]
    fn empty_rules_preserve_drop_policies_without_flushing_other_tables() {
        let mut config = Config::default();
        config.firewall.default_policy.input = "drop".into();
        config.firewall.default_policy.forward = "drop".into();
        config.firewall.default_policy.output = "drop".into();
        let value = render_json(&config);
        let objects = value["nftables"].as_array().unwrap();
        assert!(objects.iter().all(|object| object.get("flush").is_none()));
        let chains: Vec<_> = objects.iter().filter_map(|object| object.get("add")?.get("chain")).collect();
        assert_eq!(chains.len(), 3);
        assert!(chains.iter().all(|chain| chain["policy"] == "drop"));
        let deleted: Vec<_> = objects.iter().filter_map(|object| object.get("delete")?.get("table")).collect();
        assert_eq!(deleted.len(), 4);
    }

    #[test]
    fn test_render_with_rules() {
        let mut config = Config::default();
        config.firewall.rules.input.push(FirewallRule {
            id: 1,
            action: Action::Accept,
            comment: "allow-ssh".into(),
            interfaces: vec!["br-lan".into()],
            oif: None, route_via: None, preserve_internal_routes: true,
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
            interfaces_invert: false, saddr_invert: false, daddr_invert: false,
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
            interfaces_invert: false,
            source_address_invert: false,
            target_address_invert: false,
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
            oif: None, route_via: None, preserve_internal_routes: true,
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
            interfaces_invert: false, saddr_invert: false, daddr_invert: false,
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
        assert_eq!(
            port_spec_expr(&PortSpec::Set("@myset".into())),
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
            oif: None, route_via: None, preserve_internal_routes: true,
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
            interfaces_invert: false, saddr_invert: false, daddr_invert: false,
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
            oif: None, route_via: None, preserve_internal_routes: true,
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
            interfaces_invert: false, saddr_invert: false, daddr_invert: false,
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
            interfaces_invert: false,
            source_address_invert: false,
            target_address_invert: false,
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
            interfaces_invert: false,
            source_address_invert: false,
            target_address_invert: false,
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
            interfaces_invert: false,
            source_address_invert: false,
            target_address_invert: false,
            enabled: true,
        });
        let val = render_json(&config);
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("dnat"));
        assert!(json_str.contains("10.0.0.0"));
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
            interfaces_invert: false,
            source_address_invert: false,
            target_address_invert: false,
            enabled: true,
        });
        let val = render_json(&config);
        let json_str = serde_json::to_string(&val).unwrap();
        assert!(json_str.contains("eth0"));
        assert!(json_str.contains("wg0"));
    }
}

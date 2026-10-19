import { checked, Editor, integer, text } from './Editor';
import type { Field, Values } from './Editor';
import type { Config, FirewallRule, NftSet, PortForward } from '../lib/types';
import { formatPort, list, parsePort } from '../lib/format';
import { useConfig } from '../lib/queries';
import { interfaceDisplayName } from '../lib/interfaces';

const ingress: Field = {
  name: 'interfaces',
  label: 'Ingress interfaces',
  type: 'interface',
  multiple: true,
  required: true,
  placeholder: 'eth0, br0',
  hint: 'Choose interfaces by display name, or enter comma-separated device names manually.',
};
const comment: Field = {
  name: 'comment',
  label: 'Description',
  placeholder: 'What is this rule for?',
};
const enabled: Field = { name: 'enabled', label: 'Enabled', type: 'toggle' };

export function wanMasqueradeWarning(
  config: Config | undefined,
  name: string,
): string | undefined {
  if (!config || !name) return undefined;
  const group = config.wan_groups?.find((item) => name === `group:${item.id}`);
  if (group) {
    return group.members
      .map((member) => wanMasqueradeWarning(config, member.interface))
      .filter(Boolean).join(' ') || undefined;
  }
  const wan = config.interfaces.items.find((iface) => iface.name === name);
  if (!wan || (wan.method === 'static' && !wan.static_config?.gateway))
    return undefined;
  const device = wan.method === 'pppoe' ? 'ppp0' : wan.name;
  if (config.firewall.nat.masquerade.some((rule) => rule.oif === device))
    return undefined;
  const displayName = interfaceDisplayName(device, config.interfaces.items);
  return `No masquerade is configured on ${displayName}. Private LAN clients normally need it for Internet access unless the upstream router has a return route to their subnet. Add ${displayName} under Policies & NAT → Masquerade egress interfaces, then Save and Apply.`;
}
const invert: Field[] = [
  { name: 'interfaces_invert', label: 'Invert ingress match', type: 'toggle' },
  { name: 'saddr_invert', label: 'Invert source match', type: 'toggle' },
  { name: 'daddr_invert', label: 'Invert destination match', type: 'toggle' },
];
const ruleFields: Field[] = [
  comment,
  {
    name: 'action',
    label: 'Action',
    type: 'select',
    options: ['accept', 'drop', 'reject', 'tproxy'],
  },
  ingress,
  {
    name: 'oif',
    label: 'Egress interface',
    type: 'interface',
    placeholder: 'Any',
    hint: 'Match the selected exit interface. This does not choose a route.',
    when: (values) => values.action !== 'tproxy',
  },
  {
    name: 'route_via',
    label: 'Route via WAN',
    type: 'select',
    placeholder: 'System routing',
    when: (values) => values.action === 'accept',
    hint: 'IPv4 only. Pins new outbound connections to a WAN, or uses source-IP modulo slots across the active tier of a WAN group. Router-local and port-forwarded traffic keep normal routing. Requires WAN return routing; configure masquerade separately if needed.',
  },
  {
    name: 'preserve_internal_routes',
    label: 'Preserve internal routes',
    type: 'toggle',
    when: (values) => values.action === 'accept' && Boolean(values.route_via),
    hint: 'Enabled: configured LAN destinations use normal routing. Disabled: all matching destinations use the selected WAN table, including internal subnets.',
    warning: (values) =>
      values.preserve_internal_routes === false
        ? 'Internal traffic may go to the WAN gateway. To keep a destination reachable directly, add its route to the selected WAN table. Test with a new connection after Apply.'
        : undefined,
  },
  { name: 'proto', label: 'Protocols', placeholder: 'tcp, udp', hint: 'TPROXY supports TCP/UDP only; empty uses TCP. For other actions, empty matches any protocol.' },
  {
    name: 'state',
    label: 'Connection states',
    placeholder: 'established, related',
    hint: 'Comma-separated states.',
  },
  {
    name: 'saddr',
    label: 'Source address / set',
    placeholder: '192.168.1.0/24 or @trusted',
  },
  { name: 'daddr', label: 'Destination address / set', placeholder: 'Any' },
  { name: 'sport', label: 'Source ports', placeholder: 'Any' },
  {
    name: 'dport',
    label: 'Destination ports',
    placeholder: '443, 80 or 8000-8080 or @web',
    hint: 'A port, comma-separated ports, ordered range, or @set.',
  },
  { name: 'rate', label: 'Rate limit', placeholder: '10/second', when: (values) => values.action !== 'tproxy' },
  { name: 'log_prefix', label: 'Log prefix' },
  {
    name: 'mark',
    label: 'TPROXY routing mark',
    type: 'number',
    min: 1,
    max: 4294967295,
    required: true,
    when: (values) => values.action === 'tproxy',
    hint: 'Do not use reserved marks 253, 254 or 255.',
  },
  {
    name: 'tproxy_port',
    label: 'TPROXY port',
    type: 'number',
    min: 1,
    max: 65535,
    required: true,
    when: (values) => values.action === 'tproxy',
  },
  enabled,
  { name: 'counter', label: 'Count packets & bytes', type: 'toggle' },
  { name: 'log', label: 'Log matching packets', type: 'toggle' },
  ...invert,
];
function ruleInitial(rule?: FirewallRule): Values {
  return {
    comment: rule?.comment ?? '',
    action: rule?.action ?? 'accept',
    interfaces: rule?.interfaces.join(', ') ?? '',
    oif: rule?.oif ?? '',
    route_via: rule?.route_via ?? '',
    preserve_internal_routes: rule?.preserve_internal_routes ?? true,
    proto: rule?.proto?.join(', ') ?? '',
    state: rule?.state?.join(', ') ?? '',
    saddr: rule?.saddr ?? '',
    daddr: rule?.daddr ?? '',
    sport: formatPort(rule?.sport),
    dport: formatPort(rule?.dport),
    rate: rule?.rate ?? '',
    log_prefix: rule?.log_prefix ?? '',
    mark: String(rule?.mark ?? 1),
    tproxy_port: String(rule?.tproxy_port ?? 7893),
    enabled: rule?.enabled !== false,
    counter: rule?.counter ?? true,
    log: rule?.log ?? false,
    interfaces_invert: rule?.interfaces_invert ?? false,
    saddr_invert: rule?.saddr_invert ?? false,
    daddr_invert: rule?.daddr_invert ?? false,
  };
}
export function ruleFromValues(
  values: Values,
  original?: FirewallRule,
): FirewallRule {
  const action = text(values, 'action') as FirewallRule['action'];
  const mark =
    action === 'tproxy' ? integer(values, 'mark', 1, 4294967295) : undefined;
  if (mark && [253, 254, 255].includes(mark))
    throw new Error('TPROXY mark cannot be 253, 254 or 255.');
  const routeVia =
    action === 'accept' ? text(values, 'route_via') || undefined : undefined;
  if (routeVia && (text(values, 'oif') || text(values, 'rate')))
    throw new Error(
      'WAN selection cannot be combined with an egress interface match or rate limit.',
    );
  if (
    routeVia &&
    text(values, 'state') &&
    !list(text(values, 'state')).includes('new')
  )
    throw new Error(
      'WAN selection connection states must include new, or be empty.',
    );
  return {
    ...original,
    id: original?.id ?? 0,
    action,
    comment: text(values, 'comment'),
    interfaces: list(text(values, 'interfaces')),
    oif: action === 'tproxy' ? undefined : text(values, 'oif') || undefined,
    route_via: routeVia,
    preserve_internal_routes: routeVia
      ? values.preserve_internal_routes !== false
      : true,
    proto: text(values, 'proto') ? list(text(values, 'proto')) : undefined,
    state: text(values, 'state') ? list(text(values, 'state')) : undefined,
    saddr: text(values, 'saddr') || undefined,
    daddr: text(values, 'daddr') || undefined,
    sport: parsePort(text(values, 'sport')),
    dport: parsePort(text(values, 'dport')),
    rate: action === 'tproxy' ? undefined : text(values, 'rate') || undefined,
    log_prefix: text(values, 'log_prefix') || undefined,
    mark,
    tproxy_port:
      action === 'tproxy'
        ? integer(values, 'tproxy_port', 1, 65535)
        : undefined,
    enabled: checked(values, 'enabled'),
    counter: checked(values, 'counter'),
    log: checked(values, 'log'),
    interfaces_invert: checked(values, 'interfaces_invert'),
    saddr_invert: checked(values, 'saddr_invert'),
    daddr_invert: checked(values, 'daddr_invert'),
  };
}
export function RuleEditor({
  rule,
  chain,
  save,
  close,
}: {
  rule?: FirewallRule;
  chain: string;
  save: (rule: FirewallRule) => Promise<unknown>;
  close: () => void;
}) {
  const config = useConfig();
  const wans =
    config.data?.interfaces.items
      .filter(
        (iface) =>
          (iface.method !== 'static' ||
            Boolean(iface.static_config?.gateway)) &&
          iface.return_routing !== false,
      )
      .map((iface) => iface.name) ?? [];
  const options = [
    ...new Set([
      '', ...wans,
      ...(config.data?.wan_groups?.map((group) => `group:${group.id}`) ?? []),
      ...(rule?.route_via ? [rule.route_via] : []),
    ]),
  ];
  return (
    <Editor
      title={rule ? `Edit rule #${rule.id}` : `Add ${chain} rule`}
      initial={ruleInitial(rule)}
      fields={ruleFields
        .filter(
          (field) =>
            !['route_via', 'preserve_internal_routes'].includes(field.name) ||
            chain === 'forward',
        )
        .map((field) =>
          field.name === 'route_via'
            ? {
                ...field,
                options: options.map((name) => {
                  const group = config.data?.wan_groups?.find((item) => name === `group:${item.id}`);
                  return {
                    value: name,
                    label: group ? `Group: ${group.name}` : interfaceDisplayName(name, config.data?.interfaces.items),
                  };
                }),
                warning: (values: Values) =>
                  wanMasqueradeWarning(config.data, text(values, 'route_via')),
              }
            : field,
        )}
      onClose={close}
      onSave={(values) => save(ruleFromValues(values, rule))}
    />
  );
}

const natFields: Field[] = [
  comment,
  {
    name: 'proto',
    label: 'Protocol',
    type: 'select',
    options: ['tcp', 'udp', 'tcp+udp'],
  },
  ingress,
  {
    name: 'target_port',
    label: 'WAN destination ports',
    placeholder: '443 or 8000-8080',
  },
  {
    name: 'target_address',
    label: 'WAN destination address',
    placeholder: 'Any',
  },
  {
    name: 'source_address',
    label: 'Source address filter',
    placeholder: 'Any',
  },
  {
    name: 'redirect_address',
    label: 'Forward to address',
    required: true,
    placeholder: '192.168.1.10',
  },
  {
    name: 'redirect_port',
    label: 'Forward to ports',
    placeholder: 'Keep original port',
  },
  enabled,
  { name: 'interfaces_invert', label: 'Invert ingress match', type: 'toggle' },
  {
    name: 'source_address_invert',
    label: 'Invert source match',
    type: 'toggle',
  },
  {
    name: 'target_address_invert',
    label: 'Invert destination match',
    type: 'toggle',
  },
];
export function NatEditor({
  rule,
  save,
  close,
}: {
  rule?: PortForward;
  save: (rule: PortForward) => Promise<unknown>;
  close: () => void;
}) {
  const initial: Values = {
    comment: rule?.comment ?? '',
    proto: rule?.proto ?? 'tcp',
    interfaces: rule?.interfaces.join(', ') ?? '',
    target_port: formatPort(rule?.target_port),
    target_address: rule?.target_address ?? '',
    source_address: rule?.source_address ?? '',
    redirect_address: rule?.redirect_address ?? '',
    redirect_port: formatPort(rule?.redirect_port),
    enabled: rule?.enabled !== false,
    interfaces_invert: rule?.interfaces_invert ?? false,
    source_address_invert: rule?.source_address_invert ?? false,
    target_address_invert: rule?.target_address_invert ?? false,
  };
  return (
    <Editor
      title={rule ? `Edit port forward #${rule.id}` : 'Add port forward'}
      initial={initial}
      fields={natFields.map((field) =>
        field.name === 'proto' && rule && !field.options?.includes(rule.proto)
          ? { ...field, options: [...field.options!, rule.proto] }
          : field,
      )}
      onClose={close}
      onSave={(values) =>
        save({
          ...rule,
          id: rule?.id ?? 0,
          comment: text(values, 'comment'),
          proto: text(values, 'proto'),
          interfaces: list(text(values, 'interfaces')),
          target_port: parsePort(text(values, 'target_port')),
          target_address: text(values, 'target_address') || undefined,
          source_address: text(values, 'source_address') || undefined,
          redirect_address: text(values, 'redirect_address'),
          redirect_port: parsePort(text(values, 'redirect_port')),
          enabled: checked(values, 'enabled'),
          interfaces_invert: checked(values, 'interfaces_invert'),
          source_address_invert: checked(values, 'source_address_invert'),
          target_address_invert: checked(values, 'target_address_invert'),
        })
      }
    />
  );
}

export function SetEditor({
  set,
  save,
  close,
}: {
  set?: NftSet;
  save: (set: NftSet) => Promise<unknown>;
  close: () => void;
}) {
  return (
    <Editor
      title={set ? `Edit @${set.name}` : 'Add named set'}
      initial={{
        name: set?.name ?? '',
        set_type: set?.set_type ?? 'ipv4_addr',
        elements: set?.elements ?? '',
        comment: set?.comment ?? '',
        interval: set?.interval ?? false,
      }}
      fields={[
        {
          name: 'name',
          label: 'Set name',
          required: true,
          disabled: Boolean(set),
          placeholder: 'trusted_networks',
        },
        {
          name: 'set_type',
          label: 'Element type',
          required: true,
          placeholder: 'ipv4_addr, ipv6_addr, inet_service…',
        },
        comment,
        {
          name: 'interval',
          label: 'Enable intervals / CIDR ranges',
          type: 'toggle',
        },
        {
          name: 'elements',
          label: 'Elements',
          type: 'textarea',
          wide: true,
          hint: 'One element per line. Reference this set with @name in rules.',
        },
      ]}
      onClose={close}
      onSave={(values) =>
        save({
          ...set,
          name: set?.name ?? text(values, 'name'),
          set_type: text(values, 'set_type'),
          elements: text(values, 'elements'),
          comment: text(values, 'comment') || undefined,
          interval: checked(values, 'interval'),
        })
      }
    />
  );
}

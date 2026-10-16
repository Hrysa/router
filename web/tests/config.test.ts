import { expect, test } from 'bun:test';
import { normalizeConfig } from '../src/lib/api';
import { replacePool } from '../src/pages/Dhcp';
import {
  ruleFromValues,
  wanMasqueradeWarning,
} from '../src/components/FirewallEditors';
import { interfaceFromValues } from '../src/pages/Interfaces';
import type { Config, Pool } from '../src/lib/types';

const pool: Pool = {
  name: 'home',
  subnet: '192.168.1.0/24',
  range: { start: '192.168.1.100', end: '192.168.1.200' },
  lease_time: '12h',
  domain: 'lan.local',
  dns_servers: ['1.1.1.1'],
  enabled: true,
};
const config: Config = {
  routing: { routes: [] },
  interfaces: { items: [] },
  firewall: {
    default_policy: { input: 'drop', forward: 'drop', output: 'accept' },
    rules: { input: [], forward: [] },
    nat: { masquerade: [], port_forward: [] },
  },
  dhcp: {
    pools: [pool],
    static_leases: [
      { mac: 'aa:bb:cc:dd:ee:ff', ip: '192.168.1.10', hostname: 'server' },
    ],
  },
  hooks: { before_start: '', after_start: '' },
};

test('handles Rust serialization omitting empty items and hooks', () => {
  const raw = {
    ...config,
    interfaces: {},
    hooks: undefined,
  } as unknown as Config;
  const normalized = normalizeConfig(raw);
  expect(normalized.interfaces.items).toEqual([]);
  expect(normalized.hooks).toEqual({ before_start: '', after_start: '' });
  expect(raw.interfaces).toEqual({});
});
test('pool edits preserve the latest reservations and unrelated pools', () => {
  const fresh = {
    ...config,
    dhcp: { pools: [pool, { ...pool, name: 'guest' }], static_leases: [] },
  };
  const result = replacePool(fresh, pool, { ...pool, lease_time: '6h' });
  expect(result.static_leases).toEqual([]);
  expect(result.pools?.[0].lease_time).toBe('6h');
  expect(result.pools?.[1].name).toBe('guest');
  expect(fresh.dhcp.pools[0].lease_time).toBe('12h');
});
test('pool deletion does not restore deleted reservations', () => {
  const fresh = { ...config, dhcp: { pools: [pool], static_leases: [] } };
  expect(replacePool(fresh, pool, undefined)).toEqual({
    pools: [],
    static_leases: [],
  });
  expect(() =>
    replacePool(
      { ...config, dhcp: { pools: [], static_leases: [] } },
      pool,
      pool,
    ),
  ).toThrow('no longer exists');
});
test('rule editing preserves IDs and serializes states as arrays', () => {
  const rule = ruleFromValues(
    {
      action: 'accept',
      interfaces: 'br0, eth1',
      state: 'established, related',
      proto: 'tcp,udp',
      enabled: true,
      dport: '80,443',
      counter: true,
    },
    { id: 42, action: 'drop', interfaces: ['eth0'], enabled: false },
  );
  expect(rule.id).toBe(42);
  expect(rule.state).toEqual(['established', 'related']);
  expect(rule.interfaces).toEqual(['br0', 'eth1']);
  expect(rule.dport).toEqual([80, 443]);
  expect(rule.enabled).toBe(true);
});
test('rejects reserved TPROXY marks', () => {
  for (const mark of ['0', '253', '254', '255'])
    expect(() =>
      ruleFromValues({ action: 'tproxy', mark, tproxy_port: '7893' }),
    ).toThrow();
});
test('WAN selection warns about missing NAT using the actual egress device', () => {
  const missing: Config = {
    ...config,
    interfaces: {
      items: [
        {
          name: 'wan0',
          method: 'static',
          static_config: { address: '203.0.113.2/29', gateway: '203.0.113.1' },
        },
      ],
    },
  };
  expect(wanMasqueradeWarning(missing, 'wan0')).toContain(
    'No masquerade is configured on wan0',
  );
  expect(wanMasqueradeWarning(missing, '')).toBeUndefined();
  expect(wanMasqueradeWarning(missing, 'removed')).toBeUndefined();
  const direct = structuredClone(missing);
  direct.firewall.nat.masquerade = [{ oif: 'wan0' }];
  expect(wanMasqueradeWarning(direct, 'wan0')).toBeUndefined();
  const labelled = structuredClone(missing);
  labelled.interfaces.items[0].label = 'Office uplink';
  expect(wanMasqueradeWarning(labelled, 'wan0')).toContain(
    'No masquerade is configured on Office uplink.',
  );
  expect(wanMasqueradeWarning(labelled, 'wan0')).toContain(
    'Add Office uplink under Policies & NAT',
  );
  labelled.firewall.nat.masquerade = [{ oif: 'Office uplink' }];
  expect(wanMasqueradeWarning(labelled, 'wan0')).toBeDefined();
  labelled.firewall.nat.masquerade = [{ oif: 'wan0' }];
  expect(wanMasqueradeWarning(labelled, 'wan0')).toBeUndefined();
  const ppp = structuredClone(direct);
  ppp.interfaces.items[0].method = 'pppoe';
  expect(wanMasqueradeWarning(ppp, 'wan0')).toContain('on ppp0');
  ppp.interfaces.items[0].label = 'PPP uplink';
  expect(wanMasqueradeWarning(ppp, 'wan0')).toContain('on PPP uplink.');
  ppp.firewall.nat.masquerade = [{ oif: 'ppp0' }];
  expect(wanMasqueradeWarning(ppp, 'wan0')).toBeUndefined();
});
test('WAN selection is saved without changing rule IDs and can return to system routing', () => {
  const original = {
    id: 42,
    action: 'accept' as const,
    interfaces: ['br0'],
    route_via: 'wan0',
  };
  const values = {
    action: 'accept',
    interfaces: 'br0',
    route_via: 'wan1',
    enabled: true,
  };
  const selected = ruleFromValues(values, original);
  expect(selected.id).toBe(42);
  expect(selected.route_via).toBe('wan1');
  expect(
    ruleFromValues({ ...values, route_via: '' }, selected).route_via,
  ).toBeUndefined();
  expect(
    ruleFromValues({ ...values, action: 'drop' }, selected).route_via,
  ).toBeUndefined();
  for (const extra of [
    { oif: 'wan1' },
    { rate: '10/second' },
    { state: 'established,related' },
  ])
    expect(() => ruleFromValues({ ...values, ...extra })).toThrow();
  expect(
    ruleFromValues({ ...values, state: 'new, established' }).state,
  ).toEqual(['new', 'established']);
});
test('internal-route preservation defaults on, saves explicit opt-out and resets without WAN selection', () => {
  const values = {
    action: 'accept',
    interfaces: 'vlan2',
    route_via: 'wan0',
    enabled: true,
  };
  expect(ruleFromValues(values).preserve_internal_routes).toBe(true);
  const strict = ruleFromValues({ ...values, preserve_internal_routes: false });
  expect(strict.preserve_internal_routes).toBe(false);
  expect(
    ruleFromValues(
      { ...values, route_via: '', preserve_internal_routes: false },
      strict,
    ).preserve_internal_routes,
  ).toBe(true);
  expect(
    ruleFromValues(
      { ...values, action: 'drop', preserve_internal_routes: false },
      strict,
    ).preserve_internal_routes,
  ).toBe(true);
});
test('interface names stay immutable and PPP passwords retain whitespace', () => {
  const iface = interfaceFromValues(
    {
      name: 'changed',
      method: 'pppoe',
      username: 'user',
      password: ' secret ',
      mtu: '1492',
      keepalive_interval: '10',
      keepalive_failure: '3',
      mss_clamp: true,
    },
    { name: 'eth0', method: 'dhcp' },
  );
  expect(iface.name).toBe('eth0');
  expect(iface.pppoe?.password).toBe(' secret ');
  expect(iface.dhcp).toBeUndefined();
});

test('WAN return routing supports automatic tables, dynamic WANs and opt out', () => {
  const values = {
    name: 'wan0',
    method: 'static',
    address: '203.0.113.2/29',
    gateway: '203.0.113.1',
    return_route_table: '100',
    mtu: '1492',
    keepalive_interval: '10',
    keepalive_failure: '3',
  };
  const iface = interfaceFromValues(values);
  expect(iface.return_route_table).toBe(100);
  expect(
    interfaceFromValues({ ...values, return_route_table: '' }, iface)
      .return_route_table,
  ).toBeUndefined();
  expect(
    interfaceFromValues({ ...values, gateway: '' }, iface).return_route_table,
  ).toBeUndefined();
  for (const method of ['dhcp', 'pppoe']) {
    const dynamic = interfaceFromValues({ ...values, method }, iface);
    expect(dynamic.return_route_table).toBe(100);
    expect(dynamic.return_routing).toBe(true);
    expect(
      interfaceFromValues({ ...values, method, return_routing: false }, dynamic)
        .return_routing,
    ).toBe(false);
  }
  expect(iface.return_routing).toBe(true);
  expect(() =>
    interfaceFromValues({ ...values, return_route_table: '65536' }),
  ).toThrow();
});

test('common device MTU and MSS settings save on LANs and clear independently of PPPoE', () => {
  const values = {
    name: 'lan0',
    method: 'static',
    address: '192.168.1.1/24',
    device_mtu: '1500',
    mss_clamp_mtu: '1492',
  };
  const saved = interfaceFromValues(values);
  expect(saved.mtu).toBe(1500);
  expect(saved.mss_clamp_mtu).toBe(1492);
  expect(saved.pppoe).toBeUndefined();
  const cleared = interfaceFromValues(
    { ...values, device_mtu: '', mss_clamp_mtu: '' },
    saved,
  );
  expect(cleared.mtu).toBeUndefined();
  expect(cleared.mss_clamp_mtu).toBeUndefined();
  expect(() =>
    interfaceFromValues({ ...values, device_mtu: '1279' }),
  ).toThrow();
});

import { expect, test } from 'bun:test';
import { normalizeConfig } from '../src/lib/api';
import { replacePool } from '../src/pages/Dhcp';
import { ruleFromValues } from '../src/components/FirewallEditors';
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

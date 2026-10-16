import { expect, test } from 'bun:test';
import { routeFromValues } from '../src/pages/Routes';
import { normalizeConfig } from '../src/lib/api';
import type { Config } from '../src/lib/types';

const wans = [{ name: 'wan0', interface: 'ppp0', table: 100 }];
const values = {
  destination: '198.51.100.10/32',
  interface: 'wan0',
  gateway: '192.0.2.1',
  table_mode: 'Main',
  metric: '100',
  enabled: true,
};

test('system routes choose main, resolved WAN tables or custom tables without changing IDs', () => {
  const main = routeFromValues(values, wans);
  expect(main.table).toBe(254);
  expect(main.interface).toBe('wan0');
  expect(main.enabled).toBe(true);
  const wan = routeFromValues({ ...values, table_mode: 'WAN: wan0' }, wans, {
    ...main,
    id: 42,
  });
  expect(wan.table).toBe(100);
  expect(wan.id).toBe(42);
  expect(
    routeFromValues(
      { ...values, table_mode: 'Custom table', table: '200' },
      wans,
    ).table,
  ).toBe(200);
  expect(() =>
    routeFromValues({ ...values, table_mode: 'WAN: removed' }, wans),
  ).toThrow('no longer available');
  for (const table of ['0', '253', '255', '-1', '4294967296'])
    expect(() =>
      routeFromValues({ ...values, table_mode: 'Custom table', table }, wans),
    ).toThrow();
});

test('direct routes clear gateway flags; route metrics and enablement retain exact values', () => {
  const route = routeFromValues(
    { ...values, gateway: '', on_link: true, metric: '0', enabled: false },
    wans,
  );
  expect(route.gateway).toBeUndefined();
  expect(route.on_link).toBe(false);
  expect(route.metric).toBe(0);
  expect(route.enabled).toBe(false);
  expect(() => routeFromValues({ ...values, metric: '1.5' }, wans)).toThrow();
});

test('old configurations and Rust empty routing sections normalize to empty route arrays', () => {
  const raw = { interfaces: {}, routing: {} } as Config;
  expect(normalizeConfig(raw).routing.routes).toEqual([]);
  const old = { interfaces: {} } as Config;
  expect(normalizeConfig(old).routing.routes).toEqual([]);
  expect(raw.routing).toEqual({} as Config['routing']);
});

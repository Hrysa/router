import { expect, test } from 'bun:test';
import { interfaceOptions, toggleInterface } from '../src/lib/interfaces';
import type { InterfaceDetail } from '../src/lib/types';

const detected: InterfaceDetail[] = [
  { name: 'eth0', up: false, mtu: 1500, mac: '', rx_bytes: 0, tx_bytes: 0 },
  { name: 'wlan0', up: true, mtu: 1500, mac: '', rx_bytes: 0, tx_bytes: 0 },
];

test('interface options merge configured, referenced, detected and custom names', () => {
  const options = interfaceOptions(
    [
      { name: 'eth0', label: 'Internet', method: 'dhcp' },
      { name: 'br0', method: 'static', bridge_ports: ['eth1', 'eth1'] },
      { name: 'vlan10', method: 'dhcp', parent: 'eth2' },
    ],
    detected,
    ['ppp0', 'ppp0'],
  );
  expect(options.map((option) => option.name)).toEqual([
    'br0',
    'eth0',
    'eth1',
    'eth2',
    'ppp0',
    'vlan10',
    'wlan0',
  ]);
  expect(options.find((option) => option.name === 'eth0')).toEqual({
    name: 'eth0',
    label: 'Internet',
    up: false,
    source: 'Configured',
  });
  expect(options.find((option) => option.name === 'wlan0')?.source).toBe(
    'Detected',
  );
  expect(options.find((option) => option.name === 'eth1')?.source).toBe(
    'Referenced',
  );
  expect(options.find((option) => option.name === 'ppp0')?.source).toBe(
    'Custom',
  );
});

test('suggestions can be empty and exclude self without losing an existing selection', () => {
  expect(interfaceOptions()).toEqual([]);
  expect(
    interfaceOptions([], detected, [], 'eth0').map((option) => option.name),
  ).toEqual(['wlan0']);
  expect(
    interfaceOptions([], detected, ['eth0'], 'eth0').map(
      (option) => option.name,
    ),
  ).toEqual(['eth0', 'wlan0']);
});

test('multi-selection preserves unknown names and deduplicates quick fills', () => {
  expect(toggleInterface('ppp0, eth0, eth0', 'br0', true)).toBe(
    'ppp0, eth0, br0',
  );
  expect(toggleInterface('ppp0 eth0, br0', 'eth0', true)).toBe('ppp0, br0');
  expect(toggleInterface('eth0', 'eth0', true)).toBe('');
});

test('single-selection replaces rather than appends, and can be cleared', () => {
  expect(toggleInterface('eth0', 'wlan0', false)).toBe('wlan0');
  expect(toggleInterface('wlan0', 'wlan0', false)).toBe('');
});

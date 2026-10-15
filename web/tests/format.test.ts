import { describe, expect, test } from 'bun:test';
import {
  bytes,
  formatPort,
  list,
  parsePort,
  passwordError,
  role,
} from '../src/lib/format';

describe('port specifications', () => {
  test('round-trips all supported representations', () => {
    for (const value of [
      443,
      [80, 443],
      { start: 8000, end: 8080 },
      '@web_ports',
    ])
      expect(parsePort(formatPort(value))).toEqual(value);
    expect(parsePort('')).toBeUndefined();
    expect(parsePort(' 80, 443 ')).toEqual([80, 443]);
  });
  test('rejects malformed, out-of-range and unordered ports', () => {
    for (const input of [
      '0',
      '65536',
      '-1',
      '4.5',
      'NaN',
      'abc',
      '0x50',
      '80,',
      '80,,443',
      '9000-8000',
      '1-2-3',
      '@',
      '@bad name',
      '80-90,443',
    ])
      expect(() => parsePort(input)).toThrow();
  });
});
test('traffic rates are bytes/s, not bits/s', () => {
  expect(bytes(1024, true)).toBe('1 KiB/s');
  expect(bytes(0, true)).toBe('0 B/s');
  expect(bytes(undefined)).toBe('—');
  expect(bytes(NaN)).toBe('—');
});
test('password limit counts UTF-8 bytes', () => {
  expect(passwordError('a'.repeat(72))).toBeUndefined();
  expect(passwordError('a'.repeat(73))).toBeDefined();
  expect(passwordError('密'.repeat(24))).toBeUndefined();
  expect(passwordError('密'.repeat(25))).toBeDefined();
  expect(passwordError('')).toBeDefined();
});
test('interface role follows routerd inference', () => {
  expect(role({ name: 'eth0', method: 'dhcp' })).toBe('WAN');
  expect(
    role({
      name: 'eth0',
      method: 'static',
      static_config: { address: '10.0.0.2/24', gateway: '10.0.0.1' },
    }),
  ).toBe('WAN');
  expect(role({ name: 'br0', method: 'static' })).toBe('LAN');
  expect(role({ name: 'vlan10', method: 'static', vlan_id: 10 })).toBe('VLAN');
  expect(list('eth0, eth1\neth2')).toEqual(['eth0', 'eth1', 'eth2']);
});

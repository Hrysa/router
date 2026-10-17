import { expect, test } from 'bun:test';
import { groupFromValues } from '../src/pages/WanGroups';
import type { Values } from '../src/components/Editor';
const wans = [{ name: 'wan0', method: 'dhcp' as const }, { name: 'uplink', method: 'pppoe' as const }];
const values: Values = { name: 'Internet', targets: '1.1.1.1, 8.8.8.8', member_0: true, tier_0: '1', weight_0: '3', member_1: true, tier_1: '2', weight_1: '1', interval_seconds: '5', timeout_seconds: '2', failure_threshold: '3', recovery_threshold: '2', recovery_delay_seconds: '10' };
test('group editor preserves configured device names, tiers, weights and IDs', () => {
  const group = groupFromValues(values, wans);
  expect(group.members).toEqual([{ interface: 'wan0', tier: 1, weight: 3 }, { interface: 'uplink', tier: 2, weight: 1 }]);
  expect(group.targets).toEqual(['1.1.1.1', '8.8.8.8']);
  expect(groupFromValues(values, wans, { ...group, id: 42 }).id).toBe(42);
});
test('group editor rejects empty membership, invalid weights and invalid probe settings', () => {
  expect(() => groupFromValues({ ...values, member_0: false, member_1: false }, wans)).toThrow();
  expect(() => groupFromValues({ ...values, weight_0: '0' }, wans)).toThrow();
  expect(() => groupFromValues({ ...values, targets: 'example.org' }, wans)).toThrow();
  expect(() => groupFromValues({ ...values, interval_seconds: '2', timeout_seconds: '3' }, wans)).toThrow();
});

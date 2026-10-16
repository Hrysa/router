import { describe, expect, test } from 'bun:test';
import { cpuUsage } from '../src/lib/cpu';

describe('CPU utilization', () => {
  test('uses interval deltas rather than cumulative counter ratios', () => {
    expect(
      cpuUsage({ idle: 5000, total: 6000 }, { idle: 5150, total: 6200 }),
    ).toBe(25);
    expect(
      cpuUsage({ idle: 100, total: 1000 }, { idle: 110, total: 1100 }),
    ).toBeCloseTo(90);
  });

  test('supports fully idle and fully busy samples', () => {
    expect(cpuUsage({ idle: 100, total: 200 }, { idle: 200, total: 300 })).toBe(
      0,
    );
    expect(cpuUsage({ idle: 100, total: 200 }, { idle: 100, total: 300 })).toBe(
      100,
    );
  });

  test('waits for two usable snapshots', () => {
    expect(cpuUsage(undefined, { idle: 100, total: 200 })).toBeUndefined();
    expect(cpuUsage({ idle: 100, total: 200 }, undefined)).toBeUndefined();
    expect(cpuUsage({}, { idle: 100, total: 200 })).toBeUndefined();
    expect(cpuUsage({ idle: 100, total: 200 }, {})).toBeUndefined();
    expect(
      cpuUsage({ idle: 100, total: 200 }, { idle: 100, total: 200 }),
    ).toBeUndefined();
  });

  test('rejects resets and invalid counters instead of inventing a percentage', () => {
    const previous = { idle: 100, total: 200 };
    for (const current of [
      { idle: 10, total: 20 },
      { idle: 90, total: 300 },
      { idle: 250, total: 300 },
      { idle: 401, total: 400 },
      { idle: NaN, total: 300 },
      { idle: 150, total: Infinity },
      { idle: -1, total: 300 },
      { idle: 150, total: Number.MAX_SAFE_INTEGER + 1 },
      { idle: 150.5, total: 300 },
    ]) {
      expect(cpuUsage(previous, current)).toBeUndefined();
    }
    expect(cpuUsage({ idle: NaN, total: 200 }, previous)).toBeUndefined();
    expect(cpuUsage({ idle: 300, total: 200 }, previous)).toBeUndefined();
    expect(cpuUsage({ idle: 10, total: 20 }, previous)).toBe(50);
  });
});

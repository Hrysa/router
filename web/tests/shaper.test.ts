import { expect, test } from 'bun:test';
import { normalizeConfig } from '../src/lib/api';
import {
  replaceShaperProfile,
  shaperFromValues,
  shaperRates,
} from '../src/pages/Shaper';
import type { Config, ShaperStatus } from '../src/lib/types';
const values = {
  interface: 'eth0',
  side: 'wan',
  upload: '19.125',
  download: '190',
  overhead: '8',
  mpu: '0',
  link_layer: 'none',
  enabled: false,
  nat: true,
};
test('shaper rates use decimal kbit and remain disabled until explicitly enabled', () => {
  const p = shaperFromValues(values);
  expect(p).toMatchObject({
    id: 0,
    enabled: false,
    upload_kbit: 19125,
    download_kbit: 190000,
    nat: true,
  });
  expect(
    shaperFromValues({ ...values, overhead: '-8', side: 'lan' }).overhead,
  ).toBe(-8);
  expect(() => shaperFromValues({ ...values, upload: '-1' })).toThrow();
  expect(() => shaperFromValues({ ...values, upload: '1.0001' })).toThrow();
  expect(() =>
    shaperFromValues({ ...values, upload: '0', download: '0', enabled: true }),
  ).toThrow();
});
test('fresh shaper section updates retain concurrent profiles and stable IDs', () => {
  const one = { ...shaperFromValues(values), id: 10 };
  const two = { ...one, id: 20, interface: 'br0' };
  const settings = { profiles: [one, two] };
  const edited = replaceShaperProfile(
    settings,
    { ...one, upload_kbit: 5000 },
    'save',
  );
  expect(edited.profiles[1]).toEqual(two);
  expect(edited.profiles[0].id).toBe(10);
  expect(
    replaceShaperProfile(
      settings,
      shaperFromValues(values),
      'save',
    ).profiles.at(-1)?.id,
  ).toBe(21);
  expect(replaceShaperProfile(settings, one, 'delete').profiles).toEqual([two]);
  expect(() => replaceShaperProfile({ profiles: [] }, one, 'save')).toThrow();
  expect(
    normalizeConfig({ interfaces: { items: [] } } as unknown as Config).shaper,
  ).toEqual({ profiles: [] });
});
test('throughput samples use bits/s and reject counter resets and missing baselines', () => {
  const stats = {
    bytes: 1000,
    packets: 1,
    drops: 0,
    backlog_bytes: 0,
    ecn_marks: 0,
    average_delay_us: 0,
  };
  const before: ShaperStatus = {
    timestamp_ms: 1000,
    reconnect_active: true,
    profiles: [{ id: 1, interface: 'eth0', egress: stats }],
  };
  const after = {
    ...before,
    timestamp_ms: 2000,
    profiles: [{ ...before.profiles[0], egress: { ...stats, bytes: 126000 } }],
  };
  expect(shaperRates(after, before)['1/egress']).toBe(1);
  expect(shaperRates(before)).toEqual({});
  expect(shaperRates(before, after)).toEqual({});
  expect(shaperRates({ ...before, timestamp_ms: 3000 }, after)).toEqual({});
});

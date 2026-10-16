import type { SystemStats } from './types';

export function cpuUsage(
  previous: SystemStats['cpu'] | undefined,
  current: SystemStats['cpu'] | undefined,
): number | undefined {
  if (
    previous?.idle === undefined ||
    previous.total === undefined ||
    current?.idle === undefined ||
    current.total === undefined ||
    ![previous.idle, previous.total, current.idle, current.total].every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    ) ||
    previous.idle > previous.total ||
    current.idle > current.total
  )
    return undefined;
  const total = current.total - previous.total;
  const idle = current.idle - previous.idle;
  if (total <= 0 || idle < 0 || idle > total) return undefined;
  return (1 - idle / total) * 100;
}

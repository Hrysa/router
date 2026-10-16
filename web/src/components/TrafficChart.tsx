import { useId } from 'react';
import { bytes } from '../lib/format';
import { Empty } from '../lib/ui';

export function TrafficChart({
  timestamps,
  received,
  transmitted,
  label,
}: {
  timestamps: number[];
  received: number[];
  transmitted?: number[];
  label: string;
}) {
  const id = useId().replaceAll(':', '');
  const samples = timestamps.length;
  if (samples < 2)
    return (
      <Empty
        title="Collecting traffic samples"
        description="The router collects a sample every two seconds. History appears after two samples."
      />
    );
  const maximum = Math.max(
    1,
    ...received.filter(Number.isFinite),
    ...(transmitted ?? []).filter(Number.isFinite),
  );
  const width = 900;
  const height = 215;
  const first = timestamps[0];
  const span = Math.max(timestamps.at(-1)! - first, 1);
  const path = (values: number[]) =>
    timestamps
      .map(
        (timestamp, index) =>
          `${index ? 'L' : 'M'}${(((timestamp - first) / span) * width).toFixed(2)},${(height - (Math.max(0, Number.isFinite(values[index]) ? values[index] : 0) / maximum) * (height - 12)).toFixed(2)}`,
      )
      .join(' ');
  const area = (values: number[]) =>
    `${path(values)} L${width},${height} L0,${height} Z`;
  const time = (value: number) =>
    new Date(value * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });
  return (
    <div
      className="traffic-chart"
      role="img"
      aria-label={`${label}. Receive maximum ${bytes(Math.max(...received), true)}${transmitted ? `, transmit maximum ${bytes(Math.max(...transmitted), true)}` : ''}.`}
    >
      <div className="chart-scale">
        <span>{bytes(maximum, true)}</span>
        <span>{bytes(maximum / 2, true)}</span>
        <span>0</span>
      </div>
      <div className="chart-plot">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="none"
          aria-hidden="true"
        >
          <defs>
            <linearGradient id={`${id}-rx`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity=".24" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity=".01" />
            </linearGradient>
          </defs>
          {[0, 1, 2, 3, 4].map((step) => (
            <line
              key={step}
              x1="0"
              x2={width}
              y1={(height * step) / 4}
              y2={(height * step) / 4}
              className="chart-grid"
            />
          ))}
          <path d={area(received)} fill={`url(#${id}-rx)`} />
          <path d={path(received)} className="chart-line chart-rx" />
          {transmitted && (
            <path d={path(transmitted)} className="chart-line chart-tx" />
          )}
        </svg>
        <div className="chart-times">
          <span>{time(first)}</span>
          <span>{time(first + span / 2)}</span>
          <span>{time(timestamps.at(-1)!)}</span>
        </div>
      </div>
    </div>
  );
}

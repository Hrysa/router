import { useId } from 'react';
import { bytes } from '../lib/format';
import { Empty } from '../lib/ui';

export function TrafficChart({
  timestamps,
  received,
  transmitted,
  label,
  percentage = false,
}: {
  timestamps: number[];
  received: number[];
  transmitted?: number[];
  label: string;
  percentage?: boolean;
}) {
  const id = useId().replaceAll(':', '');
  const samples = timestamps.length;
  if (samples < 2)
    return (
      <Empty
        title={percentage ? "Collecting usage samples" : "Collecting traffic samples"}
        description="The router collects a sample every two seconds. History appears after two samples."
      />
    );
  const format = (value: number) => percentage ? `${value.toFixed(0)}%` : bytes(value, true);
  const maximum = percentage ? 100 : Math.max(
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
          !Number.isFinite(values[index]) ? '' : `${index && Number.isFinite(values[index - 1]) ? 'L' : 'M'}${(((timestamp - first) / span) * width).toFixed(2)},${(height - (Math.max(0, Number.isFinite(values[index]) ? values[index] : 0) / maximum) * (percentage ? height : height - 12)).toFixed(2)}`,
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
      aria-label={percentage ? `${label}. Scale 0 to 100 percent.` : `${label}. Receive maximum ${bytes(Math.max(...received), true)}${transmitted ? `, transmit maximum ${bytes(Math.max(...transmitted), true)}` : ''}.`}
    >
      <div className="chart-scale">
        {percentage ? (
          [100, 80, 60, 40, 20, 0].map((value) => (
            <span key={value}>{format(value)}</span>
          ))
        ) : (
          <>
            <span>{format(maximum)}</span>
            <span>{format(maximum / 2)}</span>
            <span>0</span>
          </>
        )}
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
          {Array.from({ length: percentage ? 6 : 5 }, (_, step) => (
            <line
              key={step}
              x1="0"
              x2={width}
              y1={(height * step) / (percentage ? 5 : 4)}
              y2={(height * step) / (percentage ? 5 : 4)}
              className="chart-grid"
            />
          ))}
          {received.every(Number.isFinite) && <path d={area(received)} fill={`url(#${id}-rx)`} />}
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

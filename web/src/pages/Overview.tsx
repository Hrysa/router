import { useEffect, useRef, useState } from 'react';
import {
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Clock,
  Cpu,
  Layers,
  Shield,
} from 'react-feather';
import { bytes, latest, role, uptime } from '../lib/format';
import { cpuUsage } from '../lib/cpu';
import type { SystemStats } from '../lib/types';
import { interfaceDisplayName } from '../lib/interfaces';
import {
  useConfig,
  useInterfaces,
  useMetrics,
  useServices,
  useStatus,
  useSystem,
  useSystemStats,
} from '../lib/queries';
import { Badge, Card, Empty, PageHeader, QueryNotice } from '../lib/ui';
import { TrafficChart } from '../components/TrafficChart';

export function Overview() {
  const config = useConfig();
  const live = useInterfaces();
  const metrics = useMetrics();
  const services = useServices();
  const system = useSystem();
  const stats = useSystemStats();
  const status = useStatus();
  const previousCpu = useRef<SystemStats['cpu'] | undefined>(undefined);
  const [cpu, setCpu] = useState<number | undefined>(undefined);
  const cpuCounters = stats.isError ? undefined : stats.data?.cpu;
  useEffect(() => {
    setCpu(cpuUsage(previousCpu.current, cpuCounters));
    previousCpu.current = cpuCounters;
  }, [cpuCounters, stats.dataUpdatedAt]);
  const [selection, setSelection] = useState('');
  const interfaces = Array.from(
    new Set([
      ...(config.data?.interfaces.items.map((iface) => iface.name) ?? []),
      ...Object.keys(metrics.data?.interfaces ?? {}),
    ]),
  );
  const wan = config.data?.interfaces.items.find(
    (iface) => iface.method !== 'static' || iface.static_config?.gateway,
  )?.name;
  const name = interfaces.includes(selection)
    ? selection
    : (wan ?? interfaces[0] ?? '');
  const displayName = interfaceDisplayName(name, config.data?.interfaces.items);
  const traffic = metrics.data?.interfaces[name];
  const memory = stats.data?.memory;
  const activeServices = services.data?.services.filter(
    (service) => service.active,
  ).length;
  return (
    <>
      <PageHeader
        title="Your network, at a glance."
        actions={
          <span className="live-label">
            <span className="status-dot" />
            Updates every 2 seconds
          </span>
        }
      />
      <QueryNotice query={system} />
      <QueryNotice query={metrics} />
      <QueryNotice query={config} />
      <QueryNotice query={stats} />
      <QueryNotice query={status} />
      <div className="stat-grid">
        <Card className="stat-card">
          <div className="stat-top">
            <span>Receive rate</span>
            <span className="stat-icon blue">
              <ArrowDown size={19} />
            </span>
          </div>
          <div className="stat-value">
            {bytes(latest(traffic?.rx_bps), true)}
          </div>
          <div className="stat-caption">
            <span className="chart-key rx" />
            {displayName || 'No interface selected'}
          </div>
        </Card>
        <Card className="stat-card">
          <div className="stat-top">
            <span>Transmit rate</span>
            <span className="stat-icon teal">
              <ArrowUp size={19} />
            </span>
          </div>
          <div className="stat-value">
            {bytes(latest(traffic?.tx_bps), true)}
          </div>
          <div className="stat-caption">
            <span className="chart-key tx" />
            {displayName || 'No interface selected'}
          </div>
        </Card>
        <Card className="stat-card">
          <div className="stat-top">
            <span>CPU usage</span>
            <span className="stat-icon blue">
              <Cpu size={18} />
            </span>
          </div>
          <div className="stat-value">
            {cpu === undefined ? '—' : `${cpu.toFixed(1)}%`}
          </div>
          <div className="stat-caption">
            {cpu === undefined
              ? 'Waiting for CPU samples'
              : 'Across all CPU cores'}
          </div>
        </Card>
        <Card className="stat-card">
          <div className="stat-top">
            <span>Memory usage</span>
            <span className="stat-icon violet">
              <Cpu size={18} />
            </span>
          </div>
          <div className="stat-value">
            {memory ? `${memory.usage_percent}%` : '—'}
          </div>
          <div className="stat-caption">
            {memory
              ? `${bytes(memory.used_kb * 1024)} of ${bytes(memory.total_kb * 1024)}`
              : 'Waiting for system data'}
          </div>
        </Card>
        <Card className="stat-card">
          <div className="stat-top">
            <span>System uptime</span>
            <span className="stat-icon amber">
              <Clock size={18} />
            </span>
          </div>
          <div className="stat-value uptime-value">
            {uptime(system.data?.uptime_seconds)}
          </div>
          <div className="stat-caption">
            {system.data?.hostname ?? 'Waiting for router'}
          </div>
        </Card>
      </div>
      <Card
        title="Traffic overview"
        subtitle="Receive and transmit · bytes per second · up to 30 minutes"
        className="traffic-card"
        actions={
          <label className="inline-select">
            <span className="sr-only">Traffic interface</span>
            <select
              value={name}
              onChange={(event) => setSelection(event.target.value)}
            >
              {interfaces.length ? (
                interfaces.map((item) => (
                  <option key={item} value={item}>
                    {interfaceDisplayName(item, config.data?.interfaces.items)}
                  </option>
                ))
              ) : (
                <option value="">No interfaces</option>
              )}
            </select>
          </label>
        }
      >
        {metrics.data && traffic ? (
          <TrafficChart
            timestamps={metrics.data.timestamps}
            received={traffic.rx_bps}
            transmitted={traffic.tx_bps}
            label={`${displayName} traffic`}
          />
        ) : (
          <Empty
            title={
              metrics.isPending
                ? 'Waiting for traffic data'
                : 'No samples for this interface'
            }
            description="Traffic appears when the router metrics collector has samples."
          />
        )}
        <div className="chart-legend">
          <span>
            <i className="chart-key rx" />
            Receive
          </span>
          <span>
            <i className="chart-key tx" />
            Transmit
          </span>
          <span className="subtle">
            One interface at a time. No bridge double-counting.
          </span>
        </div>
      </Card>
      <div className="dashboard-columns">
        <Card
          title="Network interfaces"
          subtitle="Configured connections and live link state"
          actions={
            <a className="text-link" href="#/interfaces">
              Manage
              <ArrowRight size={15} />
            </a>
          }
        >
          <QueryNotice query={live} />
          {config.data?.interfaces.items.length ? (
            <div className="interface-list">
              {config.data.interfaces.items.map((iface) => {
                const link = live.data?.interfaces.find(
                  (item) => item.name === iface.name,
                );
                return (
                  <div className="interface-row" key={iface.name}>
                    <span className="interface-symbol">
                      <Layers size={20} />
                    </span>
                    <div className="grow">
                      <strong>
                        {interfaceDisplayName(
                          iface.name,
                          config.data?.interfaces.items,
                        )}
                      </strong>
                      <span className="mono subtle">
                        {iface.name} <span className="footer-dot">·</span>{' '}
                        {iface.static_config?.address ||
                          iface.method.toUpperCase()}
                      </span>
                    </div>
                    <span className="small subtle">{role(iface)}</span>
                    <Badge tone={link?.up ? 'success' : 'neutral'}>
                      {link ? (link.up ? 'Up' : 'Down') : 'Unknown'}
                    </Badge>
                  </div>
                );
              })}
            </div>
          ) : (
            <Empty
              title="No configured interfaces"
              description="Add your first network connection."
              action={
                <a className="button" href="#/interfaces">
                  Set up interfaces
                </a>
              }
            />
          )}
        </Card>
        <Card
          title="Router health"
          subtitle="The essentials, without the noise"
        >
          <div className="health-item">
            <div className="health-label">
              <Shield size={18} />
              <span>Managed services</span>
            </div>
            <strong>
              {services.data
                ? `${activeServices} / ${services.data.services.length} active`
                : '—'}
            </strong>
          </div>
          <QueryNotice query={services} />
          <div className="health-item">
            <span className="health-label">Load average</span>
            <span className="mono">
              {status.data
                ? `${status.data.loadavg['1m']} / ${status.data.loadavg['5m']} / ${status.data.loadavg['15m']}`
                : '—'}
            </span>
          </div>
          <div className="health-item">
            <span>Free memory</span>
            <strong>{memory ? bytes(memory.available_kb * 1024) : '—'}</strong>
          </div>
          <div className="memory-track">
            <div
              style={{ width: `${Math.min(100, memory?.usage_percent ?? 0)}%` }}
            />
          </div>
          <div className="health-note">
            Live metrics describe the running router. Saved configuration may
            not be applied yet.
          </div>
          <a className="text-link health-link" href="#/monitoring">
            Explore monitoring
            <ArrowRight size={15} />
          </a>
        </Card>
      </div>
    </>
  );
}

import { useState } from 'react';
import { Activity, ArrowDown, ArrowUp } from 'react-feather';
import { bytes, latest } from '../lib/format';
import { interfaceDisplayName } from '../lib/interfaces';
import { useConfig, useInterfaces, useMetrics } from '../lib/queries';
import {
  Badge,
  Card,
  Empty,
  Loading,
  PageHeader,
  QueryNotice,
  Table,
} from '../lib/ui';
import { TrafficChart } from '../components/TrafficChart';

export function Monitoring() {
  const config = useConfig();
  const metrics = useMetrics();
  const live = useInterfaces();
  const [selected, setSelected] = useState('');
  const names = Object.keys(metrics.data?.interfaces ?? {});
  const name = names.includes(selected) ? selected : (names[0] ?? '');
  const traffic = metrics.data?.interfaces[name];
  const rules = Object.entries(metrics.data?.firewall ?? {});
  return (
    <>
      <PageHeader
        title="Monitoring"
        actions={
          <span className="live-label">
            <Activity size={16} />
            2-second samples · 30-minute history
          </span>
        }
      />
      <QueryNotice query={metrics} />
      <QueryNotice query={live} />
      <Card
        title="Interface traffic"
        subtitle="One selected interface, without adding overlapping bridge traffic"
        actions={
          <select
            aria-label="Monitor interface"
            value={name}
            onChange={(event) => setSelected(event.target.value)}
          >
            {names.length ? (
              names.map((item) => (
                <option key={item} value={item}>
                  {interfaceDisplayName(item, config.data?.interfaces.items)}
                </option>
              ))
            ) : (
              <option value="">No samples</option>
            )}
          </select>
        }
      >
        <div className="traffic-summary">
          <span>
            <ArrowDown size={17} className="rx-text" />
            {bytes(latest(traffic?.rx_bps), true)}
            <small>Receive</small>
          </span>
          <span>
            <ArrowUp size={17} className="tx-text" />
            {bytes(latest(traffic?.tx_bps), true)}
            <small>Transmit</small>
          </span>
        </div>
        {metrics.isPending ? (
          <Loading />
        ) : traffic && metrics.data ? (
          <TrafficChart
            timestamps={metrics.data.timestamps}
            received={traffic.rx_bps}
            transmitted={traffic.tx_bps}
            label={`${interfaceDisplayName(name, config.data?.interfaces.items)} traffic history`}
          />
        ) : (
          <Empty
            title="No metrics yet"
            description="The collector needs a few seconds to measure traffic."
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
          <span className="subtle">Rates are bytes/s, not bits/s.</span>
        </div>
      </Card>
      <Card
        title="Live interface counters"
        subtitle="Cumulative byte counters and latest packet rates"
      >
        <Table
          columns={[
            'Interface',
            'Link',
            'Received total',
            'Transmitted total',
            'RX packets/s',
            'TX packets/s',
          ]}
        >
          {live.data?.interfaces.map((iface) => (
            <tr key={iface.name}>
              <td>
                {interfaceDisplayName(
                  iface.name,
                  config.data?.interfaces.items,
                )}
              </td>
              <td>
                <Badge tone={iface.up ? 'success' : 'neutral'}>
                  {iface.up ? 'Up' : 'Down'}
                </Badge>
              </td>
              <td>{bytes(iface.rx_bytes)}</td>
              <td>{bytes(iface.tx_bytes)}</td>
              <td className="mono">
                {latest(metrics.data?.interfaces[iface.name]?.rx_pps)?.toFixed(
                  1,
                ) ?? '—'}
              </td>
              <td className="mono">
                {latest(metrics.data?.interfaces[iface.name]?.tx_pps)?.toFixed(
                  1,
                ) ?? '—'}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <Card
        title="Firewall activity"
        subtitle="Per-rule rates from nftables counters. Rule IDs match saved firewall rules."
      >
        {rules.length ? (
          <Table
            columns={['Rule ID', 'Chain', 'Packets / second', 'Bytes / second']}
          >
            {rules.map(([id, rule]) => (
              <tr key={id}>
                <td className="mono">#{id}</td>
                <td>
                  <Badge tone="blue">{rule.chain}</Badge>
                </td>
                <td className="mono">
                  {latest(rule.packets_per_sec)?.toFixed(1) ?? '—'}
                </td>
                <td>{bytes(latest(rule.bytes_per_sec), true)}</td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No firewall counter samples"
            description="Enable counters on a rule and apply it to collect activity."
          />
        )}
      </Card>
    </>
  );
}

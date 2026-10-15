import { useState } from 'react';
import { Edit2, Plus, Trash2, Wifi } from 'react-feather';
import { encoded, getConfig, write } from '../lib/api';
import { list } from '../lib/format';
import { useApi, useConfig } from '../lib/queries';
import type { Config, Lease, Pool, Reservation } from '../lib/types';
import {
  Badge,
  Card,
  Empty,
  Loading,
  PageHeader,
  QueryNotice,
  Table,
  useSave,
  useUi,
} from '../lib/ui';
import { checked, Editor, text } from '../components/Editor';
import type { Field, Values } from '../components/Editor';

const poolFields: Field[] = [
  { name: 'name', label: 'Pool name', required: true, placeholder: 'home' },
  {
    name: 'subnet',
    label: 'Subnet / prefix',
    required: true,
    placeholder: '192.168.1.0/24',
  },
  {
    name: 'start',
    label: 'First address',
    required: true,
    placeholder: '192.168.1.100',
  },
  {
    name: 'end',
    label: 'Last address',
    required: true,
    placeholder: '192.168.1.200',
  },
  {
    name: 'lease_time',
    label: 'Lease duration',
    required: true,
    placeholder: '12h',
    hint: 'Seconds or a duration such as 30m, 12h or 7d.',
  },
  { name: 'domain', label: 'Domain name', placeholder: 'lan.local' },
  {
    name: 'dns_servers',
    label: 'DNS servers',
    placeholder: '192.168.1.1, 1.1.1.1',
  },
  {
    name: 'gateway',
    label: 'Gateway override',
    placeholder: 'Automatic from LAN',
  },
  { name: 'enabled', label: 'Pool enabled', type: 'toggle' },
];
export function replacePool(
  config: Config,
  original: Pool | undefined,
  replacement: Pool | undefined,
): Config['dhcp'] {
  const pools = [...(config.dhcp.pools ?? [])];
  if (original) {
    const index = pools.findIndex((pool) => pool.name === original.name);
    if (index === -1)
      throw new Error('This pool no longer exists. Refresh before editing.');
    if (replacement) pools[index] = replacement;
    else pools.splice(index, 1);
  } else if (replacement) pools.push(replacement);
  return { ...config.dhcp, pools };
}
export function Dhcp() {
  const config = useConfig();
  const leases = useApi<{ leases: Lease[] }>('/monitor/leases', 10000);
  const ui = useUi();
  const [editing, setEditing] = useState<Pool | 'new' | null>(null);
  const [reservation, setReservation] = useState<Partial<Reservation> | null>(
    null,
  );
  const poolSave = useSave(
    async ({
      original,
      replacement,
    }: {
      original?: Pool;
      replacement?: Pool;
    }) => {
      const fresh = await getConfig();
      return write('/config/dhcp', replacePool(fresh, original, replacement));
    },
  );
  const reserve = useSave((lease: Reservation) =>
    write('/config/dhcp/leases', lease),
  );
  const remove = useSave((mac: string) =>
    write(`/config/dhcp/leases/${encoded(mac)}`, undefined, 'DELETE'),
  );
  const pools = config.data?.dhcp.pools ?? [];
  const reservations = config.data?.dhcp.static_leases ?? [];
  const original = editing && editing !== 'new' ? editing : undefined;
  return (
    <>
      <PageHeader
        title="DHCP & leases"
        description="A place on the network for every device."
        actions={
          <button
            className="primary"
            disabled={!config.data}
            onClick={() => setEditing('new')}
          >
            <Plus size={17} />
            Add pool
          </button>
        }
      />
      <QueryNotice query={config} />
      <div className="summary-strip">
        <span>
          <Wifi size={18} />
          <strong>{pools.filter((pool) => pool.enabled).length}</strong> enabled
          pools
        </span>
        <span>
          <strong>{leases.data?.leases.length ?? '—'}</strong> active leases
        </span>
        <span>
          <strong>{reservations.length}</strong> reservations
        </span>
      </div>
      <Card
        title="Address pools"
        subtitle="Kea DHCPv4 · settings are saved until you apply"
      >
        {config.isPending ? (
          <Loading />
        ) : !pools.length ? (
          <Empty
            title="No address pools"
            description="Create a pool to assign addresses to your devices."
          />
        ) : (
          <div className="pool-grid">
            {pools.map((pool) => (
              <div className="pool-card" key={pool.name}>
                <div className="pool-header">
                  <span className="interface-symbol">
                    <Wifi size={20} />
                  </span>
                  <Badge tone={pool.enabled ? 'success' : 'neutral'}>
                    {pool.enabled ? 'Enabled' : 'Disabled'}
                  </Badge>
                </div>
                <h3>{pool.name}</h3>
                <p className="mono">{pool.subnet}</p>
                <dl className="details-list">
                  <div>
                    <dt>Range</dt>
                    <dd className="mono">
                      {pool.range.start}
                      <br />
                      {pool.range.end}
                    </dd>
                  </div>
                  <div>
                    <dt>Lease</dt>
                    <dd>{pool.lease_time}</dd>
                  </div>
                  <div>
                    <dt>Domain</dt>
                    <dd>{pool.domain || '—'}</dd>
                  </div>
                  <div>
                    <dt>DNS</dt>
                    <dd className="mono">
                      {pool.dns_servers.join(', ') || 'None'}
                    </dd>
                  </div>
                </dl>
                <div className="pool-actions">
                  <button onClick={() => setEditing(pool)}>
                    <Edit2 size={14} />
                    Edit pool
                  </button>
                  <button
                    className="icon-button danger-text"
                    aria-label={`Delete pool ${pool.name}`}
                    disabled={poolSave.isPending}
                    onClick={async () => {
                      if (
                        await ui.confirm({
                          title: `Delete pool ${pool.name}?`,
                          message:
                            'Clients in this subnet may stop receiving DHCP addresses after Apply.',
                          label: 'Delete pool',
                          dangerous: true,
                        })
                      )
                        poolSave.mutate({ original: pool });
                    }}
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
      <Card
        title="Reserved addresses"
        subtitle="Predictable addresses for devices you know"
        actions={
          <button disabled={!config.data} onClick={() => setReservation({})}>
            <Plus size={16} />
            Add reservation
          </button>
        }
      >
        {reservations.length ? (
          <Table columns={['Device', 'MAC address', 'Reserved IP', 'Actions']}>
            {reservations.map((lease) => (
              <tr key={lease.mac}>
                <td>
                  <strong>{lease.hostname || 'Unnamed device'}</strong>
                </td>
                <td className="mono">{lease.mac}</td>
                <td className="mono">{lease.ip}</td>
                <td>
                  <button
                    className="icon-button danger-text"
                    aria-label={`Delete reservation ${lease.mac}`}
                    disabled={remove.isPending}
                    onClick={async () => {
                      if (
                        await ui.confirm({
                          title: 'Delete this reservation?',
                          message: `${lease.hostname || lease.mac} will no longer have a reserved address after Apply.`,
                          label: 'Delete reservation',
                          dangerous: true,
                        })
                      )
                        remove.mutate(lease.mac);
                    }}
                  >
                    <Trash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No reserved addresses"
            description="Reserve an IP for a server, printer or other familiar device."
          />
        )}
      </Card>
      <Card
        title="Active leases"
        subtitle="Read from the router’s Kea lease database · refreshes every 10 seconds"
      >
        <QueryNotice query={leases} />
        {leases.isPending ? (
          <Loading />
        ) : leases.data?.leases.length ? (
          <Table
            columns={[
              'Hostname',
              'Address',
              'MAC address',
              'Expires',
              'Actions',
            ]}
          >
            {leases.data.leases.map((lease) => (
              <tr key={lease.address}>
                <td>{lease.hostname || 'Unnamed device'}</td>
                <td className="mono">{lease.address}</td>
                <td className="mono">{lease.mac}</td>
                <td>{lease.expires || '—'}</td>
                <td>
                  {!reservations.some(
                    (item) =>
                      item.mac.toLowerCase() === lease.mac.toLowerCase(),
                  ) && (
                    <button
                      onClick={() =>
                        setReservation({
                          mac: lease.mac,
                          ip: lease.address,
                          hostname: lease.hostname,
                        })
                      }
                      disabled={!config.data}
                    >
                      <Plus size={14} />
                      Reserve
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No active leases reported"
            description="Leases appear when clients receive addresses from Kea. An empty list can also mean the lease database is unavailable."
          />
        )}
      </Card>
      {editing && (
        <Editor
          title={original ? `Edit ${original.name}` : 'Add DHCP pool'}
          fields={poolFields}
          initial={{
            name: original?.name ?? '',
            subnet: original?.subnet ?? '',
            start: original?.range.start ?? '',
            end: original?.range.end ?? '',
            lease_time: original?.lease_time ?? '12h',
            domain: original?.domain ?? 'lan.local',
            dns_servers: original?.dns_servers.join(', ') ?? '',
            gateway: original?.gateway ?? '',
            enabled: original?.enabled ?? true,
          }}
          onClose={() => setEditing(null)}
          onSave={(values: Values) =>
            poolSave.mutateAsync({
              original,
              replacement: {
                ...original,
                name: text(values, 'name'),
                subnet: text(values, 'subnet'),
                range: {
                  start: text(values, 'start'),
                  end: text(values, 'end'),
                },
                lease_time: text(values, 'lease_time'),
                domain: text(values, 'domain'),
                dns_servers: list(text(values, 'dns_servers')),
                gateway: text(values, 'gateway'),
                enabled: checked(values, 'enabled'),
              },
            })
          }
        />
      )}
      {reservation && (
        <Editor
          title="Reserve an address"
          initial={{
            hostname: reservation.hostname ?? '',
            mac: reservation.mac ?? '',
            ip: reservation.ip ?? '',
          }}
          fields={[
            { name: 'hostname', label: 'Hostname', placeholder: 'home-server' },
            {
              name: 'mac',
              label: 'MAC address',
              required: true,
              placeholder: 'aa:bb:cc:dd:ee:ff',
            },
            {
              name: 'ip',
              label: 'Reserved IPv4 address',
              required: true,
              placeholder: '192.168.1.10',
            },
          ]}
          onClose={() => setReservation(null)}
          onSave={(values) =>
            reserve.mutateAsync({
              mac: text(values, 'mac'),
              ip: text(values, 'ip'),
              hostname: text(values, 'hostname'),
            })
          }
        />
      )}
    </>
  );
}

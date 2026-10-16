import { useEffect, useRef, useState } from 'react';
import { Edit2, Plus, Trash2 } from 'react-feather';
import { checked, Editor, integer, text } from '../components/Editor';
import type { Field, Values } from '../components/Editor';
import { getConfig, write } from '../lib/api';
import { bytes } from '../lib/format';
import { interfaceDisplayName } from '../lib/interfaces';
import { useApi, useConfig } from '../lib/queries';
import type { ShaperProfile, ShaperSettings, ShaperStatus } from '../lib/types';
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

function rate(values: Values, key: string): number {
  const value = text(values, key) || '0';
  const number = Number(value);
  if (
    !/^\d+(\.\d{1,3})?$/.test(value) ||
    !Number.isFinite(number) ||
    number < 0 ||
    number > 100000
  )
    throw new Error(
      `${key} must be 0–100000 Mbit/s with at most three decimal places.`,
    );
  return Math.round(number * 1000);
}
export function shaperFromValues(
  values: Values,
  original?: ShaperProfile,
): ShaperProfile {
  const overhead = Number(text(values, 'overhead'));
  if (
    !/^-?\d+$/.test(text(values, 'overhead')) ||
    !Number.isInteger(overhead) ||
    overhead < -64 ||
    overhead > 256
  )
    throw new Error('Overhead must be a whole number from -64 to 256.');
  const profile: ShaperProfile = {
    ...original,
    id: original?.id ?? 0,
    comment: text(values, 'comment'),
    interface: text(values, 'interface'),
    enabled: checked(values, 'enabled'),
    side: text(values, 'side') === 'lan' ? 'lan' : 'wan',
    upload_kbit: rate(values, 'upload'),
    download_kbit: rate(values, 'download'),
    nat: checked(values, 'nat'),
    overhead,
    mpu: integer(values, 'mpu', 0, 256),
    link_layer: text(values, 'link_layer') as ShaperProfile['link_layer'],
  };
  if (profile.enabled && !profile.upload_kbit && !profile.download_kbit)
    throw new Error('Set a nonzero rate for at least one direction.');
  return profile;
}
export function replaceShaperProfile(
  settings: ShaperSettings,
  profile: ShaperProfile,
  mode: 'save' | 'delete',
): ShaperSettings {
  const profiles = settings.profiles ?? [];
  if (profile.id && !profiles.some((p) => p.id === profile.id))
    throw new Error('This profile was removed. Refresh before editing.');
  if (mode === 'delete')
    return {
      ...settings,
      profiles: profiles.filter((p) => p.id !== profile.id),
    };
  if (profile.id)
    return {
      ...settings,
      profiles: profiles.map((p) => (p.id === profile.id ? profile : p)),
    };
  const id = Math.max(0, ...profiles.map((p) => p.id)) + 1;
  if (id > 4294967295) throw new Error('Profile ID space exhausted.');
  return { ...settings, profiles: [...profiles, { ...profile, id }] };
}
export function shaperRates(
  current: ShaperStatus,
  previous?: ShaperStatus,
): Record<string, number> {
  const rates: Record<string, number> = {};
  const elapsed = previous
    ? (current.timestamp_ms - previous.timestamp_ms) / 1000
    : 0;
  if (!previous || elapsed <= 0) return rates;
  for (const profile of current.profiles) {
    const old = previous.profiles.find(
      (p) => p.id === profile.id && p.interface === profile.interface,
    );
    for (const direction of ['ingress', 'egress'] as const) {
      const now = profile[direction],
        before = old?.[direction];
      if (now && before && now.bytes >= before.bytes)
        rates[`${profile.id}/${direction}`] =
          ((now.bytes - before.bytes) * 8) / elapsed / 1e6;
    }
  }
  return rates;
}

export function Shaper() {
  const config = useConfig();
  const live = useApi<ShaperStatus>('/monitor/shaper', 5000);
  const [editing, setEditing] = useState<ShaperProfile | 'new'>();
  const [rates, setRates] = useState<Record<string, number>>({});
  const previous = useRef<ShaperStatus | undefined>(undefined);
  const ui = useUi();
  useEffect(() => {
    if (live.data) {
      setRates(shaperRates(live.data, previous.current));
      previous.current = live.data;
    }
  }, [live.data]);
  const profiles = config.data?.shaper?.profiles ?? [];
  const operation = useSave(
    async ({
      profile,
      mode,
    }: {
      profile: ShaperProfile;
      mode: 'save' | 'delete';
    }) => {
      const fresh = await getConfig();
      return write(
        '/config/shaper',
        replaceShaperProfile(fresh.shaper ?? { profiles: [] }, profile, mode),
        'PUT',
      );
    },
  );
  const fields: Field[] = [
    { name: 'comment', label: 'Description' },
    {
      name: 'interface',
      label: 'Interface',
      type: 'select',
      required: true,
      options: [
        '',
        ...(config.data?.interfaces.items.map((iface) => ({
          value: iface.name,
          label: interfaceDisplayName(
            iface.name,
            config.data?.interfaces.items,
          ),
        })) ?? []),
      ],
      hint: 'PPPoE profiles target ppp0. Shape each connection independently.',
    },
    {
      name: 'side',
      label: 'Interface faces',
      type: 'select',
      options: ['wan', 'lan'],
      hint: 'wan: upload on egress. lan: download on egress. LAN profiles can separate clients using a router proxy. Avoid shaping both ends of the same bottleneck unintentionally.',
    },
    {
      name: 'upload',
      label: 'Upload (Mbit/s)',
      placeholder: 'e.g. 19',
      hint: 'Start at 90–95% of measured sustained capacity. Zero disables this direction.',
    },
    {
      name: 'download',
      label: 'Download (Mbit/s)',
      placeholder: 'e.g. 190',
      hint: 'Unused bandwidth is available to active clients. Zero disables this direction.',
    },
    {
      name: 'nat',
      label: 'NAT-aware host fairness',
      type: 'toggle',
      hint: 'Use connection tracking to distinguish hosts behind this router’s NAT. Upstream NAT and proxy-created connections may conceal client identities.',
    },
    {
      name: 'overhead',
      label: 'Link overhead (bytes)',
      type: 'number',
      min: -64,
      max: 256,
      required: true,
      hint: 'Additional bytes per packet. Leave 0 unless you know the access-link encapsulation; PPPoE alone adds 8 bytes, but total overhead depends on the link.',
    },
    {
      name: 'mpu',
      label: 'Minimum packet size (bytes)',
      type: 'number',
      min: 0,
      max: 256,
      required: true,
    },
    {
      name: 'link_layer',
      label: 'Link framing',
      type: 'select',
      options: ['none', 'atm', 'ptm'],
    },
    {
      name: 'enabled',
      label: 'Enabled',
      type: 'toggle',
      hint: 'Save first, then Apply. New profiles start disabled.',
    },
  ];
  const original = editing && editing !== 'new' ? editing : undefined;
  return (
    <>
      <PageHeader
        title="Traffic shaping"
        actions={
          <button
            className="primary"
            disabled={!config.data}
            onClick={() => setEditing('new')}
          >
            <Plus size={17} />
            Add profile
          </button>
        }
      />
      <QueryNotice query={config} />
      <div className="info-banner">
        <p>
          CAKE shares capacity fairly between IPs and flows while keeping queues
          short. A single active client can use spare bandwidth. Rates must stay
          below the real bottleneck; these are shared rates, not fixed per-IP
          limits. Save and Apply are separate.
        </p>
      </div>
      <Card
        title="Saved shaping profiles"
        subtitle="Optional per-interface upload and download shaping. Pure bridge switching and upstream proxy identities are not automatically separated."
      >
        {config.isPending ? (
          <Loading />
        ) : !profiles.length ? (
          <Empty
            title="No shaping profiles"
            description="Add a profile and enter measured link rates. Shaping is disabled by default."
          />
        ) : (
          <Table
            columns={[
              'Interface',
              'Upload / download',
              'Fairness / state',
              'Actions',
            ]}
          >
            {profiles.map((p) => (
              <tr key={p.id} className={p.enabled ? '' : 'disabled-row'}>
                <td>
                  <strong>
                    {interfaceDisplayName(
                      p.interface,
                      config.data?.interfaces.items,
                    )}
                  </strong>
                  <small className="cell-detail">
                    {p.comment || `Profile #${p.id}`}
                  </small>
                </td>
                <td>
                  {p.upload_kbit ? `${p.upload_kbit / 1000} Mbit/s` : 'Off'} /{' '}
                  {p.download_kbit ? `${p.download_kbit / 1000} Mbit/s` : 'Off'}
                </td>
                <td>
                  <Badge tone={p.enabled ? 'success' : 'neutral'}>
                    {p.enabled ? 'Enabled in saved config' : 'Disabled'}
                  </Badge>
                  <small className="cell-detail">
                    {p.side.toUpperCase()} · per-host fairness
                    {p.nat ? ' · NAT aware' : ''}
                  </small>
                </td>
                <td>
                  <div className="row-actions">
                    <button
                      className="icon-button"
                      aria-label={`Edit shaper ${p.id}`}
                      onClick={() => setEditing(p)}
                    >
                      <Edit2 size={15} />
                    </button>
                    <button
                      className="icon-button danger-text"
                      disabled={operation.isPending}
                      aria-label={`Delete shaper ${p.id}`}
                      onClick={async () => {
                        if (
                          await ui.confirm({
                            title: 'Delete shaping profile?',
                            message:
                              'Save deletion now; Apply removes its managed traffic control.',
                            label: 'Delete profile',
                            dangerous: true,
                          })
                        )
                          operation.mutate({ profile: p, mode: 'delete' });
                      }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      <QueryNotice query={live} />
      {live.data?.error && (
        <div className="warning-banner" role="alert">
          Shaper error: {live.data.error}
        </div>
      )}
      <Card
        title="Live CAKE statistics"
        subtitle="Five-second samples. Existing qdiscs do not prove that newly saved settings were applied."
      >
        {live.isPending ? (
          <Loading />
        ) : !live.data?.profiles.length ? (
          <Empty
            title="No managed live shapers"
            description="Apply an enabled profile to create CAKE queues. Missing interfaces remain pending until they appear."
          />
        ) : (
          <Table
            columns={[
              'Interface / direction',
              'Throughput / traffic',
              'Backlog',
              'Drops / ECN',
              'Average queue delay',
            ]}
          >
            {live.data.profiles.flatMap((p) =>
              (['egress', 'ingress'] as const).map((direction) => {
                const stats = p[direction];
                const rate = rates[`${p.id}/${direction}`];
                return (
                  <tr key={`${p.id}/${direction}`}>
                    <td>
                      {interfaceDisplayName(
                        p.interface,
                        config.data?.interfaces.items,
                      )}
                      <small className="cell-detail">
                        {direction}
                        {direction === 'ingress' ? ' via IFB' : ''}
                      </small>
                    </td>
                    <td>
                      {stats
                        ? `${rate === undefined ? '—' : `${rate.toFixed(2)} Mbit/s`} · ${bytes(stats.bytes)}`
                        : 'Not active'}
                    </td>
                    <td>{stats ? bytes(stats.backlog_bytes) : '—'}</td>
                    <td>
                      {stats ? `${stats.drops} / ${stats.ecn_marks}` : '—'}
                    </td>
                    <td>
                      {stats
                        ? `${(stats.average_delay_us / 1000).toFixed(2)} ms`
                        : '—'}
                    </td>
                  </tr>
                );
              }),
            )}
          </Table>
        )}
        {live.data && !live.data.reconnect_active && (
          <p className="muted">
            Reconnect repair is inactive until a successful Apply.
          </p>
        )}
      </Card>
      {editing && (
        <Editor
          title={
            original
              ? `Edit shaping profile #${original.id}`
              : 'Add shaping profile'
          }
          fields={fields}
          initial={{
            comment: original?.comment ?? '',
            interface: original?.interface ?? '',
            side: original?.side ?? 'wan',
            upload: String((original?.upload_kbit ?? 0) / 1000),
            download: String((original?.download_kbit ?? 0) / 1000),
            nat: original?.nat ?? true,
            overhead: String(original?.overhead ?? 0),
            mpu: String(original?.mpu ?? 0),
            link_layer: original?.link_layer ?? 'none',
            enabled: original?.enabled ?? false,
          }}
          onClose={() => setEditing(undefined)}
          onSave={async (values) => {
            await operation.mutateAsync({
              profile: shaperFromValues(values, original),
              mode: 'save',
            });
            setEditing(undefined);
          }}
        />
      )}
    </>
  );
}

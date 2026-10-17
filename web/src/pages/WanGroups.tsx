import { useState } from 'react';
import { Edit2, Plus, Trash2 } from 'react-feather';
import { checked, Editor, integer, text } from '../components/Editor';
import type { Field, Values } from '../components/Editor';
import { getConfig, write } from '../lib/api';
import { interfaceDisplayName } from '../lib/interfaces';
import { useApi, useConfig } from '../lib/queries';
import type { InterfaceConfig, WanGroup, WanGroupStatus } from '../lib/types';
import {
  Badge, Card, Empty, PageHeader, QueryNotice, Table, useSave, useUi,
} from '../lib/ui';

export function groupFromValues(
  values: Values,
  wans: InterfaceConfig[],
  original?: WanGroup,
): WanGroup {
  const members = wans.flatMap((wan, index) =>
    checked(values, `member_${index}`)
      ? [{
          interface: wan.name,
          tier: integer(values, `tier_${index}`, 1, 65535),
          weight: integer(values, `weight_${index}`, 1, 100),
        }]
      : [],
  );
  if (!members.length) throw new Error('Select at least one WAN member.');
  const targets = text(values, 'targets').split(/[\s,]+/).filter(Boolean);
  if (
    !targets.length || targets.length > 4 ||
    targets.some((ip) =>
      !/^\d+\.\d+\.\d+\.\d+$/.test(ip) ||
      ip.split('.').some((part) => Number(part) > 255),
    )
  ) throw new Error('Provide 1–4 IPv4 probe targets.');
  const interval = integer(values, 'interval_seconds', 2, 300);
  const timeout = integer(values, 'timeout_seconds', 1, 5);
  if (timeout > interval)
    throw new Error('Probe timeout must not exceed the interval.');
  return {
    id: original?.id ?? 0,
    name: text(values, 'name'),
    members,
    targets,
    interval_seconds: interval,
    timeout_seconds: timeout,
    failure_threshold: integer(values, 'failure_threshold', 1, 10),
    recovery_threshold: integer(values, 'recovery_threshold', 1, 10),
    recovery_delay_seconds: integer(values, 'recovery_delay_seconds', 0, 600),
  };
}

function GroupEditor({
  group, wans: initialWans, save, close,
}: {
  group?: WanGroup;
  wans: InterfaceConfig[];
  save: (group: WanGroup) => Promise<unknown>;
  close: () => void;
}) {
  // Keep field indices stable if configuration refetches while editing.
  const [wans] = useState(initialWans);
  const fields: Field[] = [
    { name: 'name', label: 'Group name', required: true },
    {
      name: 'targets', label: 'Health probe targets', required: true,
      hint: 'Comma-separated IPv4 addresses that answer ICMP. A member is reachable when any target answers through its WAN.',
    },
    ...wans.flatMap((wan, index): Field[] => [
      {
        name: `member_${index}`,
        label: `Include ${interfaceDisplayName(wan.name, wans)}`,
        type: 'toggle',
      },
      {
        name: `tier_${index}`, label: `${wan.name} tier`, type: 'number',
        min: 1, max: 65535, required: true,
        when: (values) => checked(values, `member_${index}`),
        hint: 'Lower tiers take priority. A higher tier is used only when every member of lower tiers is unhealthy.',
      },
      {
        name: `weight_${index}`, label: `${wan.name} weight`, type: 'number',
        min: 1, max: 100, required: true,
        when: (values) => checked(values, `member_${index}`),
        hint: 'Relative share of client source IPs among healthy members in the active tier.',
      },
    ]),
    {
      name: 'interval_seconds', label: 'Probe interval (seconds)',
      type: 'number', min: 2, max: 300, required: true,
    },
    {
      name: 'timeout_seconds', label: 'Probe timeout (seconds)',
      type: 'number', min: 1, max: 5, required: true,
    },
    {
      name: 'failure_threshold', label: 'Consecutive failed rounds before down',
      type: 'number', min: 1, max: 10, required: true,
    },
    {
      name: 'recovery_threshold', label: 'Consecutive successful rounds before recovery',
      type: 'number', min: 1, max: 10, required: true,
    },
    {
      name: 'recovery_delay_seconds', label: 'Recovery delay (seconds)',
      type: 'number', min: 0, max: 600, required: true,
    },
  ];
  const initial: Values = {
    name: group?.name ?? '',
    targets: group?.targets.join(', ') ?? '1.1.1.1, 8.8.8.8',
    interval_seconds: String(group?.interval_seconds ?? 5),
    timeout_seconds: String(group?.timeout_seconds ?? 2),
    failure_threshold: String(group?.failure_threshold ?? 3),
    recovery_threshold: String(group?.recovery_threshold ?? 2),
    recovery_delay_seconds: String(group?.recovery_delay_seconds ?? 10),
  };
  wans.forEach((wan, index) => {
    const member = group?.members.find((item) => item.interface === wan.name);
    initial[`member_${index}`] = Boolean(member);
    initial[`tier_${index}`] = String(member?.tier ?? 1);
    initial[`weight_${index}`] = String(member?.weight ?? 1);
  });
  return (
    <Editor
      title={group ? 'Edit WAN group' : 'Add WAN group'}
      fields={fields}
      initial={initial}
      onSave={(values) => save(groupFromValues(values, wans, group))}
      onClose={close}
    />
  );
}

export function WanGroups() {
  const config = useConfig();
  const live = useApi<WanGroupStatus>('/monitor/wan-groups', 2000);
  const [editing, setEditing] = useState<WanGroup | 'new'>();
  const ui = useUi();
  const wans = config.data?.interfaces.items.filter((wan) =>
    (wan.method !== 'static' || Boolean(wan.static_config?.gateway)) &&
    wan.return_routing !== false,
  ) ?? [];
  const operation = useSave(async ({ group, remove }: {
    group: WanGroup;
    remove?: boolean;
  }) => {
    const fresh = await getConfig();
    const groups = fresh.wan_groups ?? [];
    if (group.id && !groups.some((item) => item.id === group.id))
      throw new Error('This group was removed. Refresh before editing.');
    const saved = {
      ...group,
      id: group.id || Math.max(0, ...groups.map((item) => item.id)) + 1,
    };
    const updated = remove
      ? groups.filter((item) => item.id !== group.id)
      : group.id
        ? groups.map((item) => item.id === group.id ? saved : item)
        : [...groups, saved];
    await write('/config/wan-groups', updated, 'PUT');
  });
  return (
    <>
      <PageHeader
        title="WAN Groups"
        actions={
          <button className="primary" disabled={!wans.length} onClick={() => setEditing('new')}>
            <Plus size={17} />Add group
          </button>
        }
      />
      <QueryNotice query={config} />
      <QueryNotice query={live} />
      <div className="info-banner">
        <p>
          Save groups, then Apply. Select a group in a forward Accept rule’s
          Route via control. Healthy members in the lowest available tier share
          clients by weight using source-IP modulo 256. Each client keeps one WAN while membership is unchanged. Existing connections keep their WAN;
          failed-WAN connections need to reconnect. If all members are down,
          matching traffic is blocked. IPv4 forwarding only.
        </p>
      </div>
      {!live.data?.active && (
        <div className="info-banner">
          <p>Health monitoring is inactive. Apply to install and activate WAN group rules.</p>
        </div>
      )}
      {live.data?.error && (
        <div className="info-banner"><p>Group map update failed: {live.data.error}</p></div>
      )}
      {!config.data?.wan_groups?.length && (
        <Card>
          <Empty title="No WAN groups" description="Add WAN interfaces with return routing enabled, then create a group." />
        </Card>
      )}
      {config.data?.wan_groups?.map((group) => {
        const running = live.data?.groups.find((item) => item.id === group.id);
        return (
          <Card
            key={group.id}
            title={group.name}
            subtitle={`Group #${group.id} · ${running?.active_tier ? `Active tier ${running.active_tier}` : 'No active tier'}`}
            actions={
              <div className="row-actions">
                <button className="icon-button" aria-label={`Edit group ${group.name}`} onClick={() => setEditing(group)}>
                  <Edit2 size={16} />
                </button>
                <button
                  className="icon-button danger-text"
                  aria-label={`Delete group ${group.name}`}
                  disabled={operation.isPending}
                  onClick={async () => {
                    if (await ui.confirm({
                      title: 'Delete WAN group?',
                      message: 'Remove this saved group? Firewall rules must stop referencing it before deletion. Apply activates the removal.',
                      label: 'Delete', dangerous: true,
                    })) operation.mutate({ group, remove: true });
                  }}
                >
                  <Trash2 size={16} />
                </button>
              </div>
            }
          >
            <Table columns={['WAN', 'Tier', 'Weight', 'Live health', 'Effective share']}>
              {group.members.map((member) => {
                const status = running?.members.find((item) => item.interface === member.interface);
                return (
                  <tr key={member.interface}>
                    <td>
                      {interfaceDisplayName(member.interface, config.data?.interfaces.items)}
                      <small className="cell-detail">{member.interface}</small>
                    </td>
                    <td>{member.tier}</td>
                    <td>{member.weight}</td>
                    <td>
                      <Badge tone={status?.health.healthy ? 'success' : 'neutral'}>
                        {status?.health.healthy ? 'Healthy' : status?.health.reason ? 'Unavailable / recovering' : 'Waiting for probes'}
                      </Badge>
                      <small className="cell-detail">{status?.health.reason}</small>
                    </td>
                    <td>{status ? `${status.effective_percent.toFixed(1)}%` : '—'}</td>
                  </tr>
                );
              })}
            </Table>
            <p className="subtle">
              Live health and shares describe the installed group. Shares are
              weighted shares of 256 source-IP slots, not bandwidth guarantees.
              Equal-weight WANs split consecutive addresses evenly; arbitrary
              active addresses may still be uneven.
              Configure masquerade separately for each member WAN.
            </p>
          </Card>
        );
      })}
      {editing && (
        <GroupEditor
          group={editing === 'new' ? undefined : editing}
          wans={wans}
          close={() => setEditing(undefined)}
          save={async (group) => {
            await operation.mutateAsync({ group });
            setEditing(undefined);
          }}
        />
      )}
    </>
  );
}

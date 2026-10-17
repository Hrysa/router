import { useEffect, useState } from 'react';
import {
  ArrowDown,
  ArrowUp,
  Edit2,
  Plus,
  Settings,
  Shield,
  Trash2,
} from 'react-feather';
import { encoded, getConfig, write } from '../lib/api';
import { formatPort, list } from '../lib/format';
import { interfaceDisplayName } from '../lib/interfaces';
import { useConfig } from '../lib/queries';
import type { FirewallRule, NftSet, PortForward } from '../lib/types';
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
import { Editor, text } from '../components/Editor';
import type { Values } from '../components/Editor';
import {
  NatEditor,
  RuleEditor,
  SetEditor,
  wanMasqueradeWarning,
} from '../components/FirewallEditors';

type Tab = 'input' | 'forward' | 'nat' | 'sets';
const tabs: Tab[] = ['input', 'forward', 'nat', 'sets'];
function tabFromHash(): Tab {
  const value = new URLSearchParams(window.location.hash.split('?')[1]).get(
    'tab',
  );
  return tabs.includes(value as Tab) ? (value as Tab) : 'input';
}

type Editing =
  | { kind: 'rule'; original?: FirewallRule; chain: 'input' | 'forward' }
  | { kind: 'nat'; original?: PortForward }
  | { kind: 'set'; original?: NftSet }
  | { kind: 'policy' };
export function Firewall() {
  const config = useConfig();
  const ui = useUi();
  const [tab, setTab] = useState<Tab>(tabFromHash);
  useEffect(() => {
    const syncTab = () => setTab(tabFromHash());
    window.addEventListener('hashchange', syncTab);
    return () => window.removeEventListener('hashchange', syncTab);
  }, []);
  const selectTab = (next: Tab) => {
    setTab(next);
    window.location.hash = `/firewall?tab=${next}`;
  };
  const [editing, setEditing] = useState<Editing | null>(null);
  const firewall = config.data?.firewall;
  const interfaceName = (name: string) =>
    config.data?.wan_groups?.find((group) => name === `group:${group.id}`)?.name ?? interfaceDisplayName(name, config.data?.interfaces.items);
  const missingMasquerade =
    firewall?.rules.forward.filter(
      (rule) =>
        rule.enabled !== false &&
        rule.action === 'accept' &&
        rule.route_via &&
        wanMasqueradeWarning(config.data, rule.route_via),
    ) ?? [];
  const operation = useSave(
    ({
      path,
      body,
      method = 'POST',
    }: {
      path: string;
      body?: unknown;
      method?: string;
    }) => write(path, body, method),
  );
  const policy = useSave(async (values: Values) => {
    const fresh = await getConfig();
    return write('/config/firewall', {
      ...fresh.firewall,
      default_policy: {
        input: text(values, 'input'),
        forward: text(values, 'forward'),
        output: text(values, 'output'),
      },
      nat: {
        ...fresh.firewall.nat,
        masquerade: list(text(values, 'masquerade')).map((oif) => ({ oif })),
      },
      blackhole: list(text(values, 'blackhole')),
    });
  });
  const deleteItem = async (path: string, name: string) => {
    if (
      await ui.confirm({
        title: `Delete ${name}?`,
        message:
          'This changes saved firewall configuration only. Apply separately to update the running firewall.',
        label: 'Delete',
        dangerous: true,
      })
    )
      operation.mutate({ path, method: 'DELETE' });
  };
  const add = () =>
    setEditing(
      tab === 'nat'
        ? { kind: 'nat' }
        : tab === 'sets'
          ? { kind: 'set' }
          : { kind: 'rule', chain: tab },
    );
  return (
    <>
      <PageHeader
        title="Firewall"
        actions={
          <>
            <button
              onClick={() => setEditing({ kind: 'policy' })}
              disabled={!firewall}
            >
              <Settings size={16} />
              Policies & NAT
            </button>
            <button className="primary" onClick={add} disabled={!firewall}>
              <Plus size={17} />
              {tab === 'sets'
                ? 'Add set'
                : tab === 'nat'
                  ? 'Add port forward'
                  : 'Add rule'}
            </button>
          </>
        }
      />
      <QueryNotice query={config} />
      {tab === 'forward' && missingMasquerade.length > 0 && (
        <div className="warning-banner" role="status">
          <p>
            WAN selection has no configured masquerade for{' '}
            {missingMasquerade
              .map(
                (rule) =>
                  `rule #${rule.id} (${interfaceName(rule.route_via ?? '')})`,
              )
              .join(', ')}
            . Private LAN clients normally need source NAT unless the upstream
            router routes their subnet back.
          </p>
          <button onClick={() => setEditing({ kind: 'policy' })}>
            Review masquerade
          </button>
        </div>
      )}
      <div className="summary-strip">
        <span>
          <Shield size={18} />
          Default input{' '}
          <Badge
            tone={
              firewall?.default_policy.input === 'drop' ? 'success' : 'warning'
            }
          >
            {firewall?.default_policy.input ?? '—'}
          </Badge>
        </span>
        <span>
          Forward <Badge>{firewall?.default_policy.forward ?? '—'}</Badge>
        </span>
        <span>
          Output <Badge>{firewall?.default_policy.output ?? '—'}</Badge>
        </span>
      </div>
      <div
        className="tabs"
        role="tablist"
        aria-label="Firewall sections"
        onKeyDown={(event) => {
          const current = tabs.indexOf(tab);
          const next =
            event.key === 'ArrowRight'
              ? tabs[(current + 1) % tabs.length]
              : event.key === 'ArrowLeft'
                ? tabs[(current + tabs.length - 1) % tabs.length]
                : event.key === 'Home'
                  ? tabs[0]
                  : event.key === 'End'
                    ? tabs.at(-1)
                    : undefined;
          if (next) {
            event.preventDefault();
            selectTab(next);
            document.getElementById(`tab-${next}`)?.focus();
          }
        }}
      >
        {tabs.map((item) => (
          <button
            key={item}
            role="tab"
            tabIndex={tab === item ? 0 : -1}
            aria-selected={tab === item}
            id={`tab-${item}`}
            aria-controls="firewall-panel"
            className={tab === item ? 'selected' : ''}
            onClick={() => selectTab(item)}
          >
            {item === 'nat'
              ? 'Port forwarding'
              : item === 'sets'
                ? 'Named sets'
                : `${item[0].toUpperCase()}${item.slice(1)} rules`}
            <span className="tab-count">
              {item === 'nat'
                ? (firewall?.nat.port_forward.length ?? 0)
                : item === 'sets'
                  ? (firewall?.sets?.length ?? 0)
                  : (firewall?.rules[item].length ?? 0)}
            </span>
          </button>
        ))}
      </div>
      <div role="tabpanel" id="firewall-panel" aria-labelledby={`tab-${tab}`}>
        <Card
          title={
            tab === 'input'
              ? 'Traffic to the router'
              : tab === 'forward'
                ? 'Traffic through the router'
                : tab === 'nat'
                  ? 'Port forwarding'
                  : 'Reusable named sets'
          }
          subtitle={
            tab === 'forward'
              ? 'Filter verdicts run in order. The first matching WAN selection pins each new IPv4 outbound connection.'
              : tab === 'input'
                ? 'Rules run in order. The first matching verdict wins.'
                : tab === 'nat'
                  ? 'Redirect incoming connections to an internal destination.'
                  : 'Share address and port collections across firewall rules.'
          }
        >
          {config.isPending ? (
            <Loading />
          ) : firewall && (tab === 'input' || tab === 'forward') ? (
            firewall.rules[tab].length ? (
              <Table columns={['Rule', 'Match', 'Action', 'State', 'Actions']}>
                {firewall.rules[tab].map((rule, index) => (
                  <tr
                    key={rule.id}
                    className={rule.enabled === false ? 'disabled-row' : ''}
                  >
                    <td>
                      <strong>{rule.comment || `Rule #${rule.id}`}</strong>
                      <small className="cell-detail mono">
                        #{rule.id}
                        {rule.counter ? ' · counters on' : ''}
                      </small>
                    </td>
                    <td>
                      <span className="mono">
                        {rule.interfaces_invert ? 'not ' : ''}
                        {rule.interfaces.map(interfaceName).join(', ') ||
                          'Any ingress'}
                        {rule.oif ? ` → ${interfaceName(rule.oif)}` : ''}
                        {rule.route_via
                          ? ` → WAN ${interfaceName(rule.route_via)}`
                          : ''}
                      </span>
                      <small className="cell-detail">
                        {rule.route_via &&
                        rule.preserve_internal_routes === false
                          ? 'Includes internal destinations · '
                          : ''}
                        {rule.proto?.join(', ') || 'Any protocol'}
                        {rule.dport ? ` · port ${formatPort(rule.dport)}` : ''}
                        {rule.saddr ? ` · from ${rule.saddr}` : ''}
                        {rule.state?.length
                          ? ` · ${rule.state.join(', ')}`
                          : ''}
                      </small>
                    </td>
                    <td>
                      <Badge
                        tone={
                          rule.action === 'accept'
                            ? 'success'
                            : rule.action === 'tproxy'
                              ? 'blue'
                              : 'danger'
                        }
                      >
                        {rule.action}
                      </Badge>
                    </td>
                    <td>
                      <button
                        className="status-toggle"
                        aria-label={`${rule.enabled === false ? 'Enable' : 'Disable'} rule ${rule.id}`}
                        disabled={operation.isPending}
                        onClick={() =>
                          operation.mutate({
                            path: `/config/firewall/rules/${rule.id}`,
                            method: 'PUT',
                            body: { ...rule, enabled: rule.enabled === false },
                          })
                        }
                      >
                        <Badge
                          tone={rule.enabled === false ? 'neutral' : 'success'}
                        >
                          {rule.enabled === false ? 'Disabled' : 'Enabled'}
                        </Badge>
                      </button>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          aria-label={`Move rule ${rule.id} up`}
                          disabled={!index || operation.isPending}
                          onClick={() =>
                            operation.mutate({
                              path: `/config/firewall/rules/${rule.id}/move`,
                              body: { direction: 'up' },
                            })
                          }
                        >
                          <ArrowUp size={15} />
                        </button>
                        <button
                          className="icon-button"
                          aria-label={`Move rule ${rule.id} down`}
                          disabled={
                            index === firewall.rules[tab].length - 1 ||
                            operation.isPending
                          }
                          onClick={() =>
                            operation.mutate({
                              path: `/config/firewall/rules/${rule.id}/move`,
                              body: { direction: 'down' },
                            })
                          }
                        >
                          <ArrowDown size={15} />
                        </button>
                        <button
                          className="icon-button"
                          aria-label={`Edit rule ${rule.id}`}
                          onClick={() =>
                            setEditing({
                              kind: 'rule',
                              chain: tab,
                              original: rule,
                            })
                          }
                        >
                          <Edit2 size={15} />
                        </button>
                        <button
                          className="icon-button danger-text"
                          aria-label={`Delete rule ${rule.id}`}
                          disabled={operation.isPending}
                          onClick={() =>
                            void deleteItem(
                              `/config/firewall/rules/${rule.id}`,
                              `rule #${rule.id}`,
                            )
                          }
                        >
                          <Trash2 size={15} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty
                title="No rules in this chain"
                description={`Unmatched traffic follows the ${firewall.default_policy[tab]} policy.`}
                action={
                  <button onClick={add}>
                    <Plus size={16} />
                    Add the first rule
                  </button>
                }
              />
            )
          ) : null}
          {tab === 'nat' &&
            firewall &&
            (firewall.nat.port_forward.length ? (
              <Table
                columns={[
                  'Description',
                  'Ingress',
                  'Destination',
                  'State',
                  'Actions',
                ]}
              >
                {firewall.nat.port_forward.map((rule) => (
                  <tr key={rule.id}>
                    <td>
                      <strong>{rule.comment || `Forward #${rule.id}`}</strong>
                      <small className="cell-detail">
                        {rule.proto.toUpperCase()} ·{' '}
                        {formatPort(rule.target_port) || 'Any port'}
                      </small>
                    </td>
                    <td className="mono">
                      {rule.interfaces.map(interfaceName).join(', ')}
                    </td>
                    <td className="mono">
                      {rule.redirect_address}
                      {rule.redirect_port
                        ? ` : ${formatPort(rule.redirect_port)}`
                        : ''}
                    </td>
                    <td>
                      <Badge tone={rule.enabled ? 'success' : 'neutral'}>
                        {rule.enabled ? 'Enabled' : 'Disabled'}
                      </Badge>
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          aria-label={`Edit port forward ${rule.id}`}
                          onClick={() =>
                            setEditing({ kind: 'nat', original: rule })
                          }
                        >
                          <Edit2 size={16} />
                        </button>
                        <button
                          className="icon-button danger-text"
                          aria-label={`Delete port forward ${rule.id}`}
                          disabled={operation.isPending}
                          onClick={() =>
                            void deleteItem(
                              `/config/firewall/nat/port-forward/${rule.id}`,
                              `port forward #${rule.id}`,
                            )
                          }
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty
                title="No port forwards"
                description="Expose only the internal services you intend to share."
              />
            ))}
          {tab === 'sets' &&
            firewall &&
            (firewall.sets?.length ? (
              <Table columns={['Set', 'Type', 'Elements', 'Actions']}>
                {firewall.sets.map((set) => (
                  <tr key={set.name}>
                    <td>
                      <strong className="mono">@{set.name}</strong>
                      <small className="cell-detail">
                        {set.comment || 'No description'}
                      </small>
                    </td>
                    <td>
                      <Badge tone="blue">{set.set_type}</Badge>
                      {set.interval && (
                        <small className="cell-detail">Intervals enabled</small>
                      )}
                    </td>
                    <td className="set-preview mono">
                      {set.elements || 'Empty'}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          className="icon-button"
                          aria-label={`Edit set ${set.name}`}
                          onClick={() =>
                            setEditing({ kind: 'set', original: set })
                          }
                        >
                          <Edit2 size={16} />
                        </button>
                        <button
                          className="icon-button danger-text"
                          aria-label={`Delete set ${set.name}`}
                          disabled={operation.isPending}
                          onClick={() =>
                            void deleteItem(
                              `/config/firewall/sets/${encoded(set.name)}`,
                              `@${set.name}`,
                            )
                          }
                        >
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </Table>
            ) : (
              <Empty
                title="No named sets"
                description="Create reusable address or port lists, then reference them with @name."
              />
            ))}
        </Card>
      </div>
      {editing?.kind === 'rule' && (
        <RuleEditor
          rule={editing.original}
          chain={editing.chain}
          close={() => setEditing(null)}
          save={(rule) =>
            operation.mutateAsync({
              path: editing.original
                ? `/config/firewall/rules/${editing.original.id}`
                : `/config/firewall/rules?chain=${editing.chain}`,
              body: rule,
              method: editing.original ? 'PUT' : 'POST',
            })
          }
        />
      )}
      {editing?.kind === 'nat' && (
        <NatEditor
          rule={editing.original}
          close={() => setEditing(null)}
          save={(rule) =>
            operation.mutateAsync({
              path: editing.original
                ? `/config/firewall/nat/port-forward/${editing.original.id}`
                : '/config/firewall/nat/port-forward',
              body: rule,
              method: editing.original ? 'PUT' : 'POST',
            })
          }
        />
      )}
      {editing?.kind === 'set' && (
        <SetEditor
          set={editing.original}
          close={() => setEditing(null)}
          save={(set) =>
            operation.mutateAsync({
              path: editing.original
                ? `/config/firewall/sets/${encoded(editing.original.name)}`
                : '/config/firewall/sets',
              body: set,
              method: editing.original ? 'PUT' : 'POST',
            })
          }
        />
      )}
      {editing?.kind === 'policy' && firewall && (
        <Editor
          title="Policies, masquerade & blocklist"
          initial={{
            ...firewall.default_policy,
            masquerade: firewall.nat.masquerade
              .map((rule) => rule.oif)
              .join(', '),
            blackhole: firewall.blackhole?.join('\n') ?? '',
          }}
          fields={[
            ...(['input', 'forward', 'output'] as const).map((name) => ({
              name,
              label: `${name[0].toUpperCase()}${name.slice(1)} policy`,
              type: 'select' as const,
              options: ['accept', 'drop'],
            })),
            {
              name: 'masquerade',
              label: 'Masquerade egress interfaces',
              type: 'interface',
              multiple: true,
              placeholder: 'eth0, ppp0',
              hint: 'Choose interfaces or enter names. Empty disables masquerading.',
            },
            {
              name: 'blackhole',
              label: 'Blocked addresses',
              type: 'textarea',
              wide: true,
              hint: 'IP addresses and CIDR ranges, one per line.',
            },
          ]}
          onClose={() => setEditing(null)}
          onSave={(values) => policy.mutateAsync(values)}
        />
      )}
    </>
  );
}

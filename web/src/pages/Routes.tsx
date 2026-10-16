import { useState } from 'react';
import { Edit2, Plus, Trash2 } from 'react-feather';
import { checked, Editor, integer, text } from '../components/Editor';
import type { Field, Values } from '../components/Editor';
import { write } from '../lib/api';
import { useApi, useConfig } from '../lib/queries';
import { interfaceDisplayName } from '../lib/interfaces';
import type {
  InterfaceConfig,
  KernelRoute,
  RoutingSettings,
  StaticRoute,
  WanTable,
} from '../lib/types';
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

export function routeFromValues(
  values: Values,
  wans: WanTable[],
  original?: StaticRoute,
): StaticRoute {
  const choice = text(values, 'table_mode');
  const wan = wans.find((wan) => choice === `WAN: ${wan.name}`);
  if (choice !== 'Main' && choice !== 'Custom table' && !wan)
    throw new Error(
      'The selected WAN table is no longer available. Choose another table.',
    );
  const table =
    choice === 'Main'
      ? 254
      : (wan?.table ?? integer(values, 'table', 1, 4294967295));
  if ([253, 255].includes(table))
    throw new Error('Tables 253 and 255 are reserved.');
  const gateway = text(values, 'gateway') || undefined;
  return {
    ...original,
    id: original?.id ?? 0,
    comment: text(values, 'comment'),
    destination: text(values, 'destination'),
    interface: text(values, 'interface'),
    gateway,
    table,
    metric: integer(values, 'metric', 0, 4294967295),
    on_link: Boolean(gateway) && checked(values, 'on_link'),
    enabled: checked(values, 'enabled'),
  };
}

function RouteEditor({
  route,
  wans,
  interfaces,
  save,
  close,
}: {
  route?: StaticRoute;
  wans: WanTable[];
  interfaces: InterfaceConfig[];
  save: (values: Values) => Promise<unknown>;
  close: () => void;
}) {
  const table = route?.table ?? 254;
  const wan = wans.find((wan) => wan.table === table);
  const fields: Field[] = [
    { name: 'comment', label: 'Description' },
    {
      name: 'destination',
      label: 'Destination address / prefix',
      required: true,
      placeholder: '198.51.100.10/32 or 2001:db8::/64',
      hint: 'A bare IP creates a host route. Use 0.0.0.0/0 or ::/0 for a default route.',
    },
    {
      name: 'interface',
      label: 'Route interface',
      type: 'select',
      required: true,
      options: [
        ...new Set([
          '',
          ...interfaces.map((iface) => iface.name),
          ...(route ? [route.interface] : []),
        ]),
      ].map((name) => ({
        value: name,
        label: interfaceDisplayName(name, interfaces),
      })),
      placeholder: 'Choose a configured interface',
      hint: 'For PPPoE, select its configured physical interface; the route uses ppp0.',
    },
    {
      name: 'gateway',
      label: 'Gateway',
      placeholder: 'Optional for a directly connected route',
      hint: 'Must be reachable on this interface and match the destination IP family.',
    },
    {
      name: 'table_mode',
      label: 'Routing table',
      type: 'select',
      options: [
        'Main',
        ...wans.map((wan) => ({
          value: `WAN: ${wan.name}`,
          label: `WAN: ${interfaceDisplayName(wan.name, interfaces)}`,
        })),
        'Custom table',
      ],
      hint: `Main (254) affects system routing. WAN tables: ${wans.map((wan) => `${interfaceDisplayName(wan.name, interfaces)} = ${wan.table}`).join(', ') || 'none'}. Custom tables need a matching system policy rule. IPv6 WAN policy routing is not configured here.`,
    },
    {
      name: 'table',
      label: 'Custom table ID',
      type: 'number',
      min: 1,
      max: 4294967295,
      required: true,
      when: (values) => values.table_mode === 'Custom table',
    },
    {
      name: 'metric',
      label: 'Metric',
      type: 'number',
      min: 0,
      max: 4294967295,
      required: true,
      hint: 'The longest matching prefix wins; among equal prefixes, lower metrics are preferred. Existing default routes may have metric 0.',
    },
    {
      name: 'on_link',
      label: 'Treat gateway as on-link',
      type: 'toggle',
      when: (values) => Boolean(values.gateway),
      hint: 'Use only when the gateway is directly reachable despite being outside the configured subnet.',
    },
    { name: 'enabled', label: 'Enabled', type: 'toggle' },
  ];
  return (
    <Editor
      title={route ? `Edit route #${route.id}` : 'Add system route'}
      fields={fields}
      initial={{
        comment: route?.comment ?? '',
        destination: route?.destination ?? '',
        interface: route?.interface ?? '',
        gateway: route?.gateway ?? '',
        table_mode:
          table === 254 ? 'Main' : wan ? `WAN: ${wan.name}` : 'Custom table',
        table: String(table),
        metric: String(route?.metric ?? 100),
        on_link: route?.on_link ?? false,
        enabled: route?.enabled ?? true,
      }}
      onSave={save}
      onClose={close}
    />
  );
}

export function Routes() {
  const config = useConfig();
  const interfaceName = (name: string) =>
    interfaceDisplayName(name, config.data?.interfaces.items);
  const settings = useApi<RoutingSettings>('/config/routing');
  const live = useApi<{ routes: KernelRoute[] }>('/monitor/routes', 10000);
  const ui = useUi();
  const [editing, setEditing] = useState<StaticRoute | 'new'>();
  const wans = settings.data?.wan_tables ?? [];
  const routes = settings.data?.routes ?? [];
  const operation = useSave(
    ({ route, method }: { route: StaticRoute; method: string }) =>
      write(
        `/config/routing/routes${method === 'POST' ? '' : `/${route.id}`}`,
        method === 'DELETE' ? undefined : route,
        method,
      ),
  );
  return (
    <>
      <PageHeader
        title="Routes"
        actions={
          <button
            className="primary"
            disabled={!settings.data || !config.data}
            onClick={() => setEditing('new')}
          >
            <Plus size={17} />
            Add route
          </button>
        }
      />
      <QueryNotice query={settings} />
      <QueryNotice query={config} />
      <div className="info-banner">
        <p>
          Routes in Main apply to LAN forwarding and router-originated traffic
          that uses system routing. “Route via WAN” uses that WAN’s table. Save
          first, then Apply to activate changes.
        </p>
      </div>
      <Card
        title="Saved system routes"
        subtitle="Persistent IPv4 and IPv6 routes on configured interfaces. Save changes, then Apply."
      >
        {settings.isPending ? (
          <Loading />
        ) : !routes.length ? (
          <Empty
            title="No saved routes"
            description="Add a destination, interface and optional gateway to control system routing."
          />
        ) : (
          <Table
            columns={[
              'Destination',
              'Gateway / interface',
              'Table / metric',
              'State',
              'Actions',
            ]}
          >
            {routes.map((route) => (
              <tr
                key={route.id}
                className={route.enabled ? '' : 'disabled-row'}
              >
                <td>
                  <strong className="mono">{route.destination}</strong>
                  <small className="cell-detail">
                    #{route.id}
                    {route.comment ? ` · ${route.comment}` : ''}
                  </small>
                </td>
                <td>
                  <span className="mono">{route.gateway || 'Direct'}</span>
                  <small className="cell-detail mono">
                    {interfaceName(route.interface)}
                    {route.on_link ? ' · gateway on-link' : ''}
                  </small>
                </td>
                <td>
                  {route.table === 254 ? 'main (254)' : route.table}
                  <small className="cell-detail">Metric {route.metric}</small>
                </td>
                <td>
                  <button
                    className="status-toggle"
                    disabled={operation.isPending}
                    aria-label={`${route.enabled ? 'Disable' : 'Enable'} route ${route.id}`}
                    onClick={() =>
                      operation.mutate({
                        route: { ...route, enabled: !route.enabled },
                        method: 'PUT',
                      })
                    }
                  >
                    <Badge tone={route.enabled ? 'success' : 'neutral'}>
                      {route.enabled ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </button>
                </td>
                <td>
                  <div className="row-actions">
                    <button
                      className="icon-button"
                      aria-label={`Edit route ${route.id}`}
                      onClick={() => setEditing(route)}
                    >
                      <Edit2 size={15} />
                    </button>
                    <button
                      className="icon-button danger-text"
                      disabled={operation.isPending}
                      aria-label={`Delete route ${route.id}`}
                      onClick={async () => {
                        if (
                          await ui.confirm({
                            title: 'Delete saved route?',
                            message:
                              'The route will be removed from the saved configuration. Apply to remove it from networking.',
                            label: 'Delete route',
                            dangerous: true,
                          })
                        )
                          operation.mutate({ route, method: 'DELETE' });
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
      <Card
        title="Live kernel routes"
        subtitle="Read-only view across all tables. Includes routes created by the system and other tools; this list does not prove saved changes were applied."
      >
        {live.isPending ? (
          <Loading />
        ) : !live.data?.routes.length ? (
          <Empty
            title="No live route data"
            description="Kernel routes appear here when available."
          />
        ) : (
          <Table
            columns={[
              'Family / destination',
              'Gateway / interface',
              'Table',
              'Metric / protocol',
            ]}
          >
            {live.data.routes.map((route, index) => (
              <tr key={index}>
                <td>
                  <span className="mono">{route.dst ?? 'default'}</span>
                  <small className="cell-detail">
                    {route.family}
                    {route.type ? ` · ${route.type}` : ''}
                  </small>
                </td>
                <td>
                  <span className="mono">
                    {route.gateway ??
                      (route.nexthops
                        ? route.nexthops
                            .map(
                              (hop) =>
                                `${hop.gateway ?? 'Direct'} (${hop.dev ? interfaceName(hop.dev) : '—'})`,
                            )
                            .join(', ')
                        : route.dev
                          ? 'Direct'
                          : '—')}
                  </span>
                  <small className="cell-detail mono">
                    {route.dev ? interfaceName(route.dev) : '—'}
                  </small>
                </td>
                <td>{route.table}</td>
                <td>
                  {route.metric ?? '—'}
                  <small className="cell-detail">{route.protocol ?? '—'}</small>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
      {editing && (
        <RouteEditor
          route={editing === 'new' ? undefined : editing}
          wans={wans}
          interfaces={config.data?.interfaces.items ?? []}
          close={() => setEditing(undefined)}
          save={async (values) => {
            const original = editing === 'new' ? undefined : editing;
            await operation.mutateAsync({
              route: routeFromValues(values, wans, original),
              method: original ? 'PUT' : 'POST',
            });
            setEditing(undefined);
          }}
        />
      )}
    </>
  );
}

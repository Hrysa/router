import type { Page } from '@playwright/test';
import type {
  Config,
  FirewallRule,
  InterfaceConfig,
  NftSet,
  PortForward,
  Reservation,
} from '../src/lib/types';

export async function mockRouter(
  page: Page,
  options: { authenticated?: boolean; passwordConfigured?: boolean } = {},
) {
  const config: Config = {
    interfaces: {
      items: [
        { name: 'eth0', label: 'Internet', method: 'dhcp' },
        {
          name: 'br0',
          label: 'Home network',
          method: 'static',
          static_config: { address: '192.168.1.1/24', dns: ['1.1.1.1'] },
          bridge_ports: ['eth1', 'eth2'],
        },
      ],
    },
    firewall: {
      default_policy: { input: 'drop', forward: 'drop', output: 'accept' },
      rules: {
        input: [
          {
            id: 17,
            comment: 'Established connections',
            action: 'accept',
            interfaces: ['br0'],
            state: ['established', 'related'],
            proto: ['tcp'],
            enabled: true,
            counter: true,
          },
        ],
        forward: [],
      },
      nat: {
        masquerade: [{ oif: 'eth0' }],
        port_forward: [
          {
            id: 2,
            proto: 'tcp',
            comment: 'Home server',
            interfaces: ['eth0'],
            target_port: 443,
            redirect_address: '192.168.1.10',
            redirect_port: 443,
            enabled: true,
          },
        ],
      },
      sets: [
        {
          name: 'trusted',
          set_type: 'ipv4_addr',
          elements: '192.168.1.0/24',
          interval: true,
        },
      ],
    },
    dhcp: {
      pools: [
        {
          name: 'home',
          subnet: '192.168.1.0/24',
          range: { start: '192.168.1.100', end: '192.168.1.200' },
          lease_time: '12h',
          domain: 'lan.local',
          dns_servers: ['192.168.1.1'],
          enabled: true,
        },
      ],
      static_leases: [
        {
          hostname: 'home-server',
          mac: 'aa:bb:cc:dd:ee:ff',
          ip: '192.168.1.10',
        },
      ],
    },
    hooks: { before_start: '', after_start: '' },
  };
  const state = {
    config,
    expired: false,
    passwordConfigured: options.passwordConfigured ?? true,
    raw: '{\n  // Keep this comment\n  "log": { "level": "info" }\n}\n',
    writes: [] as { path: string; method: string; body: unknown }[],
    unexpected: [] as string[],
  };
  await page.addInitScript((authenticated) => {
    localStorage.clear();
    localStorage.setItem('routerd_theme', 'light');
    if (authenticated) localStorage.setItem('routerd_token', 'mock-token');
  }, options.authenticated ?? true);
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = decodeURIComponent(url.pathname.slice(4));
    const method = request.method();
    const reply = (body: unknown, status = 200) =>
      route.fulfill({ status, json: body });
    if (path === '/auth/status')
      return reply({ password_configured: state.passwordConfigured });
    if (path === '/auth/setup') {
      state.passwordConfigured = true;
      return reply({ status: 'ok' });
    }
    if (path === '/auth/login') return reply({ token: 'mock-token' });
    if (
      state.expired ||
      request.headers().authorization !== 'Bearer mock-token'
    )
      return reply({ error: { message: 'unauthorized' } }, 401);
    const body = request.postData()
      ? request.headers()['content-type'] === 'text/plain'
        ? request.postData()
        : request.postDataJSON()
      : undefined;
    if (method !== 'GET') state.writes.push({ path, method, body });
    if (method === 'GET') {
      if (path === '/config') {
        const wire = structuredClone(state.config);
        if (!wire.interfaces.items.length)
          Reflect.deleteProperty(wire.interfaces, 'items');
        if (!wire.hooks.before_start && !wire.hooks.after_start)
          Reflect.deleteProperty(wire, 'hooks');
        return reply(wire);
      }
      if (path === '/monitor/system')
        return reply({
          hostname: 'home-router',
          uptime_seconds: 184920,
          uptime_human: '2d 3h 22m',
        });
      if (path === '/status')
        return reply({
          hostname: 'home-router',
          uptime: '184920.00',
          loadavg: { '1m': '0.18', '5m': '0.12', '15m': '0.09' },
        });
      if (path === '/status/system')
        return reply({
          memory: {
            total_kb: 4000000,
            used_kb: 1200000,
            available_kb: 2800000,
            usage_percent: 30,
          },
          cpu: { idle: 5000, total: 6000 },
        });
      if (path === '/monitor/interfaces')
        return reply({
          interfaces: state.config.interfaces.items.map((iface) => ({
            name: iface.name,
            up: true,
            mtu: 1500,
            mac: '00:11:22:33:44:55',
            rx_bytes: 12000000,
            tx_bytes: 3000000,
          })),
        });
      if (path === '/services')
        return reply({
          services: [
            {
              name: 'systemd-networkd',
              display_name: 'Networking',
              active: true,
              status: 'active',
              pid: 1032,
            },
            {
              name: 'kea-dhcp4-server',
              display_name: 'DHCP server',
              active: true,
              status: 'active',
              pid: 1042,
            },
            {
              name: 'sing-box',
              display_name: 'sing-box',
              active: false,
              status: 'inactive',
              pid: null,
            },
          ],
        });
      if (path === '/monitor/leases')
        return reply({
          leases: [
            {
              hostname: 'laptop',
              mac: '11:22:33:44:55:66',
              address: '192.168.1.101',
              expires: '2026-10-16 20:00',
            },
          ],
        });
      if (path === '/config/backups')
        return reply({
          backups: [
            {
              id: '20261016-120000-mock',
              created: '2026-10-16T12:00:00Z',
              size: 4096,
            },
          ],
        });
      if (path === '/singbox/config') return reply({ raw: state.raw });
      if (path === '/metrics') {
        const timestamps = Array.from(
          { length: 60 },
          (_, index) => 1792123200 + index * 5,
        );
        return reply({
          timestamps,
          interfaces: Object.fromEntries(
            ['eth0', 'br0'].map((name) => [
              name,
              {
                rx_bps: timestamps.map(
                  (_, index) =>
                    600000 + Math.sin(index / 4) * 220000 + index * 2500,
                ),
                tx_bps: timestamps.map(
                  (_, index) => 130000 + Math.sin(index / 5) * 80000,
                ),
                rx_pps: timestamps.map(() => 100),
                tx_pps: timestamps.map(() => 50),
              },
            ]),
          ),
          firewall: {
            '17': {
              chain: 'input',
              packets_per_sec: timestamps.map(() => 25),
              bytes_per_sec: timestamps.map(() => 5000),
            },
          },
        });
      }
    }
    if (path === '/config/validate') return reply({ valid: true, errors: [] });
    if (
      path === '/config/apply' ||
      /^\/config\/backups\/[^/]+\/restore$/.test(path)
    )
      return reply({
        success: true,
        errors: [],
        services_restarted: ['networking'],
        changeset: {},
      });
    if (path === '/config/dhcp') {
      state.config.dhcp = body as Config['dhcp'];
      return reply({ status: 'ok' });
    }
    if (path === '/config/hooks') {
      state.config.hooks = body as Config['hooks'];
      return reply({ status: 'ok' });
    }
    if (path === '/config/firewall') {
      state.config.firewall = body as Config['firewall'];
      return reply({ status: 'ok' });
    }
    if (path === '/singbox/config') {
      state.raw = String(body);
      return reply({ status: 'ok' });
    }
    if (path === '/config/dhcp/leases') {
      state.config.dhcp.static_leases.push(body as Reservation);
      return reply({ status: 'ok' });
    }
    if (path.startsWith('/config/dhcp/leases/') && method === 'DELETE') {
      state.config.dhcp.static_leases = state.config.dhcp.static_leases.filter(
        (lease) => lease.mac !== path.split('/').at(-1),
      );
      return reply({ status: 'ok' });
    }
    if (path === '/config/interfaces') {
      state.config.interfaces.items.push(body as InterfaceConfig);
      return reply({ status: 'ok' });
    }
    if (path.startsWith('/config/interfaces/')) {
      const name = path.split('/').at(-1);
      state.config.interfaces.items =
        method === 'DELETE'
          ? state.config.interfaces.items.filter((iface) => iface.name !== name)
          : state.config.interfaces.items.map((iface) =>
              iface.name === name ? (body as InterfaceConfig) : iface,
            );
      return reply({ status: 'ok' });
    }
    if (path.startsWith('/config/firewall/rules/')) {
      const id = Number(path.split('/')[4]);
      for (const chain of ['input', 'forward'] as const) {
        if (method === 'PUT')
          state.config.firewall.rules[chain] = state.config.firewall.rules[
            chain
          ].map((rule) => (rule.id === id ? (body as FirewallRule) : rule));
        if (method === 'DELETE')
          state.config.firewall.rules[chain] = state.config.firewall.rules[
            chain
          ].filter((rule) => rule.id !== id);
      }
      return reply({ status: 'ok' });
    }
    if (path === '/config/firewall/rules') {
      const chain =
        url.searchParams.get('chain') === 'forward' ? 'forward' : 'input';
      state.config.firewall.rules[chain].push({
        ...(body as FirewallRule),
        id: 18,
      });
      return reply({ status: 'ok' });
    }
    if (path === '/config/firewall/nat/port-forward') {
      state.config.firewall.nat.port_forward.push({
        ...(body as PortForward),
        id: 3,
      });
      return reply({ status: 'ok' });
    }
    if (path === '/config/firewall/sets') {
      state.config.firewall.sets = [
        ...(state.config.firewall.sets ?? []),
        body as NftSet,
      ];
      return reply({ status: 'ok' });
    }
    if (/^\/service\/[^/]+\/(start|stop|restart)$/.test(path))
      return reply({ status: 'ok' });
    state.unexpected.push(`${method} ${path}`);
    return reply(
      { error: { message: `Unmocked endpoint: ${method} ${path}` } },
      501,
    );
  });
  return state;
}

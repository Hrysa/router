import { useEffect, useRef, useState } from 'react';
import {
  useIsMutating,
  useMutation,
  useQueryClient,
} from '@tanstack/react-query';
import * as Dialog from '@radix-ui/react-dialog';
import {
  Activity,
  Box,
  Check,
  ChevronRight,
  Code,
  Grid,
  Layers,
  LogOut,
  Menu,
  Monitor,
  Moon,
  RefreshCw,
  Server,
  Settings,
  Shield,
  Sun,
  Wifi,
  Share2,
  X,
} from 'react-feather';
import { getToken, setToken, write } from './lib/api';
import { errorMessage } from './lib/format';
import { useApplyStatus, useSystem } from './lib/queries';
import { Badge, canLeave, useUi } from './lib/ui';
import type { ApplyResult } from './lib/types';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { Interfaces } from './pages/Interfaces';
import { Firewall } from './pages/Firewall';
import { Dhcp } from './pages/Dhcp';
import { Services } from './pages/Services';
import { Monitoring } from './pages/Monitoring';
import { ConfigEditors } from './pages/ConfigEditors';
import { Backups } from './pages/Backups';
import { Routes } from './pages/Routes';
import { Shaper } from './pages/Shaper';

const navigation = [
  { id: 'overview', label: 'Overview', icon: Grid, group: 'WORKSPACE' },
  { id: 'interfaces', label: 'Interfaces', icon: Layers },
  { id: 'routes', label: 'Routes', icon: Share2 },
  { id: 'shaper', label: 'Traffic shaping', icon: Activity },
  { id: 'firewall', label: 'Firewall', icon: Shield },
  { id: 'dhcp', label: 'DHCP & leases', icon: Wifi },
  { id: 'monitoring', label: 'Monitoring', icon: Activity },
  { id: 'services', label: 'Services', icon: Server, group: 'SYSTEM' },
  { id: 'singbox', label: 'sing-box', icon: Box },
  { id: 'hooks', label: 'Startup hooks', icon: Code },
  { id: 'backups', label: 'Configuration', icon: Settings },
];
const routeFromHash = () =>
  window.location.hash.replace(/^#\/?/, '').split('?')[0] || 'overview';
type Theme = 'light' | 'dark' | 'system';
function initialTheme(): Theme {
  const theme = localStorage.getItem('routerd_theme');
  return theme === 'light' || theme === 'dark' ? theme : 'system';
}

export function App() {
  const [token, setSession] = useState(getToken);
  const client = useQueryClient();
  const previous = useRef(token);
  useEffect(() => {
    const sync = () => {
      const next = getToken();
      if (previous.current !== next) {
        previous.current = next;
        client.clear();
        setSession(next);
      }
    };
    window.addEventListener('routerd-session', sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener('routerd-session', sync);
      window.removeEventListener('storage', sync);
    };
  }, [client]);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      document.documentElement.dataset.theme =
        theme === 'system' ? (media.matches ? 'dark' : 'light') : theme;
    };
    applyTheme();
    localStorage.setItem('routerd_theme', theme);
    media.addEventListener('change', applyTheme);
    return () => media.removeEventListener('change', applyTheme);
  }, [theme]);
  return token ? (
    <Shell key={token} theme={theme} setTheme={setTheme} />
  ) : (
    <Login />
  );
}

function Shell({
  theme,
  setTheme,
}: {
  theme: Theme;
  setTheme: (theme: Theme) => void;
}) {
  const [route, setRoute] = useState(routeFromHash);
  const routeRef = useRef(route);
  const [mobileOpen, setMobileOpen] = useState(false);
  const system = useSystem();
  const applyStatus = useApplyStatus();
  const client = useQueryClient();
  const ui = useUi();
  const writes = useIsMutating({ mutationKey: ['write'] });
  useEffect(() => {
    const navigate = () => {
      const next = routeFromHash();
      if (next === routeRef.current) return;
      if (!canLeave()) {
        history.replaceState(null, '', `#/${routeRef.current}`);
        return;
      }
      routeRef.current = next;
      setRoute(next);
      setMobileOpen(false);
      window.scrollTo(0, 0);
    };
    window.addEventListener('hashchange', navigate);
    return () => window.removeEventListener('hashchange', navigate);
  }, []);
  useEffect(() => {
    document.title = `${navigation.find((item) => item.id === route)?.label ?? 'Not found'} · routerd`;
  }, [route]);
  const apply = useMutation({
    mutationKey: ['write'],
    mutationFn: async () => {
      const result = await write<ApplyResult>('/config/apply');
      if (!result.success || result.errors?.length)
        throw new Error(result.errors?.join('\n') || 'Apply did not complete.');
      return result;
    },
    onSuccess: (result) => {
      ui.notify(
        `Configuration applied. ${result.services_restarted.length} service(s) reconciled.`,
      );
    },
    onError: (error) =>
      ui.notify(
        `${errorMessage(error)}\nApply can leave partial changes. Check the router before retrying.`,
        true,
      ),
    onSettled: () => client.invalidateQueries(),
  });
  const sidebar = (
    <>
      <a className="brand" href="#/overview">
        <span className="brand-symbol">
          <Layers size={24} />
        </span>
        <span>
          routerd<span className="brand-caption">NETWORK CONSOLE</span>
        </span>
      </a>
      <nav aria-label="Main navigation">
        {navigation.map(({ id, label, icon: Icon, group }) => (
          <div key={id}>
            {group && <div className="nav-group">{group}</div>}
            <a
              href={`#/${id}`}
              className={`nav-item ${route === id ? 'active' : ''}`}
              aria-current={route === id ? 'page' : undefined}
              onClick={() => setMobileOpen(false)}
            >
              <Icon size={18} />
              <span>{label}</span>
              {route === id && <span className="nav-active-dot" />}
            </a>
          </div>
        ))}
      </nav>
      <div className="sidebar-bottom">
        <div className="device-label">
          <span
            className={`status-dot ${system.isError ? 'status-error' : ''}`}
          />
          <div>
            <strong>{system.data?.hostname ?? 'Router'}</strong>
            <span>
              {system.isError
                ? 'Connection interrupted'
                : system.data
                  ? 'Management API reachable'
                  : 'Connecting…'}
            </span>
          </div>
        </div>
        <div className="theme-picker" aria-label="Color theme">
          {(
            [
              { value: 'light', icon: Sun },
              { value: 'system', icon: Monitor },
              { value: 'dark', icon: Moon },
            ] as const
          ).map(({ value, icon: Icon }) => (
            <button
              key={value}
              className={theme === value ? 'selected' : ''}
              aria-label={`${value} theme`}
              aria-pressed={theme === value}
              onClick={() => setTheme(value)}
            >
              <Icon size={16} />
            </button>
          ))}
        </div>
        <button
          className="signout"
          onClick={() => {
            if (canLeave()) setToken(null);
          }}
        >
          <LogOut size={16} />
          Sign out
        </button>
        <div className="sidebar-credit">Inspired by Yacd-meta</div>
      </div>
    </>
  );
  const known = navigation.some((item) => item.id === route);
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main-content')?.focus();
        }}
      >
        Skip to content
      </a>
      <aside className="sidebar">{sidebar}</aside>
      <div className="workspace">
        <div className="topbar">
          <div className="breadcrumb">
            <Dialog.Root open={mobileOpen} onOpenChange={setMobileOpen}>
              <Dialog.Trigger asChild>
                <button
                  className="icon-button mobile-menu"
                  aria-label="Open navigation"
                >
                  <Menu size={21} />
                </button>
              </Dialog.Trigger>
              <Dialog.Portal>
                <Dialog.Overlay className="dialog-overlay" />
                <Dialog.Content
                  className="mobile-sidebar"
                  aria-describedby={undefined}
                >
                  <Dialog.Title className="sr-only">Navigation</Dialog.Title>
                  <Dialog.Close
                    className="icon-button mobile-close"
                    aria-label="Close navigation"
                  >
                    <X size={20} />
                  </Dialog.Close>
                  {sidebar}
                </Dialog.Content>
              </Dialog.Portal>
            </Dialog.Root>
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>
              {navigation.find((item) => item.id === route)?.label ??
                'Not found'}
            </strong>
          </div>
          <div className="topbar-actions">
            <span className="save-status" id="apply-status">
              {applyStatus.isError ? (
                <Badge tone="warning">Unable to check Apply status</Badge>
              ) : !applyStatus.data ? (
                <span className="subtle">Checking saved configuration…</span>
              ) : applyStatus.data.pending ? (
                <Badge tone="warning">Apply required</Badge>
              ) : (
                <span className="subtle">No changes to apply</span>
              )}
            </span>
            <button
              className="icon-button"
              aria-label="Refresh all data"
              onClick={() => void client.invalidateQueries()}
            >
              <RefreshCw size={17} />
            </button>
            <button
              className="primary apply-button"
              aria-describedby="apply-status"
              disabled={
                writes > 0 ||
                applyStatus.isError ||
                applyStatus.isFetching ||
                !applyStatus.data?.pending
              }
              title={
                applyStatus.isError
                  ? 'Unable to check saved configuration. Refresh to retry.'
                  : undefined
              }
              onClick={async () => {
                if (
                  await ui.confirm({
                    title: 'Apply saved configuration?',
                    message:
                      'Only saved configuration is applied; unsaved editor text is not included. This reconciles live networking and firewall state, starting inactive services and restarting changed services. Unchanged nftables rules and running sing-box are skipped after a successful apply. You may lose access. Failure can leave partial changes; apply is not transactional.',
                    label: 'Apply configuration',
                    dangerous: true,
                  })
                )
                  apply.mutate();
              }}
            >
              <Check size={16} />
              <span>{apply.isPending ? 'Applying…' : 'Apply changes'}</span>
            </button>
          </div>
        </div>
        <main id="main-content" tabIndex={-1} key={route}>
          {route === 'overview' && <Overview />}
          {route === 'interfaces' && <Interfaces />}
          {route === 'routes' && <Routes />}
          {route === 'shaper' && <Shaper />}
          {route === 'firewall' && <Firewall />}
          {route === 'dhcp' && <Dhcp />}
          {route === 'monitoring' && <Monitoring />}
          {route === 'services' && <Services />}
          {(route === 'hooks' || route === 'singbox') && (
            <ConfigEditors mode={route} />
          )}
          {route === 'backups' && <Backups />}
          {!known && (
            <div className="empty">
              <h1>Page not found</h1>
              <a href="#/overview">Back to overview</a>
            </div>
          )}
          <footer className="page-footer">
            <span>
              routerd <span className="footer-dot">·</span> Your network, under
              control.
            </span>
            <span>Configuration saves do not apply automatically.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}

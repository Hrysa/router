import axios from 'axios';

const TOKEN_KEY = 'routerd_token';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach JWT to every request if available.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

// ── Auth ─────────────────────────────────────────────────────────────────────

export async function getAuthStatus() {
  const { data } = await api.get('/auth/status');
  return data;
}

export async function login(password: string) {
  const { data } = await api.post('/auth/login', { password });
  setToken(data.token);
  return data;
}

export async function setupPassword(password: string) {
  const { data } = await api.post('/auth/setup', { password });
  return data;
}

// ── Status ───────────────────────────────────────────────────────────────────

export async function getStatus() {
  const { data } = await api.get('/status');
  return data;
}

export async function getSystemStats() {
  const { data } = await api.get('/status/system');
  return data;
}

// ── Config ───────────────────────────────────────────────────────────────────

export async function getConfig() {
  const { data } = await api.get('/config');
  return data;
}

export async function replaceConfig(config: any) {
  const { data } = await api.put('/config', config);
  return data;
}

export async function patchConfig(section: string, patch: any) {
  const { data } = await api.post(`/config/${section}`, patch);
  return data;
}

export async function validateConfig(config: any) {
  const { data } = await api.post('/config/validate', config);
  return data;
}

export async function applyConfig() {
  const { data } = await api.post('/config/apply');
  return data;
}

export async function rollbackConfig() {
  const { data } = await api.post('/config/rollback');
  return data;
}

export async function listBackups() {
  const { data } = await api.get('/config/backups');
  return data;
}

export async function restoreBackup(id: string) {
  const { data } = await api.post(`/config/backups/${id}/restore`);
  return data;
}

// ── Firewall Rules CRUD ──────────────────────────────────────────────────────

export async function listFirewallRules() {
  const { data } = await api.get('/config/firewall/rules');
  return data;
}

export async function addFirewallRule(rule: any, chain?: 'input' | 'forward') {
  const url = chain ? `/config/firewall/rules?chain=${chain}` : '/config/firewall/rules';
  const { data } = await api.post(url, rule);
  return data;
}

export async function updateFirewallRule(id: number, rule: any) {
  const { data } = await api.put(`/config/firewall/rules/${id}`, rule);
  return data;
}

export async function deleteFirewallRule(id: number) {
  const { data } = await api.delete(`/config/firewall/rules/${id}`);
  return data;
}

export async function moveFirewallRule(id: number, direction: 'up' | 'down') {
  const { data } = await api.post(`/config/firewall/rules/${id}/move`, { direction });
  return data;
}

export async function getFirewallStats() {
  const { data } = await api.get('/firewall/stats');
  return data;
}

// ── Firewall NAT CRUD ───────────────────────────────────────────────────────

export async function listNatRules() {
  const { data } = await api.get('/config/firewall/nat');
  return data;
}

export async function addPortForward(rule: any) {
  const { data } = await api.post('/config/firewall/nat/port-forward', rule);
  return data;
}

export async function updatePortForward(id: number, rule: any) {
  const { data } = await api.put(`/config/firewall/nat/port-forward/${id}`, rule);
  return data;
}

export async function deletePortForward(id: number) {
  const { data } = await api.delete(`/config/firewall/nat/port-forward/${id}`);
  return data;
}

// ── Interfaces CRUD ─────────────────────────────────────────────────────────

export async function listInterfaces() {
  const { data } = await api.get('/config/interfaces');
  return data;
}

export async function createInterface(iface: any) {
  const { data } = await api.post('/config/interfaces', iface);
  return data;
}

export async function updateInterface(name: string, iface: any) {
  const { data } = await api.put(`/config/interfaces/${encodeURIComponent(name)}`, iface);
  return data;
}

export async function deleteInterface(name: string) {
  const { data } = await api.delete(`/config/interfaces/${encodeURIComponent(name)}`);
  return data;
}

// ── Services ─────────────────────────────────────────────────────────────────

export async function listServices() {
  const { data } = await api.get('/services');
  return data;
}

export async function getServiceStatus(name: string) {
  const { data } = await api.get(`/service/${name}/status`);
  return data;
}

export async function startService(name: string) {
  const { data } = await api.post(`/service/${name}/start`);
  return data;
}

export async function stopService(name: string) {
  const { data } = await api.post(`/service/${name}/stop`);
  return data;
}

export async function restartService(name: string) {
  const { data } = await api.post(`/service/${name}/restart`);
  return data;
}

// ── Monitoring ───────────────────────────────────────────────────────────────

export async function getSystemMonitor() {
  const { data } = await api.get('/monitor/system');
  return data;
}

export async function getInterfaces() {
  const { data } = await api.get('/monitor/interfaces');
  return data;
}

export async function getTrafficStats() {
  const { data } = await api.get('/monitor/traffic');
  return data;
}

export async function getConnections() {
  const { data } = await api.get('/monitor/connections');
  return data;
}

export async function getLeases() {
  const { data } = await api.get('/monitor/leases');
  return data;
}

// ── nftables Sets CRUD ──────────────────────────────────────────────────────

export async function listNftSets() {
  const { data } = await api.get('/config/firewall/sets');
  return data;
}

export async function addNftSet(set: any) {
  const { data } = await api.post('/config/firewall/sets', set);
  return data;
}

export async function updateNftSet(name: string, set: any) {
  const { data } = await api.put(`/config/firewall/sets/${encodeURIComponent(name)}`, set);
  return data;
}

export async function deleteNftSet(name: string) {
  const { data } = await api.delete(`/config/firewall/sets/${encodeURIComponent(name)}`);
  return data;
}

// ── DHCP ────────────────────────────────────────────────────────────────────

export async function listDhcpLeases() {
  const { data } = await api.get('/config/dhcp/leases');
  return data;
}

export async function addDhcpLease(lease: any) {
  const { data } = await api.post('/config/dhcp/leases', lease);
  return data;
}

export async function deleteDhcpLease(mac: string) {
  const { data } = await api.delete(`/config/dhcp/leases/${encodeURIComponent(mac)}`);
  return data;
}

export default api;

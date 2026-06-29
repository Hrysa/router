import { writable } from 'svelte/store';
import { getConfig, getStatus, listServices, getToken, clearToken } from './api';

// ── Auth store ───────────────────────────────────────────────────────────────

export const isAuthenticated = writable(!!getToken());
export const username = writable('admin');

export function logout() {
  clearToken();
  isAuthenticated.set(false);
  window.location.hash = '/';
}

export function markAuthenticated() {
  isAuthenticated.set(true);
}

// ── Config store ─────────────────────────────────────────────────────────────

export const config = writable<any>(null);
export const configLoading = writable(false);

export async function loadConfig() {
  configLoading.set(true);
  try {
    const data = await getConfig();
    config.set(data);
  } catch (e) {
    console.error('Failed to load config:', e);
  } finally {
    configLoading.set(false);
  }
}

// ── Status store ─────────────────────────────────────────────────────────────

export const status = writable<any>(null);
export const statusLoading = writable(false);

export async function loadStatus() {
  statusLoading.set(true);
  try {
    const data = await getStatus();
    status.set(data);
  } catch (e) {
    console.error('Failed to load status:', e);
  } finally {
    statusLoading.set(false);
  }
}

// ── Services store ───────────────────────────────────────────────────────────

export const services = writable<any[]>([]);
export const servicesLoading = writable(false);

export async function loadServices() {
  servicesLoading.set(true);
  try {
    const data = await listServices();
    services.set(data.services || []);
  } catch (e) {
    console.error('Failed to load services:', e);
  } finally {
    servicesLoading.set(false);
  }
}

// ── Notification store ───────────────────────────────────────────────────────

export interface Notification {
  id: number;
  type: 'success' | 'error' | 'info' | 'warning';
  message: string;
}

let nextId = 0;
export const notifications = writable<Notification[]>([]);

export function notify(type: Notification['type'], message: string) {
  const id = nextId++;
  notifications.update((n) => [...n, { id, type, message }]);
  setTimeout(() => {
    notifications.update((n) => n.filter((item) => item.id !== id));
  }, 5000);
}

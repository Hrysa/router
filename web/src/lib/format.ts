import type { InterfaceConfig, PortSpec } from './types';
export function bytes(value: number | undefined, rate = false): string {
  if (value === undefined || !Number.isFinite(value)) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  const exponent = Math.min(
    Math.floor(Math.log(Math.max(value, 1)) / Math.log(1024)),
    units.length - 1,
  );
  return `${(value / 1024 ** exponent).toLocaleString(undefined, { maximumFractionDigits: exponent ? 1 : 0 })} ${units[exponent]}${rate ? '/s' : ''}`;
}
export function macIdentity(value: string): string {
  return value.replaceAll('-', ':').toLowerCase();
}
export function list(value: string): string[] {
  return value
    .split(/[,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}
export function parsePort(value: string): PortSpec | undefined {
  const input = value.trim();
  if (!input) return undefined;
  if (/^@[a-zA-Z_][a-zA-Z0-9_]*$/.test(input)) return input;
  const port = (part: string) => {
    if (!/^\d+$/.test(part.trim()))
      throw new Error('Ports must be whole numbers from 1 to 65535.');
    const result = Number(part.trim());
    if (result < 1 || result > 65535)
      throw new Error('Ports must be between 1 and 65535.');
    return result;
  };
  if (input.includes('-')) {
    const parts = input.split('-');
    if (parts.length !== 2)
      throw new Error('Use a single ordered range, such as 8000-8080.');
    const start = port(parts[0]);
    const end = port(parts[1]);
    if (start > end)
      throw new Error('The start port must not exceed the end port.');
    return { start, end };
  }
  if (input.includes(',')) return input.split(',').map(port);
  return port(input);
}
export function formatPort(value?: PortSpec): string {
  if (value === undefined) return '';
  if (typeof value === 'number' || typeof value === 'string')
    return String(value);
  if (Array.isArray(value)) return value.join(', ');
  return `${value.start}-${value.end}`;
}
export function role(iface: InterfaceConfig): string {
  if (iface.vlan_id !== undefined) return 'VLAN';
  return iface.method !== 'static' || iface.static_config?.gateway
    ? 'WAN'
    : 'LAN';
}
export function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : 'An unexpected error occurred.';
}
export function latest(values?: number[]): number | undefined {
  return values?.at(-1);
}
export function uptime(seconds: number | undefined): string {
  if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0)
    return '—';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return `${days}d ${hours}h`;
}
export function passwordError(password: string): string | undefined {
  const length = new TextEncoder().encode(password).length;
  if (!length) return 'Enter a password.';
  if (length > 72) return 'Passwords must not exceed 72 UTF-8 bytes.';
  return undefined;
}

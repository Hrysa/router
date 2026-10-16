import type { Config } from './types';

export const TOKEN_KEY = 'routerd_token';
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export function getToken() {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(token: string | null) {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
  window.dispatchEvent(new Event('routerd-session'));
}
export async function request<Result>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    raw?: boolean;
    signal?: AbortSignal;
  } = {},
): Promise<Result> {
  const token = getToken();
  const response = await fetch(`/api${path}`, {
    method: options.method ?? 'GET',
    signal: options.signal,
    credentials: 'omit',
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.body !== undefined
        ? { 'Content-Type': options.raw ? 'text/plain' : 'application/json' }
        : {}),
    },
    body:
      options.body === undefined
        ? undefined
        : options.raw
          ? String(options.body)
          : JSON.stringify(options.body),
  });
  if (token !== getToken())
    throw new ApiError('Session changed. Please sign in again.', 401);
  if (response.status === 401 && token) setToken(null);
  const text = await response.text();
  if (response.ok && token !== getToken())
    throw new ApiError('Session changed. Please sign in again.', 401);
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(
      'The server returned an unexpected response.',
      response.status,
    );
  }
  if (!response.ok) {
    const payload = data as {
      error?: {
        message?: string;
        details?: { field: string; message: string }[];
      };
    } | null;
    const details = payload?.error?.details
      ?.map((detail) => `${detail.field}: ${detail.message}`)
      .join('\n');
    throw new ApiError(
      details ||
        payload?.error?.message ||
        `Request failed (${response.status}).`,
      response.status,
    );
  }
  return data as Result;
}
export function write<Result = unknown>(
  path: string,
  body?: unknown,
  method = 'POST',
) {
  return request<Result>(path, { method, body });
}
export const encoded = encodeURIComponent;

export function normalizeConfig(config: Config): Config {
  return {
    ...config,
    interfaces: { ...config.interfaces, items: config.interfaces.items ?? [] },
    routing: { ...config.routing, routes: config.routing?.routes ?? [] },
    shaper: { ...config.shaper, profiles: config.shaper?.profiles ?? [] },
    hooks: config.hooks ?? { before_start: '', after_start: '' },
  };
}
export async function getConfig(signal?: AbortSignal): Promise<Config> {
  return normalizeConfig(await request<Config>('/config', { signal }));
}

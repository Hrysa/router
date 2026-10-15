import { afterAll, beforeEach, expect, mock, test } from 'bun:test';
import { ApiError, getToken, request, setToken } from '../src/lib/api';

const originalFetch = globalThis.fetch;
const originalStorage = Object.getOwnPropertyDescriptor(
  globalThis,
  'localStorage',
);
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
const storage = new Map<string, string>();
Object.defineProperty(globalThis, 'localStorage', {
  configurable: true,
  value: {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
  },
});
Object.defineProperty(globalThis, 'window', {
  configurable: true,
  value: new EventTarget(),
});
beforeEach(() => {
  storage.clear();
});
afterAll(() => {
  globalThis.fetch = originalFetch;
  if (originalStorage)
    Object.defineProperty(globalThis, 'localStorage', originalStorage);
  else Reflect.deleteProperty(globalThis, 'localStorage');
  if (originalWindow)
    Object.defineProperty(globalThis, 'window', originalWindow);
  else Reflect.deleteProperty(globalThis, 'window');
});

test('attaches bearer credentials and propagates cancellation', async () => {
  setToken('test-token');
  const controller = new AbortController();
  const fetcher = mock(async () => Response.json({ ok: true }));
  globalThis.fetch = fetcher as unknown as typeof fetch;
  await request('/config', { signal: controller.signal });
  expect(fetcher.mock.calls[0]).toEqual([
    '/api/config',
    {
      method: 'GET',
      credentials: 'omit',
      signal: controller.signal,
      headers: { Authorization: 'Bearer test-token' },
      body: undefined,
    },
  ]);
});
test('raw JSONC is not stringified or stripped of comments', async () => {
  const fetcher = mock(async () => Response.json({ status: 'ok' }));
  globalThis.fetch = fetcher as unknown as typeof fetch;
  const raw = '{\n // preserved\n "log": {}\n}';
  await request('/singbox/config', { method: 'PUT', body: raw, raw: true });
  expect(fetcher.mock.calls[0]).toEqual([
    '/api/singbox/config',
    {
      method: 'PUT',
      signal: undefined,
      credentials: 'omit',
      headers: { 'Content-Type': 'text/plain' },
      body: raw,
    },
  ]);
});
test('reports field validation details', async () => {
  globalThis.fetch = mock(async () =>
    Response.json(
      {
        error: {
          message: 'validation failed',
          details: [
            { field: 'interfaces.items.0.name', message: 'invalid interface' },
          ],
        },
      },
      { status: 422 },
    ),
  ) as unknown as typeof fetch;
  await expect(request('/config')).rejects.toThrow(
    'interfaces.items.0.name: invalid interface',
  );
});
test('401 clears the session and notifies the app', async () => {
  setToken('expired');
  let cleared = false;
  const listener = () => {
    cleared = !getToken();
  };
  window.addEventListener('routerd-session', listener);
  globalThis.fetch = mock(async () =>
    Response.json({ error: { message: 'unauthorized' } }, { status: 401 }),
  ) as unknown as typeof fetch;
  await expect(request('/config')).rejects.toBeInstanceOf(ApiError);
  expect(getToken()).toBeNull();
  expect(cleared).toBe(true);
  window.removeEventListener('routerd-session', listener);
});
test('discards responses from a previous session', async () => {
  setToken('old-session');
  globalThis.fetch = mock(async () => {
    setToken('new-session');
    return Response.json({ secret: 'do not show' });
  }) as unknown as typeof fetch;
  await expect(request('/config')).rejects.toThrow('Session changed');
  expect(getToken()).toBe('new-session');
});
test('non-JSON errors do not leak response content', async () => {
  globalThis.fetch = mock(
    async () => new Response('<html>proxy error</html>', { status: 502 }),
  ) as unknown as typeof fetch;
  await expect(request('/config')).rejects.toThrow('unexpected response');
});

test('discards a body completed after the session changed', async () => {
  setToken('old-session');
  const response = Response.json({ secret: 'do not show' });
  response.text = async () => {
    setToken('new-session');
    return '{"secret":"do not show"}';
  };
  globalThis.fetch = mock(async () => response) as unknown as typeof fetch;
  await expect(request('/config')).rejects.toThrow('Session changed');
});

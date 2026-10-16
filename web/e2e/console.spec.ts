import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { mockRouter } from './router';

async function navigate(page: Page, label: string) {
  const menu = page.getByRole('button', { name: 'Open navigation' });
  if (await menu.isVisible()) await menu.click();
  await page
    .getByRole('navigation')
    .filter({ visible: true })
    .getByRole('link', { name: label, exact: true })
    .click();
}

test('overview, all routes, themes and responsive layout', async ({
  page,
}, info) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const state = await mockRouter(page);
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Your network, at a glance.' }),
  ).toBeVisible();
  await expect(
    page.getByRole('img', { name: /Internet traffic/ }),
  ).toBeVisible();
  await expect(page.locator('.uptime-value')).toHaveText('2d 3h');
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath('overview-light.png'),
    fullPage: true,
  });
  const menu = page.getByRole('button', { name: 'Open navigation' });
  if (await menu.isVisible()) await menu.click();
  await page
    .getByRole('button', { name: 'dark theme', exact: true })
    .filter({ visible: true })
    .click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  if (await page.getByRole('button', { name: 'Close navigation' }).isVisible())
    await page.getByRole('button', { name: 'Close navigation' }).click();
  await page.screenshot({
    path: info.outputPath('overview-dark.png'),
    fullPage: true,
  });
  for (const [label, title] of [
    ['Interfaces', 'Interfaces'],
    ['Routes', 'Routes'],
    ['Firewall', 'Firewall'],
    ['DHCP & leases', 'DHCP & leases'],
    ['Monitoring', 'Monitoring'],
    ['Services', 'Services'],
    ['sing-box', 'sing-box'],
    ['Startup hooks', 'Startup hooks'],
    ['Configuration', 'Configuration'],
  ]) {
    await navigate(page, label);
    await expect(
      page.getByRole('heading', { name: title, exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
  }
  expect(errors).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('interface save is separate from Apply, with confirmed activation', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/interfaces');
  await expect(
    page.getByRole('button', { name: 'Apply changes' }),
  ).toBeDisabled();
  await page.getByRole('button', { name: 'Add interface' }).click();
  await page.getByLabel('Interface name', { exact: false }).fill('vlan10');
  await page.getByLabel('Display label').fill('Guest network');
  await page.getByLabel('Address / prefix').fill('192.168.10.1/24');
  await page.getByLabel('VLAN ID').fill('10');
  await page
    .getByRole('textbox', { name: 'VLAN parent', exact: true })
    .fill('eth1');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.getByText('Guest network', { exact: true })).toBeVisible();
  expect(state.writes.map((entry) => entry.path)).toEqual([
    '/config/interfaces',
  ]);
  expect(state.config.interfaces.items.at(-1)?.vlan_id).toBe(10);
  await page.getByRole('button', { name: 'Apply changes' }).click();
  await expect(
    page.getByRole('dialog', { name: 'Apply saved configuration?' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(state.writes.some((entry) => entry.path === '/config/apply')).toBe(
    false,
  );
  await page.getByRole('button', { name: 'Apply changes' }).click();
  await page
    .getByRole('button', { name: 'Apply configuration', exact: true })
    .click();
  await expect
    .poll(() => state.writes.some((entry) => entry.path === '/config/apply'))
    .toBe(true);
  await expect(
    page.getByRole('button', { name: 'Apply changes' }),
  ).toBeDisabled();
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached();
});

test('firewall editor preserves rule ID and array states', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/firewall');
  await page.getByRole('button', { name: 'Edit rule 17', exact: true }).click();
  await page
    .getByLabel('Description', { exact: true })
    .fill('Allow established traffic');
  await expect(page.getByLabel('Connection states')).toHaveValue(
    'established, related',
  );
  await page.getByLabel('Destination ports').fill('443, 8443');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.input[0]).toMatchObject({
    id: 17,
    state: ['established', 'related'],
    dport: [443, 8443],
  });
  expect(state.writes[0].path).toBe('/config/firewall/rules/17');
});

test('port forwards validate ports and named sets can be created', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/firewall');
  await page.getByRole('tab', { name: /Port forwarding/ }).click();
  await page.getByRole('button', { name: 'Add port forward' }).click();
  await page.getByLabel('Description', { exact: true }).fill('Test forward');
  await page
    .getByRole('textbox', { name: 'Ingress interfaces', exact: false })
    .fill('eth0');
  await page.getByLabel('WAN destination ports').fill('9000-8000');
  await page.getByLabel('Forward to address').fill('192.168.1.20');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText(
    'start port must not exceed',
  );
  expect(state.writes).toEqual([]);
  await page.getByLabel('WAN destination ports').fill('8000-9000');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.nat.port_forward.at(-1)?.target_port).toEqual({
    start: 8000,
    end: 9000,
  });
  await page.getByRole('tab', { name: /Named sets/ }).click();
  await page.getByRole('button', { name: 'Add set', exact: true }).click();
  await page.getByLabel('Set name').fill('test_ports');
  await page.getByLabel('Element type').fill('inet_service');
  await page.getByLabel('Elements', { exact: true }).fill('80\n443');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.getByText('@test_ports', { exact: true })).toBeVisible();
});

test('reservation deletion survives a later pool save', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/dhcp');
  await page
    .getByRole('button', { name: 'Delete reservation aa:bb:cc:dd:ee:ff' })
    .click();
  await page
    .getByRole('button', { name: 'Delete reservation', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'No reserved addresses' }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Edit pool', exact: true }).click();
  await page.getByLabel('Lease duration').fill('6h');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.dhcp.static_leases).toEqual([]);
  expect(state.config.dhcp.pools?.[0].lease_time).toBe('6h');
});

test('raw sing-box comments, draft protection and explicit live controls', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/singbox');
  const deployed = state.deployedRaw;
  const value = '{\n // Still a comment\n "log": { "level": "debug" }\n}';
  await page.getByLabel('sing-box JSONC configuration').fill(value);
  page.once('dialog', (dialog) => dialog.dismiss());
  await navigate(page, 'Overview');
  await expect(
    page.getByRole('heading', { name: 'sing-box', exact: true }),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect.poll(() => state.raw).toBe(value);
  expect(state.config.singbox?.config).toBe(value);
  expect(state.deployedRaw).toBe(deployed);
  expect(state.writes.map((entry) => entry.path)).toEqual(['/singbox/config']);
  await navigate(page, 'Services');
  await page
    .getByRole('button', { name: 'Restart', exact: true })
    .first()
    .click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(state.writes.some((entry) => entry.path.startsWith('/service/'))).toBe(
    false,
  );
  await navigate(page, 'Configuration');
  await page
    .getByRole('button', { name: 'Restore & apply', exact: true })
    .click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(state.writes.some((entry) => entry.path.endsWith('/restore'))).toBe(
    false,
  );
});

test('401 removes protected data and shows login', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/interfaces');
  await expect(page.getByText('Home network', { exact: true })).toBeVisible();
  state.expired = true;
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  const refresh = page.getByRole('button', { name: 'Refresh all data' });
  if (await refresh.isVisible()) await refresh.click();
  else await page.waitForTimeout(5500);
  await expect(
    page.getByRole('heading', { name: 'Welcome back' }),
  ).toBeVisible();
  await expect(
    page.getByText('Home network', { exact: true }),
  ).not.toBeVisible();
  expect(
    await page.evaluate(() => localStorage.getItem('routerd_token')),
  ).toBeNull();
});

test('first-time setup and UTF-8 password limits', async ({ page }) => {
  const state = await mockRouter(page, {
    authenticated: false,
    passwordConfigured: false,
  });
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Set up your console' }),
  ).toBeVisible();
  await page
    .getByLabel('Administrator password', { exact: true })
    .fill('密'.repeat(25));
  await page
    .getByLabel('Confirm password', { exact: true })
    .fill('密'.repeat(25));
  await page.getByRole('button', { name: 'Create password & sign in' }).click();
  await expect(page.getByRole('alert')).toHaveText(
    'Passwords must not exceed 72 UTF-8 bytes.',
  );
  expect(state.passwordConfigured).toBe(false);
  await page
    .getByLabel('Administrator password', { exact: true })
    .fill('a secure test password');
  await page
    .getByLabel('Confirm password', { exact: true })
    .fill('a secure test password');
  await page.getByRole('button', { name: 'Create password & sign in' }).click();
  await expect(
    page.getByRole('heading', { name: 'Your network, at a glance.' }),
  ).toBeVisible();
  expect(state.passwordConfigured).toBe(true);
});

test('empty Rust config fields and network failures do not crash the shell', async ({
  page,
}) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const state = await mockRouter(page);
  state.config.interfaces.items = [];
  state.config.dhcp = { static_leases: [] };
  await page.route('**/api/metrics', (route) =>
    route.fulfill({
      status: 503,
      json: { error: { message: 'Metrics temporarily unavailable' } },
    }),
  );
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'No configured interfaces' }),
  ).toBeVisible();
  await expect(page.getByText('Metrics temporarily unavailable')).toBeVisible();
  await navigate(page, 'Interfaces');
  await expect(
    page.getByRole('heading', { name: 'Build your first connection' }),
  ).toBeVisible();
  await navigate(page, 'Startup hooks');
  await expect(page.getByLabel('Before startup script')).toHaveValue('');
  expect(errors).toEqual([]);
});

test('firewall tab survives refresh and browser history', async ({ page }) => {
  await mockRouter(page);
  await page.goto('/#/firewall');
  await page.getByRole('tab', { name: /Forward rules/ }).click();
  await expect(page).toHaveURL(/#\/firewall\?tab=forward$/);
  await page.reload();
  await expect(
    page.getByRole('tab', { name: /Forward rules/ }),
  ).toHaveAttribute('aria-selected', 'true');
  await page.getByRole('tab', { name: /Named sets/ }).click();
  await page.goBack();
  await expect(
    page.getByRole('tab', { name: /Forward rules/ }),
  ).toHaveAttribute('aria-selected', 'true');
  await page.goForward();
  await expect(page.getByRole('tab', { name: /Named sets/ })).toHaveAttribute(
    'aria-selected',
    'true',
  );
});

test('common interface MTU and MSS settings persist without applying', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/interfaces');
  await page
    .getByRole('button', { name: 'Edit Home network', exact: true })
    .click();
  await page.getByLabel('Device MTU', { exact: true }).fill('1500');
  await page.getByLabel('TCP MSS path MTU', { exact: true }).fill('1492');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(
    state.config.interfaces.items.find((iface) => iface.name === 'br0'),
  ).toMatchObject({ mtu: 1500, mss_clamp_mtu: 1492 });
  await page
    .getByRole('button', { name: 'Edit Home network', exact: true })
    .click();
  await expect(page.getByLabel('Device MTU', { exact: true })).toHaveValue(
    '1500',
  );
  await expect(
    page.getByLabel('TCP MSS path MTU', { exact: true }),
  ).toHaveValue('1492');
  expect(state.writes.some((entry) => entry.path === '/config/apply')).toBe(
    false,
  );
  expect(state.unexpected).toEqual([]);
});

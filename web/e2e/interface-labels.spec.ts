import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('traffic selectors display labels while selecting device-keyed metrics', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/');
  const overview = page.getByRole('combobox', {
    name: 'Traffic interface',
    exact: true,
  });
  await expect(overview.locator('option')).toHaveText([
    'Internet',
    'Home network',
  ]);
  await overview.selectOption({ label: 'Home network' });
  await expect(overview).toHaveValue('br0');
  await expect(
    page.getByRole('img', { name: /^Home network traffic\./ }),
  ).toBeVisible();
  await expect(
    page.locator('.stat-caption').filter({ hasText: 'Home network' }),
  ).toHaveCount(2);

  await page.goto('/#/monitoring');
  const monitor = page.getByLabel('Monitor interface', { exact: true });
  await expect(monitor.locator('option')).toHaveText([
    'Internet',
    'Home network',
  ]);
  await monitor.selectOption({ label: 'Home network' });
  await expect(monitor).toHaveValue('br0');
  await expect(
    page.getByRole('img', { name: /^Home network traffic history\./ }),
  ).toBeVisible();
  await expect(
    page.getByRole('table').first().locator('tbody tr td:first-child'),
  ).toHaveText(['Internet', 'Home network']);
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('firewall and NAT summaries use labels for ingress, egress, and selected WANs', async ({
  page,
}) => {
  const state = await mockRouter(page);
  Object.assign(state.config.firewall.rules.input[0], {
    interfaces: ['br0', 'tun99'],
    interfaces_invert: true,
    oif: 'eth0',
  });
  state.config.firewall.rules.forward = [
    { id: 18, action: 'accept', interfaces: ['br0'], route_via: 'eth0' },
  ];
  state.config.firewall.nat.masquerade = [];
  const original = structuredClone(state.config);
  await page.goto('/#/firewall');
  const input = page.getByRole('row').filter({
    has: page.getByRole('button', { name: 'Edit rule 17', exact: true }),
  });
  await expect(
    input.getByRole('cell').nth(1).locator('span').first(),
  ).toHaveText('not Home network, tun99 → Internet');
  await page.getByRole('tab', { name: /Forward rules/ }).click();
  const forward = page.getByRole('row').filter({
    has: page.getByRole('button', { name: 'Edit rule 18', exact: true }),
  });
  await expect(
    forward.getByRole('cell').nth(1).locator('span').first(),
  ).toHaveText('Home network → WAN Internet');
  await expect(
    page.getByText(
      /WAN selection has no configured masquerade for rule #18 \(Internet\)/,
    ),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Edit rule 18', exact: true }).click();
  await expect(
    page.getByText(/No masquerade is configured on Internet\./),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.getByRole('tab', { name: /Port forwarding/ }).click();
  const nat = page.getByRole('row').filter({ hasText: 'Home server' });
  await expect(nat.getByRole('cell').nth(1)).toHaveText('Internet');
  expect(state.config).toEqual(original);
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('live multipath routes and shaping statistics resolve PPPoE labels and unknown devices', async ({
  page,
}) => {
  const state = await mockRouter(page);
  state.config.interfaces.items.push({
    name: 'eth2',
    label: 'Backup uplink',
    method: 'pppoe',
  });
  await page.route('**/api/monitor/routes', (route) =>
    route.fulfill({
      json: {
        routes: [
          {
            family: 'ipv4',
            dst: 'default',
            table: 'main',
            nexthops: [{ gateway: '192.0.2.1', dev: 'ppp0' }, { dev: 'tun99' }],
          },
        ],
      },
    }),
  );
  await page.route('**/api/monitor/shaper', (route) =>
    route.fulfill({
      json: {
        timestamp_ms: Date.now(),
        reconnect_active: true,
        profiles: [
          { id: 1, interface: 'ppp0' },
          { id: 2, interface: 'tun99' },
        ],
      },
    }),
  );
  await page.goto('/#/routes');
  await expect(
    page.getByRole('table').locator('tbody tr td').nth(1),
  ).toContainText('192.0.2.1 (Backup uplink), Direct (tun99)');
  await page.goto('/#/shaper');
  const interfaces = page.getByRole('table').locator('tbody tr td:first-child');
  await expect(interfaces).toHaveText([
    'Backup uplinkegress',
    'Backup uplinkingress via IFB',
    'tun99egress',
    'tun99ingress via IFB',
  ]);
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('interface diagnostics and editor titles use labels without replacing device identifiers', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/interfaces');
  const detected = page
    .getByRole('table')
    .last()
    .locator('tbody tr td:first-child');
  await expect(detected).toHaveText(['Interneteth0', 'Home networkbr0']);
  await page
    .getByRole('button', { name: 'Edit Internet', exact: true })
    .click();
  await expect(
    page.getByRole('dialog', { name: 'Edit Internet', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('textbox', { name: /^Interface name/ }),
  ).toHaveValue('eth0');
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('PPPoE and custom selections retain device names when saved without editing', async ({
  page,
}) => {
  const state = await mockRouter(page);
  state.config.interfaces.items[0].method = 'pppoe';
  state.config.firewall.rules.input[0].interfaces = ['ppp0', 'tun99'];
  await page.goto('/#/firewall');
  await page.getByRole('button', { name: 'Edit rule 17', exact: true }).click();
  const input = page.getByRole('textbox', {
    name: 'Ingress interfaces',
    exact: false,
  });
  await expect(input).toHaveValue('Internet, tun99');
  await page
    .getByRole('button', { name: 'Choose ingress interfaces', exact: true })
    .click();
  const options = page.getByRole('group', {
    name: 'Ingress interfaces options',
    exact: true,
  });
  await expect(
    options
      .locator('label')
      .filter({ hasText: 'ppp0' })
      .getByRole('checkbox', { name: 'Internet', exact: true }),
  ).toBeChecked();
  await expect(
    options.getByRole('checkbox', { name: 'tun99', exact: true }),
  ).toBeChecked();
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.input[0].interfaces).toEqual([
    'ppp0',
    'tun99',
  ]);
  expect(state.unexpected).toEqual([]);
});

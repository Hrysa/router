import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('interface quick fill supports multiple, detected-only and custom names', async ({
  page,
}, info) => {
  const state = await mockRouter(page);
  state.config.firewall.rules.input[0].interfaces = ['br0', 'ppp0'];
  await page.route('**/api/monitor/interfaces', (route) =>
    route.fulfill({
      json: {
        interfaces: [
          {
            name: 'eth0',
            up: true,
            mtu: 1500,
            mac: '',
            rx_bytes: 0,
            tx_bytes: 0,
          },
          {
            name: 'wlan0',
            up: false,
            mtu: 1500,
            mac: '',
            rx_bytes: 0,
            tx_bytes: 0,
          },
        ],
      },
    }),
  );
  await page.goto('/#/firewall');
  await page.getByRole('button', { name: 'Edit rule 17', exact: true }).click();
  await page
    .getByRole('button', { name: 'Choose ingress interfaces', exact: true })
    .click();
  const ingress = page.getByRole('group', {
    name: 'Ingress interfaces options',
    exact: true,
  });
  await expect(
    ingress.getByRole('checkbox', { name: 'ppp0', exact: true }),
  ).toBeChecked();
  await expect(ingress.getByText('Internet', { exact: false })).toBeVisible();
  await ingress
    .getByRole('checkbox', { name: 'Internet', exact: true })
    .check();
  await ingress.getByRole('checkbox', { name: 'wlan0', exact: true }).check();
  await ingress
    .getByRole('checkbox', { name: 'Home network', exact: true })
    .uncheck();
  const input = page.getByRole('textbox', {
    name: 'Ingress interfaces',
    exact: false,
  });
  await expect(input).toHaveValue('ppp0, Internet, wlan0');
  await input.focus();
  await expect(input).toHaveValue('ppp0, eth0, wlan0');
  await page.screenshot({
    path: info.outputPath('interface-options.png'),
    fullPage: true,
  });
  await input.fill('ppp0, eth0, wlan0, tun99');
  await input.press('Escape');
  await expect(ingress).not.toBeVisible();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page
    .getByRole('button', { name: 'Choose egress interface', exact: true })
    .click();
  const egress = page.getByRole('group', {
    name: 'Egress interface options',
    exact: true,
  });
  await egress.getByRole('checkbox', { name: 'Internet', exact: true }).check();
  await egress
    .getByRole('checkbox', { name: 'Home network', exact: true })
    .check();
  await expect(
    page.getByRole('textbox', { name: 'Egress interface', exact: true }),
  ).toHaveValue('Home network');
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.input[0]).toMatchObject({
    id: 17,
    interfaces: ['ppp0', 'eth0', 'wlan0', 'tun99'],
    oif: 'br0',
  });
  expect(state.writes.map((entry) => entry.path)).toEqual([
    '/config/firewall/rules/17',
  ]);
  expect(state.unexpected).toEqual([]);
});

test('bridge member and VLAN parent suggestions preserve interface payloads', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/interfaces');
  await page
    .getByRole('button', { name: 'Add interface', exact: true })
    .click();
  await page
    .getByRole('textbox', { name: 'Interface name', exact: false })
    .fill('br10');
  await page
    .getByRole('textbox', { name: 'Address / prefix', exact: false })
    .fill('192.168.10.1/24');
  await page
    .getByRole('button', { name: 'Choose bridge members', exact: true })
    .click();
  const members = page.getByRole('group', {
    name: 'Bridge members options',
    exact: true,
  });
  await members.getByRole('checkbox', { name: 'eth1', exact: true }).check();
  await members.getByRole('checkbox', { name: 'eth2', exact: true }).check();
  await page.getByLabel('VLAN ID').fill('10');
  await page
    .getByRole('button', { name: 'Choose vlan parent', exact: true })
    .click();
  const parent = page.getByRole('group', {
    name: 'VLAN parent options',
    exact: true,
  });
  await parent.getByRole('checkbox', { name: 'Internet', exact: true }).check();
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.interfaces.items.at(-1)).toMatchObject({
    name: 'br10',
    bridge_ports: ['eth1', 'eth2'],
    vlan_id: 10,
    parent: 'eth0',
  });
  expect(state.writes.map((entry) => entry.path)).toEqual([
    '/config/interfaces',
  ]);
});

test('masquerade quick fill works when live interface detection fails', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.route('**/api/monitor/interfaces', (route) =>
    route.fulfill({
      status: 503,
      json: { error: { message: 'Detection unavailable' } },
    }),
  );
  await page.goto('/#/firewall');
  await page
    .getByRole('button', { name: 'Policies & NAT', exact: true })
    .click();
  await page
    .getByRole('button', {
      name: 'Choose masquerade egress interfaces',
      exact: true,
    })
    .click();
  const options = page.getByRole('group', {
    name: 'Masquerade egress interfaces options',
    exact: true,
  });
  await options
    .getByRole('checkbox', { name: 'Internet', exact: true })
    .uncheck();
  await options
    .getByRole('checkbox', { name: 'Home network', exact: true })
    .check();
  await page
    .getByRole('textbox', { name: 'Masquerade egress interfaces', exact: true })
    .fill('br0, ppp0');
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.nat.masquerade).toEqual([
    { oif: 'br0' },
    { oif: 'ppp0' },
  ]);
  expect(state.config.firewall.nat.port_forward).toHaveLength(1);
  expect(state.writes.map((entry) => entry.path)).toEqual(['/config/firewall']);
});

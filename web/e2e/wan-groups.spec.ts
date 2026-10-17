import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('WAN groups save tiers and weights, preserve drafts, and appear in firewall targets', async ({ page }) => {
  const state = await mockRouter(page);
  state.config.interfaces.items.push({ name: 'eth3', label: 'Backup', method: 'dhcp' });
  await page.goto('/#/wan-groups');
  await page.getByRole('button', { name: 'Add group', exact: true }).click();
  await page.getByLabel('Group name', { exact: false }).fill('Internet pool');
  await page.getByRole('checkbox', { name: 'Include Internet' }).check();
  await page.getByLabel('eth0 weight', { exact: false }).fill('3');
  await page.getByRole('checkbox', { name: 'Include Backup' }).check();
  await page.getByLabel('eth3 tier', { exact: false }).fill('2');
  // A status poll while editing must not replace the draft.
  await page.waitForTimeout(2200);
  await expect(page.getByLabel('Group name', { exact: false })).toHaveValue('Internet pool');
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.wan_groups?.[0]).toMatchObject({ id: 1, name: 'Internet pool', members: [{ interface: 'eth0', tier: 1, weight: 3 }, { interface: 'eth3', tier: 2, weight: 1 }] });
  await page.getByRole('button', { name: 'Edit group Internet pool', exact: true }).click();
  await expect(page.getByLabel('eth3 tier', { exact: false })).toHaveValue('2');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await page.goto('/#/firewall');
  await page.getByRole('tab', { name: /Forward rules/ }).click();
  await page.getByRole('button', { name: 'Add rule', exact: true }).click();
  await page.getByRole('textbox', { name: 'Ingress interfaces', exact: false }).fill('br0');
  await page.getByLabel('Route via WAN', { exact: true }).selectOption({ label: 'Group: Internet pool' });
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.forward[0].route_via).toBe('group:1');
  expect(state.writes.some((write) => write.path === '/config/apply')).toBe(false);
  expect(state.unexpected).toEqual([]);
});

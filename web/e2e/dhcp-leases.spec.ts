import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('active lease deletion confirms, refreshes leases, and preserves saved config', async ({ page }) => {
  const state = await mockRouter(page);
  const saved = JSON.stringify(state.config);
  await page.goto('/#/dhcp');
  const action = page.getByRole('button', { name: 'Delete active lease 192.168.1.101', exact: true });
  await action.click();
  await expect(page.getByRole('dialog')).toContainText('immediately');
  expect(state.writes).toEqual([]);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(state.writes).toEqual([]);
  await action.click();
  await page.getByRole('button', { name: 'Delete lease now', exact: true }).click();
  await expect(action).toHaveCount(0);
  expect(state.activeLeases).toEqual([]);
  expect(state.writes).toEqual([{ path: '/dhcp/leases/192.168.1.101', method: 'DELETE', body: undefined }]);
  expect(JSON.stringify(state.config)).toBe(saved);
  expect(state.unexpected).toEqual([]);
});

test('Kea deletion failures leave the active lease visible', async ({ page }) => {
  const state = await mockRouter(page);
  state.leaseDeleteError = true;
  await page.goto('/#/dhcp');
  const action = page.getByRole('button', { name: 'Delete active lease 192.168.1.101', exact: true });
  await action.click();
  await page.getByRole('button', { name: 'Delete lease now', exact: true }).click();
  await expect(page.getByText('Kea lease deletion requires the lease_cmds hook.', { exact: true })).toBeVisible();
  await expect(action).toBeEnabled();
  expect(state.activeLeases).toHaveLength(1);
  expect(state.unexpected).toEqual([]);
});

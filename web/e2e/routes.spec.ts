import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('routes save separately from Apply and delete only saved routes', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/routes');
  await expect(page.getByText('192.0.2.1', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Add route', exact: true }).click();
  await page.getByLabel('Destination address / prefix').fill('198.51.100.10/32');
  await page.getByLabel('Route interface', { exact: true }).selectOption('eth0');
  await page.getByLabel('Gateway', { exact: true }).fill('192.0.2.1');
  await page.getByLabel('Routing table', { exact: true }).selectOption('WAN: eth0');
  await expect(page.getByLabel('Destination address / prefix')).toHaveValue('198.51.100.10/32');
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.routing.routes[0]).toMatchObject({ destination: '198.51.100.10/32', table: 100, interface: 'eth0', metric: 100 });
  expect(state.writes.map((write) => write.path)).toEqual(['/config/routing/routes']);
  expect(state.unexpected).toEqual([]);
  await page.getByRole('button', { name: 'Delete route 1', exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Delete saved route?' })).toBeVisible();
  await page.getByRole('button', { name: 'Delete route', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No saved routes' })).toBeVisible();
  expect(state.config.routing.routes).toEqual([]);
  expect(state.writes.some((write) => write.path === '/config/apply')).toBe(false);
});

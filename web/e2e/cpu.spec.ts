import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('Overview calculates CPU usage from successive samples and recovers after a reset', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/');
  await expect(page.getByText('30%', { exact: true })).toBeVisible();
  const card = page.locator('.stat-card').filter({ hasText: 'CPU usage' });
  await expect(card.locator('.stat-value')).toHaveText('—');
  await expect(card).toContainText('Waiting for CPU samples');
  state.cpu = { idle: 5150, total: 6200 };
  await expect(card.locator('.stat-value')).toHaveText('25.0%');
  await expect(card).toContainText('Across all CPU cores');
  state.cpu = { idle: 10, total: 20 };
  await expect(card.locator('.stat-value')).toHaveText('—');
  state.cpu = { idle: 30, total: 120 };
  await expect(card.locator('.stat-value')).toHaveText('80.0%');
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('Overview clears CPU usage when counters become unavailable', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/');
  await expect(page.getByText('30%', { exact: true })).toBeVisible();
  const value = page
    .locator('.stat-card')
    .filter({ hasText: 'CPU usage' })
    .locator('.stat-value');
  await expect(value).toHaveText('—');
  state.cpu = { idle: 5150, total: 6200 };
  await expect(value).toHaveText('25.0%');
  state.cpu = {};
  await expect(value).toHaveText('—');
  expect(state.unexpected).toEqual([]);
});

test('Overview clears stale CPU usage when the stats request fails', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/');
  await expect(page.getByText('30%', { exact: true })).toBeVisible();
  const value = page
    .locator('.stat-card')
    .filter({ hasText: 'CPU usage' })
    .locator('.stat-value');
  state.cpu = { idle: 5150, total: 6200 };
  await expect(value).toHaveText('25.0%');
  await page.route('**/api/status/system', (route) =>
    route.fulfill({
      status: 503,
      json: { error: { message: 'System stats unavailable' } },
    }),
  );
  await expect(
    page.getByText('System stats unavailable', { exact: true }),
  ).toBeVisible({ timeout: 8000 });
  await expect(value).toHaveText('—');
  expect(state.unexpected).toEqual([]);
});

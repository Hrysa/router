import { expect, test } from '@playwright/test';
import { mockRouter } from './router';
test('shaper profiles save disabled by default and reopen with rates intact', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/shaper');
  await page.getByRole('button', { name: 'Add profile', exact: true }).click();
  await page.getByLabel('Interface', { exact: true }).selectOption('eth0');
  await page.getByLabel('Upload (Mbit/s)', { exact: true }).fill('19');
  await page.getByLabel('Download (Mbit/s)', { exact: true }).fill('190');
  await expect(page.getByRole('checkbox', { name: /^Enabled/ })).not.toBeChecked();
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.shaper?.profiles[0]).toMatchObject({ id: 1, enabled: false, upload_kbit: 19000, download_kbit: 190000 });
  await page.getByRole('button', { name: 'Edit shaper 1', exact: true }).click();
  await expect(page.getByLabel('Upload (Mbit/s)', { exact: true })).toHaveValue('19');
  await expect(page.getByLabel('Download (Mbit/s)', { exact: true })).toHaveValue('190');
  expect(state.writes.some((w) => w.path === '/config/apply')).toBe(false);
  expect(state.unexpected).toEqual([]);
});

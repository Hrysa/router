import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('default Reject policies save without replacing rules or applying', async ({ page }) => {
  const state = await mockRouter(page);
  const original = JSON.stringify(state.config.firewall.rules);
  await page.goto('/#/firewall');
  await page.getByRole('button', { name: 'Policies & NAT', exact: true }).click();
  for (const chain of ['Input', 'Forward', 'Output'])
    await page.getByLabel(`${chain} policy`, { exact: true }).selectOption('reject');
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.default_policy).toEqual({ input: 'reject', forward: 'reject', output: 'reject' });
  expect(JSON.stringify(state.config.firewall.rules)).toBe(original);
  expect(state.writes.some((write) => write.path === '/config/apply')).toBe(false);
  expect(state.unexpected).toEqual([]);
});

test('TPROXY clears incompatible fields and NAT offers only supported protocols', async ({ page }) => {
  const state = await mockRouter(page);
  await page.goto('/#/firewall');
  await page.getByRole('button', { name: 'Edit rule 17', exact: true }).click();
  await page.getByRole('textbox', { name: 'Egress interface', exact: false }).fill('eth0');
  await page.getByLabel('Rate limit', { exact: true }).fill('10/second');
  await page.getByLabel('Action', { exact: true }).selectOption('tproxy');
  await expect(page.getByRole('textbox', { name: 'Egress interface', exact: false })).toHaveCount(0);
  await expect(page.getByLabel('Rate limit', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Save configuration', exact: true }).click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.input[0].oif).toBeUndefined();
  expect(state.config.firewall.rules.input[0].rate).toBeUndefined();
  await page.getByRole('tab', { name: /Port forwarding/ }).click();
  await page.getByRole('button', { name: 'Add port forward', exact: true }).click();
  await expect(page.getByLabel('Protocol', { exact: true }).locator('option')).toHaveText(['tcp', 'udp', 'tcp+udp']);
  expect(state.unexpected).toEqual([]);
});

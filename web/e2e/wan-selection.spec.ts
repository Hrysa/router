import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('WAN rules default to preserving internal routes and persist an explicit opt-out', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/#/firewall');
  await page.getByRole('tab', { name: /Forward rules/ }).click();
  await page.getByRole('button', { name: 'Add rule', exact: true }).click();
  await page
    .getByRole('textbox', { name: 'Ingress interfaces', exact: false })
    .fill('br0');
  await page
    .getByLabel('Route via WAN', { exact: true })
    .selectOption({ label: 'Internet' });
  const preserve = page.getByRole('checkbox', {
    name: /^Preserve internal routes/,
  });
  await expect(preserve).toBeChecked();
  await preserve.uncheck();
  await expect(
    page.getByText(/Internal traffic may go to the WAN gateway/),
  ).toBeVisible();
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(state.config.firewall.rules.forward[0]).toMatchObject({
    route_via: 'eth0',
    preserve_internal_routes: false,
  });
  await page.getByRole('button', { name: 'Edit rule 18', exact: true }).click();
  await expect(preserve).not.toBeChecked();
  expect(state.writes.some((write) => write.path === '/config/apply')).toBe(
    false,
  );
  expect(state.unexpected).toEqual([]);
});

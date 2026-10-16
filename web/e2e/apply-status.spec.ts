import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

test('unchanged configuration disables Apply regardless of old browser flags', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.addInitScript(() =>
    localStorage.setItem('routerd_pending_changes', 'true'),
  );
  await page.goto('/');
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached();
  await expect(
    page.getByRole('button', { name: 'Apply changes' }),
  ).toBeDisabled();
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

test('saving and reverting raw sing-box configuration updates Apply availability', async ({
  page,
}) => {
  const state = await mockRouter(page);
  const original = state.raw;
  const deployed = state.deployedRaw;
  await page.goto('/#/singbox');
  const editor = page.getByLabel('sing-box JSONC configuration');
  const apply = page.getByRole('button', { name: 'Apply changes' });
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached();
  await editor.fill(`${original}// added comment\n`);
  await expect(apply).toBeDisabled();
  for (const value of [`${original}// added comment\n`, original]) {
    await editor.fill(value);
    await page
      .getByRole('button', { name: 'Save configuration', exact: true })
      .click();
    const dialog = page.getByRole('dialog', {
      name: 'Save sing-box configuration?',
    });
    await dialog
      .getByRole('button', { name: 'Save configuration', exact: true })
      .click();
    await expect(dialog).not.toBeVisible();
    expect(state.config.singbox?.config).toBe(value);
    expect(state.deployedRaw).toBe(deployed);
    if (value === original) {
      await expect(
        page.getByText('No changes to apply', { exact: true }),
      ).toBeAttached();
      await expect(apply).toBeDisabled();
    } else {
      await expect(apply).toBeEnabled();
    }
  }
  expect(state.raw).toBe(original);
  expect(state.writes.map((entry) => entry.path)).toEqual([
    '/singbox/config',
    '/singbox/config',
  ]);
  expect(state.unexpected).toEqual([]);
});

test('sing-box saves to routerd configuration and deploys only on Apply', async ({
  page,
}) => {
  const state = await mockRouter(page);
  const original = state.deployedRaw;
  const saved = '// saved in YAML\n{"log":{"level":"debug"}}\n';
  await page.goto('/#/singbox');
  await page.getByLabel('sing-box JSONC configuration').fill(saved);
  await page
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  const dialog = page.getByRole('dialog', {
    name: 'Save sing-box configuration?',
  });
  await expect(dialog).toContainText('config.yml');
  await dialog
    .getByRole('button', { name: 'Save configuration', exact: true })
    .click();
  await expect(dialog).not.toBeVisible();
  expect(state.config.singbox?.config).toBe(saved);
  expect(state.deployedRaw).toBe(original);
  await page.reload();
  await expect(page.getByLabel('sing-box JSONC configuration')).toHaveValue(
    saved,
  );
  await page.getByRole('button', { name: 'Apply changes' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Apply configuration', exact: true })
    .click();
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached();
  expect(state.deployedRaw).toBe(saved);
  expect(state.unexpected).toEqual([]);
});

test('polling notices another client saving and reverting configuration', async ({
  page,
}) => {
  const state = await mockRouter(page);
  await page.goto('/');
  const apply = page.getByRole('button', { name: 'Apply changes' });
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached();
  const original = state.config.firewall.blackhole;
  state.config.firewall.blackhole = [...(original ?? []), '203.0.113.1'];
  await expect(apply).toBeEnabled({ timeout: 12000 });
  state.config.firewall.blackhole = original;
  await expect(
    page.getByText('No changes to apply', { exact: true }),
  ).toBeAttached({ timeout: 12000 });
  await expect(apply).toBeDisabled();
  expect(state.writes).toEqual([]);
});

test('first and failed applies stay available until successful completion', async ({
  page,
}) => {
  const state = await mockRouter(page);
  state.applied = null;
  state.applyError = true;
  await page.goto('/');
  const apply = page.getByRole('button', { name: 'Apply changes' });
  for (const fail of [true, false]) {
    state.applyError = fail;
    await expect(apply).toBeEnabled();
    await apply.click();
    await page
      .getByRole('dialog')
      .getByRole('button', { name: 'Apply configuration', exact: true })
      .click();
    if (fail) {
      await expect(page.getByRole('alert')).toContainText('Apply failed');
      await expect(apply).toBeEnabled();
    } else {
      await expect(
        page.getByText('No changes to apply', { exact: true }),
      ).toBeAttached();
      await expect(apply).toBeDisabled();
    }
  }
  expect(
    state.writes.filter((entry) => entry.path === '/config/apply'),
  ).toHaveLength(2);
  expect(state.unexpected).toEqual([]);
});

test('status loading and failures disable Apply until status can be checked', async ({
  page,
  isMobile,
}) => {
  const state = await mockRouter(page);
  state.applied = null;
  let fail = true;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route('**/api/config/apply/status', async (route) => {
    await held;
    if (fail)
      return route.fulfill({
        status: 503,
        json: { error: { message: 'Status unavailable' } },
      });
    return route.fallback();
  });
  await page.goto('/');
  const apply = page.getByRole('button', { name: 'Apply changes' });
  await expect(
    page.getByText('Checking saved configuration…', { exact: true }),
  ).toBeAttached();
  await expect(apply).toBeDisabled();
  release();
  await expect(
    page.getByText('Unable to check Apply status', { exact: true }),
  ).toBeAttached();
  await expect(apply).toBeDisabled();
  fail = false;
  if (!isMobile)
    await page.getByRole('button', { name: 'Refresh all data' }).click();
  await expect(apply).toBeEnabled({ timeout: 12000 });
  expect(state.writes).toEqual([]);
  expect(state.unexpected).toEqual([]);
});

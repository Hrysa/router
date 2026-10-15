import { expect, test } from '@playwright/test';
import type { Locator } from '@playwright/test';
import { mockRouter } from './router';

async function expectInputFocus(control: Locator, ringColor: string) {
  await expect(control).toBeFocused();
  await expect(control).toHaveCSS('outline-style', 'none');
  await expect(control).toHaveCSS('border-color', 'rgb(59, 130, 246)');
  await expect(control).toHaveCSS('box-shadow', `${ringColor} 0px 0px 0px 3px`);
}

for (const theme of ['light', 'dark']) {
  test(`${theme} text controls use Yacd-style focus without an offset outline`, async ({
    page,
  }, info) => {
    const state = await mockRouter(page);
    await page.goto('/#/firewall');
    await page.evaluate((value) => {
      document.documentElement.dataset.theme = value;
    }, theme);
    await page
      .getByRole('button', { name: 'Policies & NAT', exact: true })
      .click();
    const ringColor =
      theme === 'dark' ? 'rgba(59, 130, 246, 0.2)' : 'rgb(224, 237, 255)';
    const policy = page.getByLabel('Input policy', { exact: true });
    await policy.focus();
    await expectInputFocus(policy, ringColor);

    const interfaces = page.getByRole('textbox', {
      name: 'Masquerade egress interfaces',
      exact: true,
    });
    await interfaces.scrollIntoViewIfNeeded();
    const before = await interfaces.boundingBox();
    await interfaces.click();
    await expectInputFocus(interfaces, ringColor);
    expect(await interfaces.boundingBox()).toEqual(before);
    await interfaces.press('Escape');
    await expectInputFocus(interfaces, ringColor);
    await page.screenshot({
      path: info.outputPath(`input-focus-${theme}.png`),
      fullPage: true,
    });

    const blocked = page.getByRole('textbox', {
      name: 'Blocked addresses',
      exact: true,
    });
    await blocked.click();
    await expectInputFocus(blocked, ringColor);
    await blocked.press('Shift+Tab');
    const toggle = page.getByRole('button', {
      name: 'Choose masquerade egress interfaces',
      exact: true,
    });
    await expect(toggle).toBeFocused();
    await expect(toggle).toHaveCSS('outline-style', 'solid');
    await expect(toggle).toHaveCSS('outline-width', '2px');
    expect(state.writes).toEqual([]);
    expect(state.unexpected).toEqual([]);
  });
}

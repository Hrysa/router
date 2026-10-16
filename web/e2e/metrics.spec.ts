import { expect, test } from '@playwright/test';
import { mockRouter } from './router';

for (const view of ['overview', 'monitoring']) {
  test(`${view} refreshes traffic samples and live counters every two seconds`, async ({
    page,
  }) => {
    const state = await mockRouter(page);
    const paths = ['/api/metrics', '/api/monitor/interfaces'];
    if (view === 'overview') paths.push('/api/status/system');
    const responses = new Map(paths.map((path) => [path, [] as number[]]));
    page.on('response', (response) => {
      const timestamps = responses.get(new URL(response.url()).pathname);
      if (response.ok()) timestamps?.push(Date.now());
    });
    await page.goto(`/#/${view}`);
    await expect(
      page.getByText(
        view === 'overview'
          ? 'Updates every 2 seconds'
          : '2-second samples · 30-minute history',
        { exact: true },
      ),
    ).toBeAttached();
    await expect
      .poll(
        () =>
          [...responses.values()].every((timestamps) => timestamps.length >= 3),
        { timeout: 6500 },
      )
      .toBe(true);
    for (const timestamps of responses.values()) {
      expect(timestamps.at(-1)! - timestamps.at(-2)!).toBeLessThan(3500);
    }
    expect(state.writes).toEqual([]);
    expect(state.unexpected).toEqual([]);
  });
}

test('empty traffic history describes the two-second sampling interval', async ({
  page,
}) => {
  await mockRouter(page);
  await page.route('**/api/metrics', (route) =>
    route.fulfill({
      json: {
        timestamps: [],
        interfaces: {
          eth0: { rx_bps: [], tx_bps: [], rx_pps: [], tx_pps: [] },
        },
        firewall: {},
      },
    }),
  );
  await page.goto('/');
  await expect(
    page.getByText(
      'The router collects a sample every two seconds. History appears after two samples.',
      { exact: true },
    ),
  ).toBeVisible();
});

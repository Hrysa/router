<script lang="ts">
  import { onMount } from 'svelte';
  import { getSystemMonitor, getInterfaces, getLeases, getMetrics } from '../lib/api';
  import { notify } from '../lib/stores';
  import UPlotChart from '../lib/UPlotChart.svelte';

  let system = $state<any>(null);
  let interfaces = $state<any[]>([]);
  let leases = $state<any[]>([]);
  let metrics = $state<any>(null);
  let loading = $state(true);

  onMount(() => {
    let interval: ReturnType<typeof setInterval>;

    async function load() {
      try {
        const [systemData, ifaceData, leaseData, metricsData] = await Promise.all([
          getSystemMonitor(),
          getInterfaces(),
          getLeases(),
          getMetrics(),
        ]);
        system = systemData;
        interfaces = ifaceData.interfaces || [];
        leases = leaseData.leases || [];
        metrics = metricsData;
      } catch (e) {
        notify('error', 'Failed to load monitoring data');
      } finally {
        loading = false;
      }
    }

    load();
    interval = setInterval(async () => {
      try {
        metrics = await getMetrics();
      } catch (e) {
        // silently fail background poll
      }
    }, 5000);

    return () => clearInterval(interval);
  });

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function formatBitsPerSec(bps: number | null | undefined): string {
    if (bps == null || Number.isNaN(bps) || bps === 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    const i = Math.min(Math.floor(Math.log(bps) / Math.log(k)), sizes.length - 1);
    return parseFloat((bps / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  const ifaceColors = [
    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#06b6d4',
  ];

  const ifaceChart = $derived(buildIfaceChart(metrics));
  const firewallChart = $derived(buildFirewallChart(metrics));

  function buildIfaceChart(data: any): { options: any; data: any } | null {
    if (!data?.timestamps?.length) return null;

    const names = Object.keys(data.interfaces || {}).sort();
    const timestamps = data.timestamps;

    const series: any[] = [{
      label: 'Time',
      value: (_u: any, v: number | null | undefined) =>
        v == null || Number.isNaN(v) ? '-' : new Date(v * 1000).toLocaleTimeString(),
    }];
    const aligned: any[] = [timestamps];

    names.forEach((name, idx) => {
      const color = ifaceColors[idx % ifaceColors.length];
      const s = data.interfaces[name];
      series.push({
        label: `${name} RX`,
        stroke: color,
        width: 1.5,
        value: (_u: any, v: number) => formatBitsPerSec(v),
      });
      series.push({
        label: `${name} TX`,
        stroke: color,
        width: 1.5,
        dash: [4, 4],
        value: (_u: any, v: number) => formatBitsPerSec(v),
      });
      aligned.push(s.rx_bps.map((v: number) => v * 8));
      aligned.push(s.tx_bps.map((v: number) => v * 8));
    });

    return {
      options: {
        title: 'Interface Traffic',
        width: 800,
        height: 300,
        series,
        axes: [
          { label: 'Time', values: (_u: any, vals: number[]) => vals.map((v) => new Date(v * 1000).toLocaleTimeString()) },
          { label: 'Throughput', values: (_u: any, vals: number[]) => vals.map(formatBitsPerSec) },
        ],
        scales: { x: { time: true }, y: {} },
      },
      data: aligned,
    };
  }

  function buildFirewallChart(data: any): { options: any; data: any } | null {
    if (!data?.timestamps?.length) return null;

    const ids = Object.keys(data.firewall || {}).sort((a, b) => parseInt(a) - parseInt(b));
    const timestamps = data.timestamps;

    const series: any[] = [{
      label: 'Time',
      value: (_u: any, v: number | null | undefined) =>
        v == null || Number.isNaN(v) ? '-' : new Date(v * 1000).toLocaleTimeString(),
    }];
    const aligned: any[] = [timestamps];

    ids.forEach((id, idx) => {
      const color = ifaceColors[idx % ifaceColors.length];
      const s = data.firewall[id];
      series.push({
        label: `[${id}] ${s.chain}`,
        stroke: color,
        width: 1.5,
        value: (_u: any, v: number | null | undefined) =>
          v == null || Number.isNaN(v) ? '-' : `${v.toFixed(0)} pkt/s`,
      });
      aligned.push(s.packets_per_sec);
    });

    return {
      options: {
        title: 'Firewall Traffic',
        width: 800,
        height: 300,
        series,
        axes: [
          { label: 'Time', values: (_u: any, vals: number[]) => vals.map((v) => new Date(v * 1000).toLocaleTimeString()) },
          { label: 'Packets/s' },
        ],
        scales: { x: { time: true }, y: {} },
      },
      data: aligned,
    };
  }
</script>

<div class="max-w-6xl">
  <h2 class="h2 mb-6">Monitoring</h2>

  {#if loading}
    <div class="placeholder animate-pulse h-32"></div>
  {:else}
    <section class="mb-6">
      <h3 class="h4 mb-3">System</h3>
      <div class="grid grid-cols-2 gap-4">
        <div class="card p-4">
          <div class="text-sm text-surface-500 mb-1">Hostname</div>
          <div class="text-xl font-semibold">{system?.hostname || '-'}</div>
        </div>
        <div class="card p-4">
          <div class="text-sm text-surface-500 mb-1">Uptime</div>
          <div class="text-xl font-semibold">{system?.uptime_human || '-'}</div>
        </div>
      </div>
    </section>

    <section class="mb-6">
      <h3 class="h4 mb-3">Interface Traffic</h3>
      {#if ifaceChart}
        <div class="card p-2">
          <UPlotChart data={ifaceChart.data} options={ifaceChart.options} />
        </div>
      {:else}
        <p class="text-surface-500 italic">No traffic data yet</p>
      {/if}
    </section>

    <section class="mb-6">
      <h3 class="h4 mb-3">Firewall Traffic</h3>
      {#if firewallChart}
        <div class="card p-2">
          <UPlotChart data={firewallChart.data} options={firewallChart.options} />
        </div>
      {:else}
        <p class="text-surface-500 italic">No firewall data yet</p>
      {/if}
    </section>

    <section class="mb-6">
      <h3 class="h4 mb-3">Interfaces</h3>
      {#if interfaces.length === 0}
        <p class="text-surface-500 italic">No interfaces detected</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>MAC</th>
                <th>MTU</th>
                <th>RX</th>
                <th>TX</th>
              </tr>
            </thead>
            <tbody>
              {#each interfaces as iface}
                <tr>
                  <td class="font-mono">{iface.name}</td>
                  <td>
                    <span class="badge {iface.up ? 'preset-filled-success-500' : 'preset-filled-error-500'}">
                      {iface.up ? 'UP' : 'DOWN'}
                    </span>
                  </td>
                  <td class="font-mono text-sm">{iface.mac || '-'}</td>
                  <td>{iface.mtu}</td>
                  <td>{formatBytes(iface.rx_bytes)}</td>
                  <td>{formatBytes(iface.tx_bytes)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <section>
      <h3 class="h4 mb-3">DHCP Leases</h3>
      {#if leases.length === 0}
        <p class="text-surface-500 italic">No active leases</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>IP</th>
                <th>MAC</th>
                <th>Hostname</th>
              </tr>
            </thead>
            <tbody>
              {#each leases as lease}
                <tr>
                  <td class="font-mono">{lease.ip}</td>
                  <td class="font-mono text-sm">{lease.mac}</td>
                  <td>{lease.hostname || '-'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {/if}
</div>

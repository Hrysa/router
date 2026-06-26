<script lang="ts">
  import { onMount } from 'svelte';
  import { getSystemMonitor, getInterfaces, getLeases } from '../lib/api';
  import { notify } from '../lib/stores';

  let system = $state<any>(null);
  let interfaces = $state<any[]>([]);
  let leases = $state<any[]>([]);
  let loading = $state(true);

  onMount(async () => {
    try {
      const [systemData, ifaceData, leaseData] = await Promise.all([
        getSystemMonitor(),
        getInterfaces(),
        getLeases(),
      ]);
      system = systemData;
      interfaces = ifaceData.interfaces || [];
      leases = leaseData.leases || [];
    } catch (e) {
      notify('error', 'Failed to load monitoring data');
    } finally {
      loading = false;
    }
  });

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }
</script>

<div class="monitoring-page">
  <h2>Monitoring</h2>

  {#if loading}
    <p>Loading...</p>
  {:else}
    <section>
      <h3>System</h3>
      <div class="stats-row">
        <div class="stat-card">
          <div class="stat-label">Hostname</div>
          <div class="stat-value">{system?.hostname || '-'}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Uptime</div>
          <div class="stat-value">{system?.uptime_human || '-'}</div>
        </div>
      </div>
    </section>

    <section>
      <h3>Interfaces</h3>
      {#if interfaces.length === 0}
        <p class="empty">No interfaces detected</p>
      {:else}
        <table>
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
                <td>{iface.name}</td>
                <td>
                  <span class="status" class:up={iface.up} class:down={!iface.up}>
                    {iface.up ? 'UP' : 'DOWN'}
                  </span>
                </td>
                <td>{iface.mac || '-'}</td>
                <td>{iface.mtu}</td>
                <td>{formatBytes(iface.rx_bytes)}</td>
                <td>{formatBytes(iface.tx_bytes)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <section>
      <h3>DHCP Leases</h3>
      {#if leases.length === 0}
        <p class="empty">No active leases</p>
      {:else}
        <table>
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
                <td>{lease.ip}</td>
                <td>{lease.mac}</td>
                <td>{lease.hostname || '-'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>
  {/if}
</div>

<style>
  .monitoring-page { max-width: 1200px; }
  h2 { margin: 0 0 1.5rem; color: #f1f5f9; }
  h3 { margin: 1.5rem 0 0.75rem; color: #94a3b8; font-size: 1rem; }
  .stats-row { display: flex; gap: 1rem; }
  .stat-card { background: #1e293b; padding: 1rem; border-radius: 8px; flex: 1; }
  .stat-label { color: #94a3b8; font-size: 0.875rem; margin-bottom: 0.25rem; }
  .stat-value { font-size: 1.25rem; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
  th { background: #334155; color: #94a3b8; font-weight: 600; font-size: 0.875rem; text-transform: uppercase; }
  .status { padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .status.up { background: #059669; color: white; }
  .status.down { background: #dc2626; color: white; }
  .empty { color: #64748b; font-style: italic; }
</style>

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

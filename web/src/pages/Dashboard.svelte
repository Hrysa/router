<script lang="ts">
  import { onMount } from 'svelte';
  import { getStatus, getSystemMonitor, listServices } from '../lib/api';
  import { notify } from '../lib/stores';

  let status = $state<any>(null);
  let system = $state<any>(null);
  let services = $state<any[]>([]);
  let loading = $state(true);

  onMount(async () => {
    try {
      const [statusData, systemData, servicesData] = await Promise.all([
        getStatus(),
        getSystemMonitor(),
        listServices(),
      ]);
      status = statusData;
      system = systemData;
      services = servicesData.services || [];
    } catch (e: any) {
      notify('error', 'Failed to load dashboard data');
    } finally {
      loading = false;
    }
  });
</script>

<div class="max-w-6xl">
  <h2 class="h2 mb-6">Dashboard</h2>

  {#if loading}
    <div class="placeholder animate-pulse h-32"></div>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <!-- System Card -->
      <div class="card p-4">
        <header class="card-header">
          <h3 class="h4">System</h3>
        </header>
        <div class="card-body">
          <dl class="divide-y divide-surface-200">
            <div class="flex justify-between py-2">
              <dt class="text-surface-500">Hostname</dt>
              <dd class="font-medium">{status?.hostname || '-'}</dd>
            </div>
            <div class="flex justify-between py-2">
              <dt class="text-surface-500">Uptime</dt>
              <dd class="font-medium">{system?.uptime_human || '-'}</dd>
            </div>
          </dl>
        </div>
      </div>

      <!-- Load Average Card -->
      <div class="card p-4">
        <header class="card-header">
          <h3 class="h4">Load Average</h3>
        </header>
        <div class="card-body">
          {#if status?.loadavg}
            <dl class="divide-y divide-surface-200">
              <div class="flex justify-between py-2">
                <dt class="text-surface-500">1 min</dt>
                <dd class="font-medium">{status.loadavg['1m']}</dd>
              </div>
              <div class="flex justify-between py-2">
                <dt class="text-surface-500">5 min</dt>
                <dd class="font-medium">{status.loadavg['5m']}</dd>
              </div>
              <div class="flex justify-between py-2">
                <dt class="text-surface-500">15 min</dt>
                <dd class="font-medium">{status.loadavg['15m']}</dd>
              </div>
            </dl>
          {/if}
        </div>
      </div>

      <!-- Services Card -->
      <div class="card p-4">
        <header class="card-header">
          <h3 class="h4">Services</h3>
        </header>
        <div class="card-body">
          <dl class="divide-y divide-surface-200">
            {#each services as svc}
              <div class="flex justify-between py-2">
                <dt class="text-surface-500">{svc.display_name}</dt>
                <dd>
                  <span class="badge {svc.active ? 'preset-filled-success-500' : 'preset-filled-error-500'}">
                    {svc.active ? '● Running' : '○ Stopped'}
                  </span>
                </dd>
              </div>
            {/each}
          </dl>
        </div>
      </div>
    </div>
  {/if}
</div>

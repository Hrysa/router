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

<div class="dashboard">
  <h2>Dashboard</h2>

  {#if loading}
    <p>Loading...</p>
  {:else}
    <div class="cards">
      <div class="card">
        <div class="card-header">System</div>
        <div class="card-body">
          <div class="stat">
            <span class="label">Hostname</span>
            <span class="value">{status?.hostname || '-'}</span>
          </div>
          <div class="stat">
            <span class="label">Uptime</span>
            <span class="value">{system?.uptime_human || '-'}</span>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">Load Average</div>
        <div class="card-body">
          {#if status?.loadavg}
            <div class="stat">
              <span class="label">1 min</span>
              <span class="value">{status.loadavg['1m']}</span>
            </div>
            <div class="stat">
              <span class="label">5 min</span>
              <span class="value">{status.loadavg['5m']}</span>
            </div>
            <div class="stat">
              <span class="label">15 min</span>
              <span class="value">{status.loadavg['15m']}</span>
            </div>
          {/if}
        </div>
      </div>

      <div class="card">
        <div class="card-header">Services</div>
        <div class="card-body">
          {#each services as svc}
            <div class="stat">
              <span class="label">{svc.display_name}</span>
              <span class="value" class:active={svc.active} class:inactive={!svc.active}>
                {svc.active ? '●' : '○'} {svc.status}
              </span>
            </div>
          {/each}
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .dashboard {
    max-width: 1200px;
  }

  h2 {
    margin: 0 0 1.5rem;
    color: #f1f5f9;
  }

  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1rem;
  }

  .card {
    background: #1e293b;
    border-radius: 8px;
    overflow: hidden;
  }

  .card-header {
    background: #334155;
    padding: 0.75rem 1rem;
    font-weight: 600;
    color: #94a3b8;
    font-size: 0.875rem;
    text-transform: uppercase;
  }

  .card-body {
    padding: 1rem;
  }

  .stat {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #334155;
  }

  .stat:last-child {
    border-bottom: none;
  }

  .label {
    color: #94a3b8;
  }

  .value {
    font-weight: 500;
  }

  .active {
    color: #22c55e;
  }

  .inactive {
    color: #ef4444;
  }
</style>

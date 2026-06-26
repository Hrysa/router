<script lang="ts">
  import { onMount } from 'svelte';
  import { listServices, startService, stopService, restartService } from '../lib/api';
  import { notify } from '../lib/stores';

  let services = $state<any[]>([]);
  let loading = $state(true);

  onMount(async () => {
    await loadServices();
  });

  async function loadServices() {
    loading = true;
    try {
      const data = await listServices();
      services = data.services || [];
    } catch (e) {
      notify('error', 'Failed to load services');
    } finally {
      loading = false;
    }
  }

  async function handleStart(name: string) {
    try {
      await startService(name);
      notify('success', `${name} started`);
      await loadServices();
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Failed to start service');
    }
  }

  async function handleStop(name: string) {
    try {
      await stopService(name);
      notify('success', `${name} stopped`);
      await loadServices();
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Failed to stop service');
    }
  }

  async function handleRestart(name: string) {
    try {
      await restartService(name);
      notify('success', `${name} restarted`);
      await loadServices();
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Failed to restart service');
    }
  }
</script>

<div class="services-page">
  <h2>Services</h2>

  <button onclick={loadServices}>Refresh</button>

  {#if loading}
    <p>Loading...</p>
  {:else}
    <div class="service-grid">
      {#each services as svc}
        <div class="service-card">
          <div class="service-header">
            <span class="service-name">{svc.display_name}</span>
            <span class="status" class:active={svc.active} class:inactive={!svc.active}>
              {svc.active ? '● Running' : '○ Stopped'}
            </span>
          </div>

          <div class="service-info">
            <div>Service: {svc.name}</div>
            {#if svc.pid}
              <div>PID: {svc.pid}</div>
            {/if}
          </div>

          <div class="service-actions">
            {#if svc.active}
              <button class="stop" onclick={() => handleStop(svc.name)}>Stop</button>
              <button class="restart" onclick={() => handleRestart(svc.name)}>Restart</button>
            {:else}
              <button class="start" onclick={() => handleStart(svc.name)}>Start</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .services-page {
    max-width: 1200px;
  }

  h2 {
    margin: 0 0 1.5rem;
    color: #f1f5f9;
  }

  button {
    padding: 0.5rem 1rem;
    background: #334155;
    color: #e2e8f0;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    margin-bottom: 1rem;
  }

  .service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
  }

  .service-card {
    background: #1e293b;
    border-radius: 8px;
    padding: 1rem;
  }

  .service-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .service-name {
    font-weight: 600;
    font-size: 1.125rem;
  }

  .status {
    font-size: 0.875rem;
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
  }

  .status.active {
    background: #059669;
    color: white;
  }

  .status.inactive {
    background: #475569;
    color: #94a3b8;
  }

  .service-info {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .service-actions {
    display: flex;
    gap: 0.5rem;
  }

  .service-actions button {
    flex: 1;
    margin: 0;
  }

  .start { background: #059669; }
  .start:hover { background: #047857; }
  .stop { background: #dc2626; }
  .stop:hover { background: #b91c1c; }
  .restart { background: #d97706; }
  .restart:hover { background: #b45309; }
</style>

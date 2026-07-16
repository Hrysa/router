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

<div class="max-w-6xl">
  <h2 class="h2 mb-6">Services</h2>

  <button class="btn preset-tonal mb-4" onclick={loadServices}>Refresh</button>

  {#if loading}
    <p class="text-surface-400">Loading...</p>
  {:else}
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {#each services as svc}
        <div class="card p-4">
          <div class="flex justify-between items-center mb-3">
            <span class="font-semibold text-lg">{svc.display_name}</span>
            <span class="badge {svc.active ? 'preset-filled-success-500' : 'preset-tonal-surface'}">
              {svc.active ? '● Running' : '○ Stopped'}
            </span>
          </div>

          <div class="text-sm text-surface-400 mb-4 space-y-1">
            <div>Service: {svc.name}</div>
            {#if svc.pid}
              <div>PID: {svc.pid}</div>
            {/if}
          </div>

          <div class="flex gap-2">
            {#if svc.active}
              <button class="btn preset-filled-error-500 flex-1" onclick={() => handleStop(svc.name)}>Stop</button>
              <button class="btn preset-filled-warning-500 flex-1" onclick={() => handleRestart(svc.name)}>Restart</button>
            {:else}
              <button class="btn preset-filled-success-500 flex-1" onclick={() => handleStart(svc.name)}>Start</button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

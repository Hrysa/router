<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getServiceStatus, startService, stopService, restartService,
    getSingboxConfig, putSingboxConfig,
    applyConfig,
  } from '../lib/api';
  import { notify } from '../lib/stores';
  import { Tabs } from '@skeletonlabs/skeleton-svelte';

  let activeTab = $state('status');

  // Service status
  let svcStatus = $state<any>(null);
  let loadingStatus = $state(true);

  // sing-box JSON config
  let singboxConfig = $state('');
  let loadingConfig = $state(true);
  let savingConfig = $state(false);

  function error_msg(e: any): string {
    return e.response?.data?.error?.message || e.message || 'Unknown error';
  }

  async function loadStatus() {
    try {
      const data = await getServiceStatus('sing-box');
      svcStatus = data;
    } catch (e: any) {
      svcStatus = { active: false, status: 'not found', pid: null };
    } finally {
      loadingStatus = false;
    }
  }

  async function loadConfig() {
    loadingConfig = true;
    try {
      const data = await getSingboxConfig();
      if (data.raw !== undefined) {
        singboxConfig = data.raw;
      } else {
        singboxConfig = JSON.stringify(data, null, 2);
      }
    } catch (e) {
      notify('error', 'Failed to load sing-box config');
    } finally {
      loadingConfig = false;
    }
  }

  onMount(async () => {
    await Promise.all([loadStatus(), loadConfig()]);
  });

  async function handleStart() {
    try {
      await startService('sing-box');
      notify('success', 'sing-box started');
      await loadStatus();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleStop() {
    try {
      await stopService('sing-box');
      notify('success', 'sing-box stopped');
      await loadStatus();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleRestart() {
    try {
      await restartService('sing-box');
      notify('success', 'sing-box restarted');
      await loadStatus();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function saveConfig() {
    savingConfig = true;
    try {
      await putSingboxConfig(singboxConfig);
      notify('success', 'sing-box config saved');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      savingConfig = false;
    }
  }

  async function saveAndApply() {
    await saveConfig();
    try {
      await applyConfig();
      notify('success', 'sing-box config applied');
      await loadStatus();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }
</script>

<div class="max-w-4xl">
  <h2 class="h2 mb-6">sing-box</h2>

  <Tabs value={activeTab} onValueChange={(e) => activeTab = e.value}>
    <Tabs.List>
      <Tabs.Trigger value="status">Status</Tabs.Trigger>
      <Tabs.Trigger value="config">Config</Tabs.Trigger>
    </Tabs.List>

    <Tabs.Content value="status">
      <div class="min-h-[200px]">
        {#if loadingStatus}
          <div class="placeholder animate-pulse h-32"></div>
        {:else}
          <div class="card p-5 border border-surface-200">
            <div class="flex justify-between items-center mb-3">
              <span class="font-semibold text-lg">sing-box</span>
              <span class="badge {svcStatus?.active ? 'preset-filled-success-500' : 'preset-tonal-surface'}">
                {svcStatus?.active ? '● Running' : '○ Stopped'}
              </span>
            </div>

            <div class="text-sm text-surface-500 mb-4 space-y-1">
              <div>Service: sing-box</div>
              {#if svcStatus?.pid}
                <div>PID: {svcStatus.pid}</div>
              {/if}
              <div>Status: {svcStatus?.status || 'unknown'}</div>
            </div>

            <div class="flex gap-2">
              {#if svcStatus?.active}
                <button class="btn preset-filled-error-500" onclick={handleStop}>Stop</button>
                <button class="btn preset-filled-warning-500" onclick={handleRestart}>Restart</button>
              {:else}
                <button class="btn preset-filled-success-500" onclick={handleStart}>Start</button>
              {/if}
            </div>
          </div>
        {/if}
      </div>
    </Tabs.Content>

    <Tabs.Content value="config">
      <div class="min-h-[200px]">
        {#if loadingConfig}
          <div class="placeholder animate-pulse h-32"></div>
        {:else}
          <section class="mb-6">
            <h3 class="h4 mb-1">sing-box Configuration</h3>
            <p class="text-surface-500 text-sm mb-3">
              Edit the sing-box JSONC config. Written to <code class="code">/etc/sing-box/config.jsonc</code>.
            </p>

            <textarea
              class="textarea font-mono text-sm"
              bind:value={singboxConfig}
              rows="24"
              spellcheck="false"
            ></textarea>
          </section>

          <div class="flex gap-2">
            <button class="btn preset-filled-primary-500" onclick={saveConfig} disabled={savingConfig}>
              {savingConfig ? 'Saving...' : 'Save'}
            </button>
            <button class="btn preset-filled-success-500" onclick={saveAndApply} disabled={savingConfig}>
              Save & Apply
            </button>
          </div>
        {/if}
      </div>
    </Tabs.Content>
  </Tabs>
</div>

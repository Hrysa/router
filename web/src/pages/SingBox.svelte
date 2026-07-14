<script lang="ts">
  import { onMount } from 'svelte';
  import {
    getServiceStatus, startService, stopService, restartService,
    getSingboxConfig, putSingboxConfig,
    applyConfig,
  } from '../lib/api';
  import { notify } from '../lib/stores';

  let activeTab = $state<'status' | 'config'>('status');

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

<div class="singbox-page">
  <h2>sing-box</h2>

  <div class="tabs">
    <button class="tab" class:active={activeTab === 'status'} onclick={() => activeTab = 'status'}>
      Status
    </button>
    <button class="tab" class:active={activeTab === 'config'} onclick={() => activeTab = 'config'}>
      Config
    </button>
  </div>

  {#if activeTab === 'status'}
    <div class="tab-content">
      {#if loadingStatus}
        <p class="loading">Loading...</p>
      {:else}
        <div class="status-card">
          <div class="status-header">
            <span class="service-name">sing-box</span>
            <span class="status-badge" class:active={svcStatus?.active} class:inactive={!svcStatus?.active}>
              {svcStatus?.active ? '● Running' : '○ Stopped'}
            </span>
          </div>

          <div class="service-info">
            <div>Service: sing-box</div>
            {#if svcStatus?.pid}
              <div>PID: {svcStatus.pid}</div>
            {/if}
            <div>Status: {svcStatus?.status || 'unknown'}</div>
          </div>

          <div class="service-actions">
            {#if svcStatus?.active}
              <button class="stop" onclick={handleStop}>Stop</button>
              <button class="restart" onclick={handleRestart}>Restart</button>
            {:else}
              <button class="start" onclick={handleStart}>Start</button>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {:else if activeTab === 'config'}
    <div class="tab-content">
      {#if loadingConfig}
        <p class="loading">Loading...</p>
      {:else}
        <section>
          <h3>sing-box Configuration</h3>
          <p class="section-desc">Edit the sing-box JSONC config. Written to <code>/etc/sing-box/config.jsonc</code>.</p>

          <textarea
            bind:value={singboxConfig}
            rows="24"
            spellcheck="false"
          ></textarea>
        </section>

        <div class="toolbar">
          <button class="primary" onclick={saveConfig} disabled={savingConfig}>
            {savingConfig ? 'Saving...' : 'Save'}
          </button>
          <button class="apply" onclick={saveAndApply} disabled={savingConfig}>
            Save & Apply
          </button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .singbox-page { max-width: 900px; }

  h2 { margin: 0 0 1.5rem; color: #f1f5f9; }

  .tabs {
    display: flex;
    gap: 0;
    border-bottom: 1px solid #334155;
    margin-bottom: 1.5rem;
  }

  .tab {
    padding: 0.75rem 1.5rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: #94a3b8;
    cursor: pointer;
    font-size: 0.9375rem;
  }

  .tab:hover { color: #e2e8f0; }
  .tab.active { color: #3b82f6; border-bottom-color: #3b82f6; }

  .tab-content { min-height: 200px; }
  .loading { color: #64748b; }

  /* Status tab */
  .status-card {
    background: #1e293b;
    border-radius: 8px;
    padding: 1.25rem;
  }

  .status-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.75rem;
  }

  .service-name { font-weight: 600; font-size: 1.125rem; }

  .status-badge {
    font-size: 0.875rem;
    padding: 0.25rem 0.75rem;
    border-radius: 4px;
  }

  .status-badge.active { background: #059669; color: white; }
  .status-badge.inactive { background: #475569; color: #94a3b8; }

  .service-info {
    color: #94a3b8;
    font-size: 0.875rem;
    margin-bottom: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .service-actions { display: flex; gap: 0.5rem; }
  .service-actions button { flex: 0 0 auto; }

  .start { background: #059669; }
  .start:hover { background: #047857; }
  .stop { background: #dc2626; }
  .stop:hover { background: #b91c1c; }
  .restart { background: #d97706; }
  .restart:hover { background: #b45309; }

  /* Config tab */
  section { margin-bottom: 1.5rem; }
  h3 { margin: 0 0 0.25rem; color: #94a3b8; font-size: 1rem; }
  .section-desc { color: #64748b; font-size: 0.8125rem; margin: 0 0 1rem; }
  .section-desc code { color: #94a3b8; background: #0f172a; padding: 0.125rem 0.375rem; border-radius: 3px; font-size: 0.8125rem; }

  textarea {
    width: 100%;
    background: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.8125rem;
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    resize: vertical;
    box-sizing: border-box;
    tab-size: 2;
  }
  textarea:focus { outline: none; border-color: #3b82f6; }

  .toolbar { display: flex; gap: 0.5rem; margin-top: 1.5rem; }

  button {
    padding: 0.5rem 1rem;
    background: #334155;
    color: #e2e8f0;
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }
  button:hover { background: #475569; }
  button.primary { background: #3b82f6; }
  button.primary:hover { background: #2563eb; }
  button.apply { background: #059669; }
  button.apply:hover { background: #047857; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

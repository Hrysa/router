<script lang="ts">
  import { onMount } from 'svelte';
  import { getConfig, patchConfig } from '../lib/api';
  import { notify } from '../lib/stores';

  let beforeStart = $state('');
  let afterStart = $state('');
  let loading = $state(true);
  let saving = $state(false);

  function error_msg(e: any): string {
    return e.response?.data?.error?.message || e.message || 'Unknown error';
  }

  async function loadAll() {
    loading = true;
    try {
      const config = await getConfig();
      beforeStart = config.hooks?.before_start ?? '';
      afterStart = config.hooks?.after_start ?? '';
    } catch (e) {
      notify('error', 'Failed to load hooks config');
    } finally {
      loading = false;
    }
  }

  onMount(loadAll);

  async function saveHooks() {
    saving = true;
    try {
      await patchConfig('hooks', {
        before_start: beforeStart,
        after_start: afterStart,
      });
      notify('success', 'Hooks saved');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      saving = false;
    }
  }
</script>

<div class="hooks-page">
  <h2>Hooks</h2>
  <p class="subtitle">Shell commands executed at routerd startup. One command per line.</p>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else}
    <section>
      <h3>Before Start</h3>
      <p class="section-desc">Runs after config validation, before services are applied.</p>
      <textarea
        bind:value={beforeStart}
        rows="6"
        placeholder='echo "applying routerd config"'
        spellcheck="false"
      ></textarea>
    </section>

    <section>
      <h3>After Start</h3>
      <p class="section-desc">Runs after services are applied and tproxy routing is configured.</p>
      <textarea
        bind:value={afterStart}
        rows="6"
        placeholder="modprobe xt_TPROXY"
        spellcheck="false"
      ></textarea>
    </section>

    <div class="toolbar">
      <button class="primary" onclick={saveHooks} disabled={saving}>
        {saving ? 'Saving...' : 'Save'}
      </button>
    </div>
  {/if}
</div>

<style>
  .hooks-page { max-width: 800px; }
  h2 { margin: 0 0 0.25rem; color: #f1f5f9; }
  .subtitle { color: #64748b; font-size: 0.875rem; margin: 0 0 1.5rem; }
  .loading { color: #64748b; }

  section { margin-bottom: 1.5rem; }
  h3 { margin: 0 0 0.25rem; color: #94a3b8; font-size: 1rem; }
  .section-desc { color: #64748b; font-size: 0.8125rem; margin: 0 0 0.5rem; }

  textarea {
    width: 100%;
    background: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 0.75rem;
    font-size: 0.875rem;
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    resize: vertical;
    box-sizing: border-box;
  }
  textarea:focus { outline: none; border-color: #3b82f6; }

  .toolbar { display: flex; gap: 0.5rem; margin-top: 1.5rem; }

  button { padding: 0.5rem 1rem; background: #334155; color: #e2e8f0; border: none; border-radius: 6px; cursor: pointer; }
  button:hover { background: #475569; }
  button.primary { background: #3b82f6; }
  button.primary:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

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

<div class="max-w-3xl">
  <h2 class="h2 mb-1">Hooks</h2>
  <p class="text-surface-500 text-sm mb-6">Shell commands executed at routerd startup. One command per line.</p>

  {#if loading}
    <div class="placeholder animate-pulse h-32"></div>
  {:else}
    <section class="mb-6">
      <h3 class="h4 mb-1">Before Start</h3>
      <p class="text-surface-500 text-sm mb-2">Runs after config validation, before services are applied.</p>
      <textarea
        class="textarea font-mono text-sm"
        bind:value={beforeStart}
        rows="6"
        placeholder='echo "applying routerd config"'
        spellcheck="false"
      ></textarea>
    </section>

    <section class="mb-6">
      <h3 class="h4 mb-1">After Start</h3>
      <p class="text-surface-500 text-sm mb-2">Runs after services are applied and tproxy routing is configured.</p>
      <textarea
        class="textarea font-mono text-sm"
        bind:value={afterStart}
        rows="6"
        placeholder="modprobe xt_TPROXY"
        spellcheck="false"
      ></textarea>
    </section>

    <div class="flex gap-2">
      <button class="btn preset-filled-primary-500" onclick={saveHooks} disabled={saving}>
        {saving ? 'Saving...' : 'Save'}
      </button>
    </div>
  {/if}
</div>

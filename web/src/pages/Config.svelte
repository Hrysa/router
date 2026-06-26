<script lang="ts">
  import { onMount } from 'svelte';
  import { getConfig, replaceConfig, applyConfig, validateConfig } from '../lib/api';
  import { notify } from '../lib/stores';

  let config = $state<any>(null);
  let configText = $state('');
  let loading = $state(true);
  let saving = $state(false);
  let applying = $state(false);
  let validationErrors = $state<any[]>([]);

  onMount(async () => {
    try {
      config = await getConfig();
      configText = JSON.stringify(config, null, 2);
    } catch (e) {
      notify('error', 'Failed to load config');
    } finally {
      loading = false;
    }
  });

  async function handleValidate() {
    try {
      const parsed = JSON.parse(configText);
      const result = await validateConfig(parsed);
      if (result.valid) {
        notify('success', 'Config is valid');
        validationErrors = [];
      } else {
        validationErrors = result.errors;
        notify('error', `Config has ${result.errors.length} errors`);
      }
    } catch (e: any) {
      notify('error', 'Invalid JSON: ' + e.message);
    }
  }

  async function handleSave() {
    saving = true;
    try {
      const parsed = JSON.parse(configText);
      await replaceConfig(parsed);
      notify('success', 'Config saved');
      validationErrors = [];
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Failed to save config');
    } finally {
      saving = false;
    }
  }

  async function handleApply() {
    applying = true;
    try {
      const result = await applyConfig();
      notify('success', `Config applied. Services restarted: ${result.services_restarted?.join(', ') || 'none'}`);
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Failed to apply config');
    } finally {
      applying = false;
    }
  }
</script>

<div class="config-page">
  <h2>Configuration</h2>

  {#if loading}
    <p>Loading...</p>
  {:else}
    <div class="toolbar">
      <button onclick={handleValidate}>Validate</button>
      <button onclick={handleSave} disabled={saving}>
        {saving ? 'Saving...' : 'Save'}
      </button>
      <button class="primary" onclick={handleApply} disabled={applying}>
        {applying ? 'Applying...' : 'Apply'}
      </button>
    </div>

    {#if validationErrors.length > 0}
      <div class="errors">
        {#each validationErrors as error}
          <div class="error">
            <strong>{error.field}:</strong> {error.message}
          </div>
        {/each}
      </div>
    {/if}

    <textarea
      bind:value={configText}
      spellcheck="false"
      rows="30"
    ></textarea>
  {/if}
</div>

<style>
  .config-page {
    max-width: 1200px;
  }

  h2 {
    margin: 0 0 1.5rem;
    color: #f1f5f9;
  }

  .toolbar {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }

  button {
    padding: 0.5rem 1rem;
    background: #334155;
    color: #e2e8f0;
    border: none;
    border-radius: 6px;
    cursor: pointer;
  }

  button:hover:not(:disabled) {
    background: #475569;
  }

  button.primary {
    background: #3b82f6;
  }

  button.primary:hover:not(:disabled) {
    background: #2563eb;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .errors {
    background: #7f1d1d;
    padding: 1rem;
    border-radius: 6px;
    margin-bottom: 1rem;
  }

  .error {
    padding: 0.25rem 0;
    font-size: 0.875rem;
  }

  textarea {
    width: 100%;
    background: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Monaco', 'Menlo', monospace;
    font-size: 0.875rem;
    resize: vertical;
    box-sizing: border-box;
  }

  textarea:focus {
    outline: none;
    border-color: #3b82f6;
  }
</style>

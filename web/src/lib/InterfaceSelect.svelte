<script lang="ts">
  import { onMount } from 'svelte';
  import { getInterfaces } from './api';

  let {
    value = $bindable(),
    multiple = false,
    placeholder = 'Select interface',
    exclude = [],
    items = undefined as string[] | undefined,
  }: {
    value: string | string[];
    multiple?: boolean;
    placeholder?: string;
    exclude?: string[];
    items?: string[];
  } = $props();

  let options = $state<string[]>(items ?? []);
  let open = $state(false);
  let search = $state('');
  let dropdownEl = $state<HTMLElement | null>(null);

  onMount(async () => {
    if (items !== undefined) return; // use provided items
    try {
      const data = await getInterfaces();
      options = data.interfaces ?? [];
    } catch {
      options = [];
    }
  });

  $effect(() => {
    function handleMouseDown(e: MouseEvent) {
      if (dropdownEl && !dropdownEl.contains(e.target as Node)) {
        open = false;
      }
    }
    document.addEventListener('mousedown', handleMouseDown);
    return () => document.removeEventListener('mousedown', handleMouseDown);
  });

  let available = $derived(options.filter(o => !exclude.includes(o)));
  let filtered = $derived(
    search ? available.filter(o => o.toLowerCase().includes(search.toLowerCase())) : available
  );

  function isSelected(opt: string): boolean {
    if (multiple) return Array.isArray(value) && value.includes(opt);
    return value === opt;
  }

  function toggle(opt: string) {
    if (multiple) {
      const arr = Array.isArray(value) ? [...value] : [];
      const idx = arr.indexOf(opt);
      if (idx >= 0) arr.splice(idx, 1);
      else arr.push(opt);
      value = arr;
    } else {
      value = opt;
      open = false;
    }
  }

  function remove(opt: string) {
    if (multiple && Array.isArray(value)) {
      value = value.filter(v => v !== opt);
    }
  }

  function displayText(): string {
    if (multiple) return '';
    return typeof value === 'string' ? value : '';
  }
</script>

<div class="iface-select" bind:this={dropdownEl}>
  {#if multiple && Array.isArray(value)}
    <div class="tags" onclick={() => { open = !open; }}>
      {#each value as tag}
        <span class="tag">{tag} <button class="tag-remove" onclick={(e) => { e.stopPropagation(); remove(tag); }}>×</button></span>
      {/each}
      {#if value.length === 0}
        <span class="placeholder">{placeholder}</span>
      {/if}
    </div>
  {:else}
    <div class="single-display" onclick={() => { open = !open; }}>
      {#if displayText()}
        <span class="selected-text">{displayText()}</span>
      {:else}
        <span class="placeholder">{placeholder}</span>
      {/if}
    </div>
  {/if}

  {#if open}
    <div class="dropdown">
      <input
        class="search"
        bind:value={search}
        placeholder="Filter..."
        onclick={(e) => e.stopPropagation()}
      />
      <div class="options">
        {#each filtered as opt}
          <button
            class="option"
            class:selected={isSelected(opt)}
            onclick={() => toggle(opt)}
          >
            <span class="check">{isSelected(opt) ? '✓' : ''}</span>
            <span class="mono">{opt}</span>
          </button>
        {/each}
        {#if filtered.length === 0}
          <p class="no-results">No interfaces found</p>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .iface-select { position: relative; }

  .single-display, .tags {
    background: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 4px;
    padding: 0.5rem;
    font-size: 0.875rem;
    min-height: 2.25rem;
    cursor: pointer;
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.25rem;
  }
  .single-display:hover, .tags:hover { border-color: #475569; }

  .selected-text { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; }
  .placeholder { color: #64748b; font-size: 0.875rem; }

  .tags { gap: 0.375rem; }
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    background: #334155;
    border-radius: 4px;
    padding: 0.125rem 0.375rem;
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    font-size: 0.8125rem;
  }
  .tag-remove {
    background: none;
    border: none;
    color: #94a3b8;
    cursor: pointer;
    padding: 0;
    font-size: 0.875rem;
    line-height: 1;
  }
  .tag-remove:hover { color: #e2e8f0; }

  .dropdown {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    margin-top: 2px;
    z-index: 50;
    max-height: 240px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }

  .search {
    background: #0f172a;
    color: #e2e8f0;
    border: none;
    border-bottom: 1px solid #334155;
    border-radius: 0;
    padding: 0.5rem;
    font-size: 0.8125rem;
  }
  .search:focus { outline: none; }

  .options {
    overflow-y: auto;
    display: flex;
    flex-direction: column;
  }

  .option {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.5rem;
    background: none;
    border: none;
    color: #e2e8f0;
    cursor: pointer;
    font-size: 0.8125rem;
    text-align: left;
    width: 100%;
  }
  .option:hover { background: #334155; }
  .option.selected { color: #60a5fa; }

  .check { width: 1rem; text-align: center; color: #3b82f6; font-size: 0.75rem; }
  .mono { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; }

  .no-results { color: #64748b; font-size: 0.8125rem; padding: 0.5rem; text-align: center; margin: 0; }
</style>

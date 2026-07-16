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

  let allItems = $state<string[]>([]);
  let open = $state(false);
  let search = $state('');
  let dropdownEl = $state<HTMLElement | null>(null);

  $effect(() => {
    const currentItems = items;
    if (currentItems !== undefined) {
      allItems = currentItems;
    } else {
      getInterfaces().then(data => {
        allItems = data.interfaces ?? [];
      }).catch(() => {
        allItems = [];
      });
    }
  });

  $effect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (dropdownEl && !dropdownEl.contains(e.target as Node)) {
        open = false;
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  });

  let filtered = $derived(
    search
      ? allItems.filter(o => !exclude.includes(o) && o.toLowerCase().includes(search.toLowerCase()))
      : allItems.filter(o => !exclude.includes(o))
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
</script>

<div class="relative" bind:this={dropdownEl}>
  {#if multiple}
    <button
      type="button"
      class="input w-full flex flex-wrap items-center gap-1 text-left cursor-pointer min-h-[2.5rem]"
      onclick={() => open = !open}
    >
      {#if Array.isArray(value)}
        {#each value as tag}
          <span class="badge preset-tonal-surface text-xs">{tag}
            <button type="button" class="ml-1 opacity-70 hover:opacity-100" onclick={(e) => { e.stopPropagation(); remove(tag); }}>×</button>
          </span>
        {/each}
      {/if}
      {#if !Array.isArray(value) || value.length === 0}
        <span class="text-surface-400">{placeholder}</span>
      {/if}
    </button>
  {:else}
    <button
      type="button"
      class="input w-full text-left cursor-pointer min-h-[2.5rem]"
      onclick={() => open = !open}
    >
      {#if value}
        <span>{value}</span>
      {:else}
        <span class="text-surface-400">{placeholder}</span>
      {/if}
    </button>
  {/if}

  {#if open}
    <div class="absolute top-full left-0 right-0 mt-1 bg-white border border-surface-200 rounded-lg z-50 max-h-60 flex flex-col overflow-hidden shadow-lg">
      <input
        class="input border-0 border-b border-surface-200 rounded-none text-sm"
        bind:value={search}
        placeholder="Filter..."
        onclick={(e) => e.stopPropagation()}
      />
      <div class="overflow-y-auto flex flex-col">
        {#each filtered as opt}
          <button
            type="button"
            class="flex items-center gap-2 px-3 py-1.5 text-sm text-left w-full hover:bg-surface-100 transition-colors {isSelected(opt) ? 'text-primary-500 bg-primary-50' : ''}"
            onclick={() => toggle(opt)}
          >
            <span class="w-4 text-center text-xs">{isSelected(opt) ? '✓' : ''}</span>
            <span>{opt}</span>
          </button>
        {/each}
        {#if filtered.length === 0}
          <p class="text-surface-400 text-sm text-center py-2 m-0">No options found</p>
        {/if}
      </div>
    </div>
  {/if}
</div>

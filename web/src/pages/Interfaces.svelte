<script lang="ts">
  import { onMount } from 'svelte';
  import { listInterfaces, createInterface, updateInterface, deleteInterface, applyConfig } from '../lib/api';
  import { notify } from '../lib/stores';
  import InterfaceSelect from '../lib/InterfaceSelect.svelte';
  import { Dialog, Portal } from '@skeletonlabs/skeleton-svelte';

  // ── State ───────────────────────────────────────────────────────────────────

  let items = $state<any[]>([]);
  let loading = $state(true);
  let applying = $state(false);

  // Modal
  let showModal = $state(false);
  let editing = $state(false);
  let form = $state(emptyForm());

  // ── Helpers ─────────────────────────────────────────────────────────────────

  function emptyForm() {
    return {
      name: '', label: '', method: 'static',
      static_config: { address: '', gateway: '', dns: [] as string[] },
      pppoe: { username: '', password: '', mtu: 1492, mss_clamp: true, keepalive_interval: 10, keepalive_failure: 3 },
      dhcp: { hostname: '' },
      bridge_ports: [] as string[],
      vlan_id: null as number | null,
      parent: null as string | null,
    };
  }

  function ifaceToForm(iface: any) {
    return {
      name: iface.name || '',
      label: iface.label || '',
      method: iface.method || 'static',
      static_config: iface.static_config ?? { address: '', gateway: '', dns: [] },
      pppoe: iface.pppoe ?? { username: '', password: '', mtu: 1492, mss_clamp: true, keepalive_interval: 10, keepalive_failure: 3 },
      dhcp: iface.dhcp ?? { hostname: '' },
      bridge_ports: iface.bridge_ports ?? [],
      vlan_id: iface.vlan_id ?? null,
      parent: iface.parent ?? null,
    };
  }

  function formToPayload(form: any) {
    const payload: any = {
      name: form.name,
      label: form.label,
      method: form.method,
    };
    if (form.method === 'pppoe') {
      payload.pppoe = form.pppoe;
    } else if (form.method === 'dhcp') {
      payload.dhcp = form.dhcp;
    } else {
      payload.static_config = form.static_config;
      if (form.bridge_ports.length > 0) payload.bridge_ports = form.bridge_ports;
    }
    if (form.vlan_id != null) {
      payload.vlan_id = Number(form.vlan_id);
      payload.parent = form.parent;
    }
    return payload;
  }

  function inferRole(iface: any): string {
    if (iface.method === 'pppoe' || iface.method === 'dhcp') return 'WAN';
    if (iface.vlan_id != null) return 'VLAN';
    const gw = iface.static_config?.gateway;
    if (gw && gw.length > 0) return 'WAN';
    return 'LAN';
  }

  function error_msg(e: any): string {
    return e.response?.data?.error?.message || e.message || 'Unknown error';
  }

  // ── Derived ─────────────────────────────────────────────────────────────────

  let usedNames = $derived(items.map((i: any) => i.name));

  // ── Data loading ────────────────────────────────────────────────────────────

  async function loadAll() {
    loading = true;
    try {
      const data = await listInterfaces();
      items = data.items ?? [];
    } catch (e) {
      notify('error', 'Failed to load interfaces');
    } finally {
      loading = false;
    }
  }

  onMount(loadAll);

  // ── CRUD ────────────────────────────────────────────────────────────────────

  function openAdd() {
    editing = false;
    form = emptyForm();
    showModal = true;
  }

  function openEdit(iface: any) {
    editing = true;
    form = ifaceToForm(iface);
    showModal = true;
  }

  async function handleSave() {
    const payload = formToPayload(form);
    try {
      if (editing) {
        await updateInterface(form.name, payload);
        notify('success', `Interface ${form.name} updated`);
      } else {
        await createInterface(payload);
        notify('success', `Interface ${form.name} created`);
      }
      showModal = false;
      await loadAll();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleDelete(name: string) {
    if (!confirm(`Delete interface "${name}"?`)) return;
    try {
      await deleteInterface(name);
      notify('success', `Interface ${name} deleted`);
      await loadAll();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleApply() {
    applying = true;
    try {
      await applyConfig();
      notify('success', 'Interfaces applied');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      applying = false;
    }
  }
</script>

<div class="max-w-6xl">
  <h2 class="h2 mb-6">Interfaces</h2>

  {#if loading}
    <div class="placeholder animate-pulse h-32"></div>
  {:else}
    <div class="flex items-center justify-between mb-4">
      <p class="text-sm text-surface-500">{items.length} interface{items.length !== 1 ? 's' : ''}</p>
      <button class="btn preset-filled-primary-500" onclick={openAdd}>+ Add Interface</button>
    </div>

    {#if items.length === 0}
      <p class="text-surface-500 italic">No interfaces configured</p>
    {:else}
      <div class="space-y-3">
        {#each items as iface}
          <div class="card p-4">
            <div class="flex justify-between items-center mb-2">
              <div class="flex items-baseline gap-3">
                <span class="font-mono font-semibold">{iface.name}</span>
                {#if iface.label}
                  <span class="text-surface-500 text-sm">{iface.label}</span>
                {/if}
                <span class="badge preset-tonal-surface text-xs">{iface.method}</span>
                <span class="badge {inferRole(iface) === 'WAN' ? 'preset-filled-warning-500' : 'preset-filled-success-500'} text-xs">{inferRole(iface)}</span>
              </div>
              <div class="flex gap-2">
                <button class="btn preset-tonal" onclick={() => openEdit(iface)}>Edit</button>
                <button class="btn preset-filled-error-500" onclick={() => handleDelete(iface.name)}>Delete</button>
              </div>
            </div>
            {#if iface.static_config}
              <div class="flex items-center gap-2 text-sm text-surface-500 mt-1">
                <span class="font-mono">{iface.static_config.address}</span>
                {#if iface.static_config.gateway}
                  <span>→</span>
                  <span class="font-mono">{iface.static_config.gateway}</span>
                {/if}
              </div>
            {/if}
            {#if iface.bridge_ports?.length > 0}
              <div class="flex items-center gap-2 text-sm text-surface-500 mt-1">
                <span>Bridge:</span>
                <span class="font-mono">{Array.isArray(iface.bridge_ports) ? iface.bridge_ports.join(', ') : (iface.bridge_ports || '')}</span>
              </div>
            {/if}
            {#if iface.vlan_id != null}
              <div class="flex items-center gap-2 text-sm text-surface-500 mt-1">
                <span>VLAN {iface.vlan_id}</span>
                {#if iface.parent}
                  <span>on</span>
                  <span class="font-mono">{iface.parent}</span>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

    <div class="flex gap-2 mt-6">
      <button class="btn preset-filled-primary-500" onclick={handleApply} disabled={applying}>
        {applying ? 'Applying...' : 'Apply'}
      </button>
    </div>
  {/if}
</div>

<!-- Interface Modal -->
<Dialog open={showModal} onOpenChange={(e) => showModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[580px] max-h-[85vh] overflow-y-auto shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">{editing ? 'Edit Interface' : 'Add Interface'}</Dialog.Title>

        <div class="grid grid-cols-2 gap-3">
          <label class="label">
            <span class="label-text">Interface Name</span>
            {#if editing}
              <input class="input" value={form.name} disabled />
            {:else if form.vlan_id}
              <input class="input" bind:value={form.name} placeholder="e.g. vlan100" />
            {:else}
              <InterfaceSelect bind:value={form.name} placeholder="Select interface" exclude={usedNames} />
            {/if}
          </label>
          <label class="label">
            <span class="label-text">Label</span>
            <input class="input" bind:value={form.label} placeholder="e.g. WAN, LAN, IoT" />
          </label>
          <label class="label">
            <span class="label-text">Method</span>
            <select class="input" bind:value={form.method}>
              <option value="static">Static</option>
              <option value="dhcp">DHCP</option>
              <option value="pppoe">PPPoE</option>
            </select>
          </label>
        </div>

        {#if form.method === 'static'}
          <h4 class="h4 mt-4 mb-2">Static Configuration</h4>
          <div class="grid grid-cols-2 gap-3">
            <label class="label">
              <span class="label-text">Address (CIDR)</span>
              <input class="input" bind:value={form.static_config.address} placeholder="192.168.1.1/24" />
            </label>
            <label class="label">
              <span class="label-text">Gateway (set for WAN)</span>
              <input class="input" bind:value={form.static_config.gateway} placeholder="leave empty for LAN" />
            </label>
          </div>

          <h4 class="h4 mt-4 mb-2">Bridge Ports (optional)</h4>
          <InterfaceSelect bind:value={form.bridge_ports} multiple placeholder="Select bridge ports" />
        {:else if form.method === 'pppoe'}
          <h4 class="h4 mt-4 mb-2">PPPoE Configuration</h4>
          <div class="grid grid-cols-2 gap-3">
            <label class="label">
              <span class="label-text">Username</span>
              <input class="input" bind:value={form.pppoe.username} placeholder="ISP username" />
            </label>
            <label class="label">
              <span class="label-text">Password</span>
              <input class="input" type="password" bind:value={form.pppoe.password} placeholder="ISP password" />
            </label>
            <label class="label">
              <span class="label-text">MTU</span>
              <input class="input" type="number" bind:value={form.pppoe.mtu} />
            </label>
            <label class="label">
              <span class="label-text">MSS Clamp</span>
              <select class="input" bind:value={form.pppoe.mss_clamp}>
                <option value={true}>Enabled</option>
                <option value={false}>Disabled</option>
              </select>
            </label>
          </div>
        {:else if form.method === 'dhcp'}
          <h4 class="h4 mt-4 mb-2">DHCP Client Configuration</h4>
          <div class="grid grid-cols-2 gap-3">
            <label class="label">
              <span class="label-text">Hostname (optional)</span>
              <input class="input" bind:value={form.dhcp.hostname} placeholder="router" />
            </label>
          </div>
        {/if}

        <h4 class="h4 mt-4 mb-2">VLAN (optional)</h4>
        <div class="grid grid-cols-2 gap-3">
          <label class="label">
            <span class="label-text">VLAN ID</span>
            <input class="input" type="number" bind:value={form.vlan_id} placeholder="leave empty if not VLAN" min="1" max="4094" />
          </label>
          <label class="label">
            <span class="label-text">Parent Interface</span>
            <InterfaceSelect bind:value={form.parent} placeholder="Select parent" />
          </label>
        </div>

        <div class="flex justify-end gap-2 mt-6">
          <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
          <button class="btn preset-filled-primary-500" onclick={handleSave}>
            {editing ? 'Update' : 'Create'}
          </button>
        </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

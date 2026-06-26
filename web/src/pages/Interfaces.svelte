<script lang="ts">
  import { onMount } from 'svelte';
  import { listInterfaces, createInterface, updateInterface, deleteInterface, applyConfig } from '../lib/api';
  import { notify } from '../lib/stores';
  import InterfaceSelect from '../lib/InterfaceSelect.svelte';

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

<div class="interfaces-page">
  <h2>Interfaces</h2>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else}
    <div class="section-header">
      <p class="count">{items.length} interface{items.length !== 1 ? 's' : ''}</p>
      <button onclick={openAdd} class="btn-add">+ Add Interface</button>
    </div>

    {#if items.length === 0}
      <p class="empty">No interfaces configured</p>
    {:else}
      <div class="iface-list">
        {#each items as iface}
          <div class="iface-card">
            <div class="iface-header">
              <div class="iface-title">
                <span class="iface-name">{iface.name}</span>
                {#if iface.label}
                  <span class="iface-label">{iface.label}</span>
                {/if}
                <span class="iface-method">{iface.method}</span>
              </div>
              <div class="iface-actions">
                <button class="btn-sm" onclick={() => openEdit(iface)}>Edit</button>
                <button class="btn-sm btn-danger" onclick={() => handleDelete(iface.name)}>Delete</button>
              </div>
            </div>
            {#if iface.static_config}
              <div class="iface-details">
                <span class="mono">{iface.static_config.address}</span>
                {#if iface.static_config.gateway}
                  <span class="detail-sep">→</span>
                  <span class="mono">{iface.static_config.gateway}</span>
                {/if}
              </div>
            {/if}
            {#if iface.bridge_ports?.length > 0}
              <div class="iface-details">
                <span class="label">Bridge:</span>
                <span class="mono">{iface.bridge_ports.join(', ')}</span>
              </div>
            {/if}
            {#if iface.vlan_id != null}
              <div class="iface-details">
                <span class="label">VLAN {iface.vlan_id}</span>
                {#if iface.parent}
                  <span class="detail-sep">on</span>
                  <span class="mono">{iface.parent}</span>
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

    <div class="toolbar">
      <button class="primary" onclick={handleApply} disabled={applying}>
        {applying ? 'Applying...' : 'Apply'}
      </button>
    </div>
  {/if}
</div>

<!-- ── Interface Modal ─────────────────────────────────────────────────────── -->
{#if showModal}
  <div class="modal-backdrop" onclick={() => showModal = false} role="dialog">
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>{editing ? 'Edit Interface' : 'Add Interface'}</h3>

      <div class="form-grid">
        <label>
          Interface Name
          {#if editing}
            <input value={form.name} disabled />
          {:else if form.vlan_id}
            <input bind:value={form.name} placeholder="e.g. vlan100" />
          {:else}
            <InterfaceSelect bind:value={form.name} placeholder="Select interface" exclude={usedNames} />
          {/if}
        </label>
        <label>
          Label
          <input bind:value={form.label} placeholder="e.g. WAN, LAN, IoT" />
        </label>
        <label>
          Method
          <select bind:value={form.method}>
            <option value="static">Static</option>
            <option value="dhcp">DHCP</option>
            <option value="pppoe">PPPoE</option>
          </select>
        </label>
      </div>

      {#if form.method === 'static'}
        <h4>Static Configuration</h4>
        <div class="form-grid">
          <label>
            Address (CIDR)
            <input bind:value={form.static_config.address} placeholder="192.168.1.1/24" />
          </label>
          <label>
            Gateway (set for WAN)
            <input bind:value={form.static_config.gateway} placeholder="leave empty for LAN" />
          </label>
        </div>

        <h4>Bridge Ports (optional)</h4>
        <InterfaceSelect bind:value={form.bridge_ports} multiple placeholder="Select bridge ports" />
      {:else if form.method === 'pppoe'}
        <h4>PPPoE Configuration</h4>
        <div class="form-grid">
          <label>
            Username
            <input bind:value={form.pppoe.username} placeholder="ISP username" />
          </label>
          <label>
            Password
            <input type="password" bind:value={form.pppoe.password} placeholder="ISP password" />
          </label>
          <label>
            MTU
            <input type="number" bind:value={form.pppoe.mtu} />
          </label>
          <label>
            MSS Clamp
            <select bind:value={form.pppoe.mss_clamp}>
              <option value={true}>Enabled</option>
              <option value={false}>Disabled</option>
            </select>
          </label>
        </div>
      {:else if form.method === 'dhcp'}
        <h4>DHCP Client Configuration</h4>
        <div class="form-grid">
          <label>
            Hostname (optional)
            <input bind:value={form.dhcp.hostname} placeholder="router" />
          </label>
        </div>
      {/if}

      <h4>VLAN (optional)</h4>
      <div class="form-grid">
        <label>
          VLAN ID
          <input type="number" bind:value={form.vlan_id} placeholder="leave empty if not VLAN" min="1" max="4094" />
        </label>
        <label>
          Parent Interface
          <InterfaceSelect bind:value={form.parent} placeholder="Select parent" />
        </label>
      </div>

      <div class="modal-actions">
        <button onclick={() => showModal = false}>Cancel</button>
        <button class="primary" onclick={handleSave}>
          {editing ? 'Update' : 'Create'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .interfaces-page { max-width: 1200px; }
  h2 { margin: 0 0 1.5rem; color: #f1f5f9; }
  h4 { margin: 1.25rem 0 0.5rem; color: #94a3b8; font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }
  .loading { color: #64748b; }
  .count { color: #94a3b8; font-size: 0.875rem; margin: 0; }
  .empty { color: #64748b; font-style: italic; }

  .section-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
  .btn-add { padding: 0.375rem 0.75rem; background: #1e40af; color: #e2e8f0; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8125rem; }
  .btn-add:hover { background: #2563eb; }

  /* Card list */
  .iface-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .iface-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; }
  .iface-header { display: flex; justify-content: space-between; align-items: center; }
  .iface-title { display: flex; align-items: baseline; gap: 0.625rem; }
  .iface-name { color: #f1f5f9; font-weight: 600; font-size: 1rem; font-family: 'SF Mono', 'Fira Code', monospace; }
  .iface-label { color: #94a3b8; font-size: 0.875rem; }
  .iface-method { color: #64748b; font-size: 0.8125rem; font-family: 'SF Mono', 'Fira Code', monospace; }
  .iface-actions { display: flex; gap: 0.375rem; }
  .iface-details { display: flex; align-items: center; gap: 0.375rem; margin-top: 0.5rem; font-size: 0.8125rem; color: #94a3b8; }
  .detail-sep { color: #64748b; }
  .label { color: #64748b; }
  .mono { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8125rem; }

  /* Toolbar */
  .toolbar { display: flex; gap: 0.5rem; margin-top: 1.5rem; }

  /* Buttons */
  button { padding: 0.5rem 1rem; background: #334155; color: #e2e8f0; border: none; border-radius: 6px; cursor: pointer; }
  button:hover { background: #475569; }
  button.primary { background: #3b82f6; }
  button.primary:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
  .btn-danger { background: #991b1b; }
  .btn-danger:hover { background: #dc2626; }

  /* Form */
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  .form-grid label { display: flex; flex-direction: column; gap: 0.25rem; color: #94a3b8; font-size: 0.8125rem; }
  select, input { background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; padding: 0.5rem; font-size: 0.875rem; }
  select:focus, input:focus { outline: none; border-color: #3b82f6; }
  input:disabled { opacity: 0.6; cursor: not-allowed; }

  /* Modal */
  .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; width: 580px; max-height: 85vh; overflow-y: auto; }
  .modal h3 { margin-bottom: 1.25rem; color: #f1f5f9; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem; }
</style>

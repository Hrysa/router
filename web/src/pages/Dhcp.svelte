<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getConfig, patchConfig, applyConfig, listDhcpLeases, addDhcpLease, deleteDhcpLease, getLeases } from '../lib/api';
  import { notify } from '../lib/stores';

  // ── State ───────────────────────────────────────────────────────────────────

  let dhcp = $state<any>(null);
  let staticLeases = $state<any[]>([]);
  let activeLeases = $state<any[]>([]);
  let loading = $state(true);
  let saving = $state(false);
  let applying = $state(false);

  // Tab state
  let activeTab = $state<'settings' | 'static' | 'leases'>('settings');

  // Pool modal state
  let showPoolModal = $state(false);
  let editingPoolIdx = $state<number | null>(null);
  let poolForm = $state(emptyPool());

  // Lease modal state
  let showLeaseModal = $state(false);
  let leaseForm = $state(emptyLease());

  // ── Helpers ─────────────────────────────────────────────────────────────────

  function emptyPool() {
    return { name: '', subnet: '', range_start: '', range_end: '', lease_time: '12h', domain: 'lan.local', dns_servers: '', gateway: '', enabled: true };
  }

  function emptyLease() {
    return { mac: '', ip: '', hostname: '' };
  }

  function poolToPayload(form: any) {
    return {
      name: form.name,
      subnet: form.subnet,
      range: { start: form.range_start, end: form.range_end },
      lease_time: form.lease_time,
      domain: form.domain,
      dns_servers: form.dns_servers.split(',').map((s: string) => s.trim()).filter(Boolean),
      gateway: form.gateway || '',
      enabled: form.enabled,
    };
  }

  function poolToForm(pool: any) {
    return {
      name: pool.name || '',
      subnet: pool.subnet || '',
      range_start: pool.range?.start || '',
      range_end: pool.range?.end || '',
      lease_time: pool.lease_time || '12h',
      domain: pool.domain || 'lan.local',
      dns_servers: (pool.dns_servers || []).join(', '),
      gateway: pool.gateway || '',
      enabled: pool.enabled ?? true,
    };
  }

  function error_msg(e: any): string {
    return e.response?.data?.error?.message || e.message || 'Unknown error';
  }

  // ── Data loading ────────────────────────────────────────────────────────────

  async function loadAll() {
    loading = true;
    try {
      const config = await getConfig();
      dhcp = config.dhcp;
      await Promise.all([reloadStaticLeases(), reloadActiveLeases()]);
    } catch (e) {
      notify('error', 'Failed to load DHCP config');
    } finally {
      loading = false;
    }
  }

  async function reloadStaticLeases() {
    try {
      const data = await listDhcpLeases();
      staticLeases = data.static_leases || [];
    } catch (e) {
      notify('error', 'Failed to reload leases');
    }
  }

  async function reloadActiveLeases() {
    try {
      const data = await getLeases();
      activeLeases = data.leases || [];
    } catch (e) {
      // silent — kea may not be running
    }
  }

  let leasesInterval: ReturnType<typeof setInterval>;

  onMount(() => {
    loadAll();
    // Poll active leases every 10 seconds
    leasesInterval = setInterval(reloadActiveLeases, 10000);
  });

  onDestroy(() => {
    if (leasesInterval) clearInterval(leasesInterval);
  });

  // ── DHCP settings save ──────────────────────────────────────────────────────

  async function handleSave() {
    saving = true;
    try {
      await patchConfig('dhcp', dhcp);
      notify('success', 'DHCP settings saved');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      saving = false;
    }
  }

  async function handleApply() {
    applying = true;
    try {
      await applyConfig();
      notify('success', 'DHCP settings applied');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      applying = false;
    }
  }

  // ── Pool CRUD (auto-saves to backend) ───────────────────────────────────────

  async function saveDhcp() {
    try {
      await patchConfig('dhcp', dhcp);
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  function openAddPool() {
    editingPoolIdx = null;
    poolForm = emptyPool();
    showPoolModal = true;
  }

  function openEditPool(idx: number) {
    editingPoolIdx = idx;
    poolForm = poolToForm(dhcp.pools[idx]);
    showPoolModal = true;
  }

  async function handleSavePool() {
    const pool = poolToPayload(poolForm);
    if (editingPoolIdx !== null) {
      dhcp.pools[editingPoolIdx] = pool;
      notify('success', `Pool "${pool.name}" updated`);
    } else {
      dhcp.pools = [...dhcp.pools, pool];
      notify('success', `Pool "${pool.name}" added`);
    }
    showPoolModal = false;
    await saveDhcp();
  }

  async function handleDeletePool(idx: number) {
    const name = dhcp.pools[idx].name;
    if (!confirm(`Delete pool "${name}"?`)) return;
    dhcp.pools = dhcp.pools.filter((_: any, i: number) => i !== idx);
    notify('success', `Pool "${name}" deleted`);
    await saveDhcp();
  }

  async function togglePoolEnabled(idx: number) {
    dhcp.pools[idx].enabled = !dhcp.pools[idx].enabled;
    dhcp = { ...dhcp }; // trigger reactivity
    await saveDhcp();
  }

  // ── Static lease CRUD ───────────────────────────────────────────────────────

  function openAddLease() {
    leaseForm = emptyLease();
    showLeaseModal = true;
  }

  async function handleSaveLease() {
    try {
      await addDhcpLease(leaseForm);
      notify('success', `Lease for ${leaseForm.mac} added`);
      showLeaseModal = false;
      await reloadLeases();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleDeleteLease(mac: string) {
    if (!confirm(`Delete lease for ${mac}?`)) return;
    try {
      await deleteDhcpLease(mac);
      notify('success', `Lease for ${mac} deleted`);
      await reloadLeases();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }
</script>

<div class="dhcp-page">
  <h2>DHCP</h2>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if dhcp}
    <!-- ── Sub-tabs ───────────────────────────────────────────────────────── -->
    <div class="tabs">
      <button class="tab" class:active={activeTab === 'settings'} onclick={() => activeTab = 'settings'}>Settings</button>
      <button class="tab" class:active={activeTab === 'static'} onclick={() => activeTab = 'static'}>Static Leases</button>
      <button class="tab" class:active={activeTab === 'leases'} onclick={() => activeTab = 'leases'}>Leases</button>
    </div>

    {#if activeTab === 'settings'}
      <!-- ── DHCP Pools ───────────────────────────────────────────────────── -->
      <section>
        <div class="section-header">
          <h3>Subnet Pools</h3>
          <button onclick={openAddPool} class="btn-add">+ Add Pool</button>
        </div>
        {#if dhcp.pools.length === 0}
          <p class="empty">No DHCP pools configured</p>
        {:else}
          {#each dhcp.pools as pool, idx}
            <div class="pool-card" class:disabled={pool.enabled === false}>
              <div class="pool-header">
                <div class="pool-title">
                  <span class="pool-name">{pool.name}</span>
                  <span class="pool-subnet">{pool.subnet}</span>
                </div>
                <div class="pool-actions">
                  <label class="switch">
                    <input type="checkbox" checked={pool.enabled} onchange={() => togglePoolEnabled(idx)} />
                    <span class="slider"></span>
                  </label>
                  <button class="btn-sm" onclick={() => openEditPool(idx)}>Edit</button>
                  <button class="btn-sm btn-danger" onclick={() => handleDeletePool(idx)}>Delete</button>
                </div>
              </div>
              <div class="pool-details">
                <div class="detail"><span class="label">Range</span> <span class="mono">{pool.range.start} – {pool.range.end}</span></div>
                <div class="detail"><span class="label">Lease</span> <span>{pool.lease_time}</span></div>
                <div class="detail"><span class="label">Domain</span> <span>{pool.domain}</span></div>
                <div class="detail"><span class="label">DNS</span> <span class="mono">{(pool.dns_servers || []).join(', ')}</span></div>
                {#if pool.gateway}
                  <div class="detail"><span class="label">Gateway</span> <span class="mono">{pool.gateway}</span></div>
                {/if}
              </div>
            </div>
          {/each}
        {/if}
      </section>
    {:else if activeTab === 'static'}
      <!-- ── Static Leases ────────────────────────────────────────────────── -->
      <section>
        <div class="section-header">
          <h3>Static Leases</h3>
          <button onclick={openAddLease} class="btn-add">+ Add Lease</button>
        </div>
        {#if staticLeases.length === 0}
          <p class="empty">No static leases configured</p>
        {:else}
          <table>
            <thead>
              <tr>
                <th>MAC Address</th>
                <th>IP Address</th>
                <th>Hostname</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each staticLeases as lease}
                <tr>
                  <td class="mono">{lease.mac}</td>
                  <td class="mono">{lease.ip}</td>
                  <td>{lease.hostname || '-'}</td>
                  <td class="actions">
                    <button class="btn-sm btn-danger" onclick={() => handleDeleteLease(lease.mac)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>
    {:else}
      <!-- ── Active Leases ─────────────────────────────────────────────────── -->
      <section>
        <div class="section-header">
          <h3>Active Leases</h3>
          <button class="btn-sm" onclick={reloadActiveLeases}>Refresh</button>
        </div>
        {#if activeLeases.length === 0}
          <p class="empty">No active leases</p>
        {:else}
          <table>
            <thead>
              <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Hostname</th>
                <th>Expires</th>
              </tr>
            </thead>
            <tbody>
              {#each activeLeases as lease}
                <tr>
                  <td class="mono">{lease.address}</td>
                  <td class="mono">{lease.mac}</td>
                  <td>{lease.hostname || '-'}</td>
                  <td class="mono">{lease.expires || '-'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/if}
      </section>
    {/if}

    <!-- ── Actions (only on settings tab) ──────────────────────────────────── -->
    {#if activeTab === 'settings'}
      <div class="toolbar">
        <button class="primary" onclick={handleApply} disabled={applying}>
          {applying ? 'Applying...' : 'Apply'}
        </button>
      </div>
    {/if}
  {/if}
</div>

<!-- ── Pool Modal ─────────────────────────────────────────────────────────── -->
{#if showPoolModal}
  <div class="modal-backdrop" onclick={() => showPoolModal = false}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>{editingPoolIdx !== null ? 'Edit Pool' : 'Add Pool'}</h3>
      <div class="form-grid">
        <label>
          Name
          <input bind:value={poolForm.name} placeholder="e.g. main, guest" disabled={editingPoolIdx !== null} />
        </label>
        <label>
          Subnet (CIDR)
          <input bind:value={poolForm.subnet} placeholder="192.168.1.0/24" />
        </label>
        <label>
          Range Start
          <input bind:value={poolForm.range_start} placeholder="192.168.1.100" />
        </label>
        <label>
          Range End
          <input bind:value={poolForm.range_end} placeholder="192.168.1.250" />
        </label>
        <label>
          Lease Time
          <input bind:value={poolForm.lease_time} placeholder="12h" />
        </label>
        <label>
          Domain
          <input bind:value={poolForm.domain} placeholder="lan.local" />
        </label>
        <label>
          DNS Servers
          <input bind:value={poolForm.dns_servers} placeholder="comma separated" />
        </label>
        <label>
          Gateway (optional)
          <input bind:value={poolForm.gateway} placeholder="auto from LAN IP" />
        </label>
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={poolForm.enabled} />
          Enabled
        </label>
      </div>
      <div class="modal-actions">
        <button onclick={() => showPoolModal = false}>Cancel</button>
        <button class="primary" onclick={handleSavePool}>
          {editingPoolIdx !== null ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ── Lease Modal ─────────────────────────────────────────────────────────── -->
{#if showLeaseModal}
  <div class="modal-backdrop" onclick={() => showLeaseModal = false}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>Add Static Lease</h3>
      <div class="form-grid">
        <label>
          MAC Address
          <input bind:value={leaseForm.mac} placeholder="aa:bb:cc:dd:ee:ff" />
        </label>
        <label>
          IP Address
          <input bind:value={leaseForm.ip} placeholder="192.168.1.50" />
        </label>
        <label>
          Hostname
          <input bind:value={leaseForm.hostname} placeholder="my-device (optional)" />
        </label>
      </div>
      <div class="modal-actions">
        <button onclick={() => showLeaseModal = false}>Cancel</button>
        <button class="primary" onclick={handleSaveLease}>Add</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .dhcp-page { max-width: 1200px; }
  h2 { margin: 0 0 1.5rem; color: #f1f5f9; }
  h3 { margin: 1.5rem 0 0.75rem; color: #94a3b8; font-size: 1rem; }
  .loading { color: #64748b; }

  /* Section header */
  /* Tabs */
  .tabs { display: flex; gap: 0; border-bottom: 1px solid #334155; margin-bottom: 1.5rem; }
  .tab { padding: 0.625rem 1.25rem; background: none; color: #94a3b8; border: none; border-bottom: 2px solid transparent; cursor: pointer; font-size: 0.875rem; font-weight: 500; transition: color 0.2s, border-color 0.2s; }
  .tab:hover { color: #e2e8f0; }
  .tab.active { color: #3b82f6; border-bottom-color: #3b82f6; }

  .section-header { display: flex; align-items: center; justify-content: space-between; margin: 1.5rem 0 0.75rem; }
  .section-header h3 { margin: 0; }
  .btn-add { padding: 0.375rem 0.75rem; background: #1e40af; color: #e2e8f0; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8125rem; }
  .btn-add:hover { background: #2563eb; }

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
  .checkbox-label { flex-direction: row !important; align-items: center; gap: 0.5rem !important; padding-top: 1.25rem; }
  .checkbox-label input { width: auto; }
  select, input { background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; padding: 0.5rem; font-size: 0.875rem; }
  select:focus, input:focus { outline: none; border-color: #3b82f6; }

  /* Pool card */
  .pool-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; }
  .pool-card.disabled { opacity: 0.5; }
  .pool-header { display: flex; justify-content: space-between; align-items: center; }
  .pool-title { display: flex; align-items: baseline; gap: 0.75rem; }
  .pool-name { color: #f1f5f9; font-weight: 600; font-size: 1rem; }
  .pool-subnet { color: #94a3b8; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8125rem; }
  .pool-actions { display: flex; align-items: center; gap: 0.5rem; }
  .pool-details { display: flex; flex-wrap: wrap; gap: 1.5rem; margin-top: 0.75rem; }
  .detail { display: flex; gap: 0.375rem; font-size: 0.8125rem; }
  .detail .label { color: #64748b; }
  .mono { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.8125rem; }

  /* Table */
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th, td { padding: 0.625rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
  th { background: #334155; color: #94a3b8; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
  .actions { text-align: right; }
  .empty { color: #64748b; font-style: italic; }

  /* Toggle switch */
  .switch { position: relative; display: inline-block; width: 2rem; height: 1.125rem; cursor: pointer; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; inset: 0; background: #475569; border-radius: 1.125rem; transition: background 0.2s; }
  .slider::before { content: ''; position: absolute; width: 0.875rem; height: 0.875rem; left: 0.125rem; bottom: 0.125rem; background: #e2e8f0; border-radius: 50%; transition: transform 0.2s; }
  .switch input:checked + .slider { background: #3b82f6; }
  .switch input:checked + .slider::before { transform: translateX(0.875rem); }

  /* Modal */
  .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; width: 520px; max-height: 85vh; overflow-y: auto; }
  .modal h3 { margin-bottom: 1rem; color: #f1f5f9; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.25rem; }
</style>

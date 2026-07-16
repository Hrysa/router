<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { getConfig, patchConfig, applyConfig, listDhcpLeases, addDhcpLease, deleteDhcpLease, getLeases } from '../lib/api';
  import { notify } from '../lib/stores';
  import { Tabs, Dialog, Portal, Switch } from '@skeletonlabs/skeleton-svelte';

  // ── State ───────────────────────────────────────────────────────────────────

  let dhcp = $state<any>(null);
  let staticLeases = $state<any[]>([]);
  let activeLeases = $state<any[]>([]);
  let loading = $state(true);
  let saving = $state(false);
  let applying = $state(false);

  // Tab state
  let activeTab = $state('settings');

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
      dns_servers: Array.isArray(pool.dns_servers) ? pool.dns_servers.join(', ') : (pool.dns_servers || ''),
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

<div class="max-w-6xl">
  <h2 class="h2 mb-6">DHCP</h2>

  {#if loading}
    <p class="text-surface-400">Loading...</p>
  {:else if dhcp}
    <Tabs value={activeTab} onValueChange={(e) => activeTab = e.value}>
      <Tabs.List>
        <Tabs.Trigger value="settings">Settings</Tabs.Trigger>
        <Tabs.Trigger value="static">Static Leases</Tabs.Trigger>
        <Tabs.Trigger value="leases">Leases</Tabs.Trigger>
      </Tabs.List>

      <Tabs.Content value="settings">
        <!-- DHCP Pools -->
        <section class="mb-6">
          <div class="flex items-center justify-between mb-3">
            <h3 class="h4">Subnet Pools</h3>
            <button class="btn preset-filled-primary-500 btn-sm" onclick={openAddPool}>+ Add Pool</button>
          </div>
          {#if dhcp.pools.length === 0}
            <p class="text-surface-500 italic">No DHCP pools configured</p>
          {:else}
            <div class="space-y-3">
              {#each dhcp.pools as pool, idx}
                <div class="card p-4 {pool.enabled === false ? 'opacity-50' : ''}">
                  <div class="flex justify-between items-center mb-3">
                    <div class="flex items-baseline gap-3">
                      <span class="font-semibold">{pool.name}</span>
                      <span class="font-mono text-sm text-surface-400">{pool.subnet}</span>
                    </div>
                    <div class="flex items-center gap-2">
                      <Switch checked={pool.enabled} onCheckedChange={() => togglePoolEnabled(idx)} />
                      <button class="btn preset-tonal btn-sm" onclick={() => openEditPool(idx)}>Edit</button>
                      <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeletePool(idx)}>Delete</button>
                    </div>
                  </div>
                  <div class="flex flex-wrap gap-x-6 gap-y-1 text-sm">
                    <div><span class="text-surface-500">Range</span> <span class="font-mono">{pool.range.start} – {pool.range.end}</span></div>
                    <div><span class="text-surface-500">Lease</span> {pool.lease_time}</div>
                    <div><span class="text-surface-500">Domain</span> {pool.domain}</div>
                    <div><span class="text-surface-500">DNS</span> <span class="font-mono">{Array.isArray(pool.dns_servers) ? pool.dns_servers.join(', ') : (pool.dns_servers || '')}</span></div>
                    {#if pool.gateway}
                      <div><span class="text-surface-500">Gateway</span> <span class="font-mono">{pool.gateway}</span></div>
                    {/if}
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </section>

        <div class="flex gap-2 mt-6">
          <button class="btn preset-filled-primary-500" onclick={handleApply} disabled={applying}>
            {applying ? 'Applying...' : 'Apply'}
          </button>
        </div>
      </Tabs.Content>

      <Tabs.Content value="static">
        <!-- Static Leases -->
        <section class="mb-6">
          <div class="flex items-center justify-between mb-3">
            <h3 class="h4">Static Leases</h3>
            <button class="btn preset-filled-primary-500 btn-sm" onclick={openAddLease}>+ Add Lease</button>
          </div>
          {#if staticLeases.length === 0}
            <p class="text-surface-500 italic">No static leases configured</p>
          {:else}
            <div class="table-wrap">
              <table class="table">
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
                      <td class="font-mono text-sm">{lease.mac}</td>
                      <td class="font-mono text-sm">{lease.ip}</td>
                      <td>{lease.hostname || '-'}</td>
                      <td class="text-right">
                        <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeleteLease(lease.mac)}>Delete</button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>
      </Tabs.Content>

      <Tabs.Content value="leases">
        <!-- Active Leases -->
        <section class="mb-6">
          <div class="flex items-center justify-between mb-3">
            <h3 class="h4">Active Leases</h3>
            <button class="btn preset-tonal btn-sm" onclick={reloadActiveLeases}>Refresh</button>
          </div>
          {#if activeLeases.length === 0}
            <p class="text-surface-500 italic">No active leases</p>
          {:else}
            <div class="table-wrap">
              <table class="table">
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
                      <td class="font-mono text-sm">{lease.address}</td>
                      <td class="font-mono text-sm">{lease.mac}</td>
                      <td>{lease.hostname || '-'}</td>
                      <td class="font-mono text-sm">{lease.expires || '-'}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        </section>
      </Tabs.Content>
    </Tabs>
  {/if}
</div>

<!-- Pool Modal -->
<Dialog open={showPoolModal} onOpenChange={(e) => showPoolModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[520px] max-h-[85vh] overflow-y-auto shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">{editingPoolIdx !== null ? 'Edit Pool' : 'Add Pool'}</Dialog.Title>
        <div class="grid grid-cols-2 gap-3">
          <label class="label">
            <span class="label-text">Name</span>
            <input class="input" bind:value={poolForm.name} placeholder="e.g. main, guest" disabled={editingPoolIdx !== null} />
          </label>
          <label class="label">
            <span class="label-text">Subnet (CIDR)</span>
            <input class="input" bind:value={poolForm.subnet} placeholder="192.168.1.0/24" />
          </label>
          <label class="label">
            <span class="label-text">Range Start</span>
            <input class="input" bind:value={poolForm.range_start} placeholder="192.168.1.100" />
          </label>
          <label class="label">
            <span class="label-text">Range End</span>
            <input class="input" bind:value={poolForm.range_end} placeholder="192.168.1.250" />
          </label>
          <label class="label">
            <span class="label-text">Lease Time</span>
            <input class="input" bind:value={poolForm.lease_time} placeholder="12h" />
          </label>
          <label class="label">
            <span class="label-text">Domain</span>
            <input class="input" bind:value={poolForm.domain} placeholder="lan.local" />
          </label>
          <label class="label">
            <span class="label-text">DNS Servers</span>
            <input class="input" bind:value={poolForm.dns_servers} placeholder="comma separated" />
          </label>
          <label class="label">
            <span class="label-text">Gateway (optional)</span>
            <input class="input" bind:value={poolForm.gateway} placeholder="auto from LAN IP" />
          </label>
          <label class="flex items-center gap-2 mt-4 col-span-2">
            <Switch checked={poolForm.enabled} onCheckedChange={(e) => poolForm.enabled = e.checked} />
            <span>Enabled</span>
          </label>
        </div>
        <div class="flex justify-end gap-2 mt-6">
          <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
          <button class="btn preset-filled-primary-500" onclick={handleSavePool}>
            {editingPoolIdx !== null ? 'Update' : 'Add'}
          </button>
        </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

<!-- Lease Modal -->
<Dialog open={showLeaseModal} onOpenChange={(e) => showLeaseModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[400px] shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">Add Static Lease</Dialog.Title>
        <div class="grid grid-cols-1 gap-3">
          <label class="label">
            <span class="label-text">MAC Address</span>
            <input class="input" bind:value={leaseForm.mac} placeholder="aa:bb:cc:dd:ee:ff" />
          </label>
          <label class="label">
            <span class="label-text">IP Address</span>
            <input class="input" bind:value={leaseForm.ip} placeholder="192.168.1.50" />
          </label>
          <label class="label">
            <span class="label-text">Hostname</span>
            <input class="input" bind:value={leaseForm.hostname} placeholder="my-device (optional)" />
          </label>
        </div>
        <div class="flex justify-end gap-2 mt-6">
          <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
          <button class="btn preset-filled-primary-500" onclick={handleSaveLease}>Add</button>
        </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

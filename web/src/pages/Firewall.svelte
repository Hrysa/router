<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import {
    getConfig, patchConfig, applyConfig,
    listFirewallRules, addFirewallRule, updateFirewallRule, deleteFirewallRule, moveFirewallRule,
    listNatRules, addPortForward, updatePortForward, deletePortForward, getFirewallStats,
    listNftSets, addNftSet, updateNftSet, deleteNftSet,
  } from '../lib/api';
  import { notify } from '../lib/stores';
  import InterfaceSelect from '../lib/InterfaceSelect.svelte';
  import { Dialog, Portal, Switch } from '@skeletonlabs/skeleton-svelte';

  // ── State ───────────────────────────────────────────────────────────────────

  let firewall = $state<any>(null);
  let inputRules = $state<any[]>([]);
  let forwardRules = $state<any[]>([]);
  let portForwards = $state<any[]>([]);
  let allInterfaces = $state<string[]>([]);
  let ruleStats = $state<Record<string, { packets: number; bytes: number }>>({});
  let loading = $state(true);
  let saving = $state(false);
  let applying = $state(false);

  // Rule modal state
  let showRuleModal = $state(false);
  let editingRule = $state<any>(null);
  let ruleChain = $state<'input' | 'forward'>('input');
  let ruleForm = $state(emptyRule());

  // Port forward modal state
  let showPfModal = $state(false);
  let editingPf = $state<any>(null);
  let pfForm = $state(emptyPortForward());

  // nftables set modal state
  let nftSets = $state<any[]>([]);
  let showSetModal = $state(false);
  let editingSet = $state<any>(null);
  let setForm = $state(emptyNftSet());

  // ── Helpers ─────────────────────────────────────────────────────────────────

  function emptyRule() {
    return {
      action: 'accept', comment: '', interfaces: [] as string[], oif: '', proto: [] as string[],
      dport: '', sport: '', saddr: '', daddr: '',
      interfaces_invert: false, saddr_invert: false, daddr_invert: false,
      state: '', rate: '', log: false, log_prefix: '',
      mark: '', tproxy_port: '', counter: false, enabled: true,
    };
  }

  function emptyPortForward() {
    return { comment: '', proto: 'tcp', target_port: '', target_address: '', source_address: '', interfaces: [] as string[], redirect_address: '', redirect_port: '', enabled: true,
      interfaces_invert: false, source_address_invert: false, target_address_invert: false };
  }

  function emptyNftSet() {
    return { name: '', set_type: 'ipv4_addr', elements: '', interval: false, comment: '' };
  }

  function ruleToPayload(form: any) {
    const rule: any = { id: form.id ?? 0, action: form.action, comment: form.comment, log: form.log, enabled: form.enabled };
    if (form.interfaces.length > 0) rule.interfaces = [...form.interfaces];
    if (form.interfaces_invert) rule.interfaces_invert = true;
    if (form.oif) rule.oif = form.oif;
    if (form.proto && form.proto.length > 0) rule.proto = [...form.proto];
    if (form.dport) rule.dport = parsePort(form.dport);
    if (form.sport) rule.sport = parsePort(form.sport);
    if (form.saddr) rule.saddr = form.saddr;
    if (form.saddr_invert) rule.saddr_invert = true;
    if (form.daddr) rule.daddr = form.daddr;
    if (form.daddr_invert) rule.daddr_invert = true;
    if (form.state && form.state.length > 0) rule.state = [...form.state];
    if (form.rate) rule.rate = form.rate;
    if (form.log_prefix) rule.log_prefix = form.log_prefix;
    if (form.mark !== '') rule.mark = Number(form.mark);
    if (form.tproxy_port !== '') rule.tproxy_port = Number(form.tproxy_port);
    rule.counter = form.counter;
    return rule;
  }

  function ruleToForm(rule: any) {
    return {
      id: rule.id ?? 0,
      action: rule.action || 'accept',
      comment: rule.comment || '',
      interfaces: [...(rule.interfaces || [])],
      interfaces_invert: rule.interfaces_invert || false,
      oif: rule.oif || '',
      proto: [...(rule.proto || [])],
      dport: formatPort(rule.dport),
      sport: formatPort(rule.sport),
      saddr: rule.saddr || '',
      saddr_invert: rule.saddr_invert || false,
      daddr: rule.daddr || '',
      daddr_invert: rule.daddr_invert || false,
      state: [...(rule.state || [])],
      rate: rule.rate || '',
      log: rule.log || false,
      log_prefix: rule.log_prefix || '',
      mark: rule.mark ?? '',
      tproxy_port: rule.tproxy_port ?? '',
      counter: rule.counter || false,
      enabled: rule.enabled ?? true,
    };
  }

  function parsePort(val: string): any {
    if (!val) return undefined;
    if (val.startsWith('@')) return val; // set reference
    if (val.includes('-')) {
      const [start, end] = val.split('-').map(Number);
      return { start, end };
    }
    if (val.includes(',')) {
      return val.split(',').map((s) => Number(s.trim()));
    }
    return Number(val);
  }

  function formatPort(port: any): string {
    if (!port) return '';
    if (typeof port === 'string') return port; // set reference
    if (typeof port === 'number') return String(port);
    if (Array.isArray(port)) return port.join(', ');
    if (port.start !== undefined) return `${port.start}-${port.end}`;
    return '';
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0) + ' ' + units[i];
  }

  function formatMatch(rule: any): string {
    const src = rule.saddr || '';
    const sport = formatPort(rule.sport) || '';
    const dst = rule.daddr || '';
    const dport = formatPort(rule.dport) || '';
    const left = src || sport ? `${src}${sport ? ':' + sport : ''}` : '';
    const right = dst || dport ? `${dst}${dport ? ':' + dport : ''}` : '';
    if (left && right) return `${left} → ${right}`;
    if (left) return `${left} → *`;
    if (right) return `* → ${right}`;
    return '*';
  }

  function formatStat(name: string): string {
    const s = ruleStats[name];
    if (!s) return '';
    return `${s.packets} pkts / ${formatBytes(s.bytes)}`;
  }

  function formatPfMatch(pf: any): string {
    const src = pf.source_address || '';
    const sport = '';
    const dst = pf.target_address || '';
    const dport = pf.target_port ? formatPort(pf.target_port) : '';
    const left = src || sport ? `${src}${sport ? ':' + sport : ''}` : '';
    const right = dst || dport ? `${dst}${dport ? ':' + dport : ''}` : '';
    if (left && right) return `${left} → ${right}`;
    if (left) return `${left} → *`;
    if (right) return `* → ${right}`;
    return '*';
  }

  function pfToPayload(form: any) {
    const payload: any = {
      id: form.id ?? 0,
      proto: form.proto,
      comment: form.comment,
      target_port: parsePort(form.target_port),
      redirect_address: form.redirect_address,
      redirect_port: parsePort(form.redirect_port),
      enabled: form.enabled,
    };
    if (form.interfaces.length > 0) payload.interfaces = [...form.interfaces];
    if (form.interfaces_invert) payload.interfaces_invert = true;
    if (form.target_address) payload.target_address = form.target_address;
    if (form.target_address_invert) payload.target_address_invert = true;
    if (form.source_address) payload.source_address = form.source_address;
    if (form.source_address_invert) payload.source_address_invert = true;
    return payload;
  }

  function error_msg(e: any): string {
    return e.response?.data?.error?.message || e.message || 'Unknown error';
  }

  // ── Data loading ────────────────────────────────────────────────────────────

  async function loadAll() {
    loading = true;
    try {
      const config = await getConfig();
      firewall = config.firewall;
      allInterfaces = (config.interfaces?.items ?? []).map((i: any) => i.name);
      await Promise.all([reloadRules(), reloadSets()]);
    } catch (e) {
      notify('error', 'Failed to load firewall config');
    } finally {
      loading = false;
    }
  }

  async function reloadRules() {
    try {
      const [rules, nat, stats] = await Promise.all([listFirewallRules(), listNatRules(), getFirewallStats()]);
      inputRules = rules.input || [];
      forwardRules = rules.forward || [];
      ruleStats = stats.stats || {};
      portForwards = nat.port_forward || [];
    } catch (e) {
      notify('error', 'Failed to reload rules');
    }
  }

  let statsInterval: ReturnType<typeof setInterval>;

  onMount(() => {
    loadAll();
    statsInterval = setInterval(async () => {
      try {
        const stats = await getFirewallStats();
        ruleStats = stats.stats || {};
      } catch { /* ignore */ }
    }, 3000);
  });

  onDestroy(() => {
    if (statsInterval) clearInterval(statsInterval);
  });

  // ── Default policies ────────────────────────────────────────────────────────

  async function handleSavePolicies() {
    saving = true;
    try {
      await patchConfig('firewall', firewall);
      notify('success', 'Default policies saved');
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
      notify('success', 'Firewall rules applied');
    } catch (e: any) {
      notify('error', error_msg(e));
    } finally {
      applying = false;
    }
  }

  // ── Rule CRUD ───────────────────────────────────────────────────────────────

  function openAddRule(chain: 'input' | 'forward' = 'input') {
    editingRule = null;
    ruleChain = chain;
    ruleForm = emptyRule();
    showRuleModal = true;
  }

  function openEditRule(rule: any) {
    editingRule = rule;
    ruleForm = ruleToForm(rule);
    showRuleModal = true;
  }

  async function handleSaveRule() {
    try {
      const payload = ruleToPayload(ruleForm);
      if (editingRule) {
        await updateFirewallRule(editingRule.id, payload);
        notify('success', `Rule "${payload.comment}" updated`);
      } else {
        await addFirewallRule(payload, ruleChain);
        notify('success', `Rule "${payload.comment}" added`);
      }
      showRuleModal = false;
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function toggleRuleEnabled(rule: any) {
    try {
      const payload = ruleToPayload(ruleToForm(rule));
      payload.enabled = !rule.enabled;
      await updateFirewallRule(rule.id, payload);
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function togglePfEnabled(pf: any) {
    try {
      const payload = { ...pf, enabled: !pf.enabled };
      await updatePortForward(pf.id, payload);
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleDeleteRule(id: number) {
    if (!confirm(`Delete this rule?`)) return;
    try {
      await deleteFirewallRule(id);
      notify('success', 'Rule deleted');
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleMoveRule(id: number, direction: 'up' | 'down') {
    try {
      await moveFirewallRule(id, direction);
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  // ── Port forward CRUD ──────────────────────────────────────────────────────

  function openAddPf() {
    editingPf = null;
    pfForm = emptyPortForward();
    showPfModal = true;
  }

  function openEditPf(pf: any) {
    editingPf = pf;
    pfForm = {
      id: pf.id ?? 0,
      comment: pf.comment || '',
      proto: pf.proto,
      target_port: formatPort(pf.target_port),
      target_address: pf.target_address || '',
      target_address_invert: pf.target_address_invert || false,
      source_address: pf.source_address || '',
      source_address_invert: pf.source_address_invert || false,
      interfaces: [...(pf.interfaces || [])],
      interfaces_invert: pf.interfaces_invert || false,
      redirect_address: pf.redirect_address,
      redirect_port: formatPort(pf.redirect_port),
      enabled: pf.enabled,
    };
    showPfModal = true;
  }

  async function handleSavePf() {
    try {
      const payload = pfToPayload(pfForm);
      if (editingPf) {
        await updatePortForward(editingPf.id, payload);
        notify('success', `Port forward "${pfForm.comment}" updated`);
      } else {
        await addPortForward(payload);
        notify('success', `Port forward "${pfForm.comment}" added`);
      }
      showPfModal = false;
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleDeletePf(id: number) {
    if (!confirm(`Delete this port forward?`)) return;
    try {
      await deletePortForward(id);
      notify('success', 'Port forward deleted');
      await reloadRules();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  // ── nftables Sets CRUD ────────────────────────────────────────────────────

  async function reloadSets() {
    try {
      const data = await listNftSets();
      nftSets = data.sets || [];
    } catch (e) {
      notify('error', 'Failed to load sets');
    }
  }

  function openAddSet() {
    editingSet = null;
    setForm = emptyNftSet();
    showSetModal = true;
  }

  function openEditSet(set: any) {
    editingSet = set;
    setForm = {
      name: set.name,
      set_type: set.set_type || 'ipv4_addr',
      elements: set.elements || '',
      interval: set.interval || false,
      comment: set.comment || '',
    };
    showSetModal = true;
  }

  async function handleSaveSet() {
    const payload: any = {
      name: setForm.name,
      set_type: setForm.set_type,
      elements: setForm.elements,
      interval: setForm.interval,
    };
    if (setForm.comment) payload.comment = setForm.comment;
    try {
      if (editingSet) {
        await updateNftSet(editingSet.name, payload);
        notify('success', `Set "${setForm.name}" updated`);
      } else {
        await addNftSet(payload);
        notify('success', `Set "${setForm.name}" added`);
      }
      showSetModal = false;
      await reloadSets();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }

  async function handleDeleteSet(name: string) {
    if (!confirm(`Delete set "${name}"?`)) return;
    try {
      await deleteNftSet(name);
      notify('success', `Set "${name}" deleted`);
      await reloadSets();
    } catch (e: any) {
      notify('error', error_msg(e));
    }
  }
</script>

<div class="max-w-6xl">
  <h2 class="h2 mb-6">Firewall</h2>

  {#if loading}
    <p class="text-surface-400">Loading...</p>
  {:else if firewall}
    <!-- Default Policies -->
    <section class="mb-6">
      <h3 class="h4 mb-2">Default Policies</h3>
      <div class="flex items-end gap-4 mb-4">
        <label class="label">
          <span class="label-text">Input</span>
          <select class="input w-32" bind:value={firewall.default_policy.input}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </label>
        <label class="label">
          <span class="label-text">Forward</span>
          <select class="input w-32" bind:value={firewall.default_policy.forward}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </label>
        <label class="label">
          <span class="label-text">Output</span>
          <select class="input w-32" bind:value={firewall.default_policy.output}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </label>
        <button class="btn preset-tonal" onclick={handleSavePolicies} disabled={saving}>
          {saving ? 'Saving...' : 'Save Policies'}
        </button>
      </div>
    </section>

    <!-- Input Rules -->
    <section class="mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="h4">Input Rules</h3>
        <button class="btn preset-filled-primary-500 btn-sm" onclick={() => openAddRule()}>+ Add Rule</button>
      </div>
      {#if inputRules.length === 0}
        <p class="text-surface-500 italic">No input rules</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Action</th>
                <th>Interface</th>
                <th>Protocol</th>
                <th>Match</th>
                <th>Log</th>
                <th>Counter</th>
                <th>Comment</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each inputRules as rule, idx}
                <tr class={rule.enabled === false ? 'opacity-50' : ''}>
                  <td><button class="badge cursor-pointer {rule.action === 'accept' ? 'preset-filled-success-500' : rule.action === 'drop' ? 'preset-filled-error-500' : 'preset-filled-warning-500'}" onclick={() => toggleRuleEnabled(rule)} title={rule.enabled !== false ? 'Click to disable' : 'Click to enable'}>{rule.action}</button></td>
                  <td class="text-sm">{Array.isArray(rule.interfaces) ? rule.interfaces.join(', ') : (rule.interfaces || '*')}</td>
                  <td class="text-sm">{Array.isArray(rule.proto) ? rule.proto.join(', ') : (rule.proto || '*')}</td>
                  <td class="font-mono text-xs whitespace-nowrap">{formatMatch(rule)}</td>
                  <td>{rule.log ? '✓' : ''}</td>
                  <td class="font-mono text-xs text-surface-400 whitespace-nowrap">{rule.counter ? formatStat(rule.comment) : ''}</td>
                  <td class="text-sm text-surface-400 max-w-48 truncate">{rule.comment}</td>
                  <td class="text-right whitespace-nowrap">
                    <button class="btn-icon preset-tonal btn-sm" disabled={idx === 0} onclick={() => handleMoveRule(rule.id, 'up')} title="Move up">↑</button>
                    <button class="btn-icon preset-tonal btn-sm" disabled={idx === inputRules.length - 1} onclick={() => handleMoveRule(rule.id, 'down')} title="Move down">↓</button>
                    <button class="btn preset-tonal btn-sm" onclick={() => openEditRule(rule)}>Edit</button>
                    <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeleteRule(rule.id)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Forward Rules -->
    <section class="mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="h4">Forward Rules</h3>
        <button class="btn preset-filled-primary-500 btn-sm" onclick={() => openAddRule('forward')}>+ Add Rule</button>
      </div>
      {#if forwardRules.length === 0}
        <p class="text-surface-500 italic">No forward rules</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Action</th>
                <th>In Interface</th>
                <th>Out Interface</th>
                <th>Protocol</th>
                <th>Match</th>
                <th>Log</th>
                <th>Counter</th>
                <th>Comment</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each forwardRules as rule, idx}
                <tr class={rule.enabled === false ? 'opacity-50' : ''}>
                  <td><button class="badge cursor-pointer {rule.action === 'accept' ? 'preset-filled-success-500' : rule.action === 'drop' ? 'preset-filled-error-500' : 'preset-filled-warning-500'}" onclick={() => toggleRuleEnabled(rule)} title={rule.enabled !== false ? 'Click to disable' : 'Click to enable'}>{rule.action}</button></td>
                  <td class="text-sm">{Array.isArray(rule.interfaces) ? rule.interfaces.join(', ') : (rule.interfaces || '*')}</td>
                  <td class="text-sm">{rule.oif || '*'}</td>
                  <td class="text-sm">{rule.proto && rule.proto.length ? rule.proto.join(', ') : '*'}</td>
                  <td class="font-mono text-xs whitespace-nowrap">{formatMatch(rule)}</td>
                  <td>{rule.log ? '✓' : ''}</td>
                  <td class="font-mono text-xs text-surface-400 whitespace-nowrap">{rule.counter ? formatStat(rule.comment) : ''}</td>
                  <td class="text-sm text-surface-400 max-w-48 truncate">{rule.comment}</td>
                  <td class="text-right whitespace-nowrap">
                    <button class="btn-icon preset-tonal btn-sm" disabled={idx === 0} onclick={() => handleMoveRule(rule.id, 'up')} title="Move up">↑</button>
                    <button class="btn-icon preset-tonal btn-sm" disabled={idx === forwardRules.length - 1} onclick={() => handleMoveRule(rule.id, 'down')} title="Move down">↓</button>
                    <button class="btn preset-tonal btn-sm" onclick={() => openEditRule(rule)}>Edit</button>
                    <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeleteRule(rule.id)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Port Forwarding -->
    <section class="mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="h4">Port Forwarding (DNAT)</h3>
        <button class="btn preset-filled-primary-500 btn-sm" onclick={openAddPf}>+ Add Port Forward</button>
      </div>
      {#if portForwards.length === 0}
        <p class="text-surface-500 italic">No port forwards configured</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Source → Target</th>
                <th>Protocol</th>
                <th>Interfaces</th>
                <th>Redirect</th>
                <th>Enabled</th>
                <th>Comment</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {#each portForwards as pf}
                <tr class={!pf.enabled ? 'opacity-50' : ''}>
                  <td class="font-mono text-xs whitespace-nowrap">{formatPfMatch(pf)}</td>
                  <td class="text-sm">{pf.proto}</td>
                  <td class="text-sm">{Array.isArray(pf.interfaces) ? pf.interfaces.join(', ') : (pf.interfaces || '*')}</td>
                  <td class="font-mono text-xs">{pf.redirect_address}:{formatPort(pf.redirect_port)}</td>
                  <td><Switch checked={pf.enabled} onCheckedChange={() => togglePfEnabled(pf)} /></td>
                  <td class="text-sm text-surface-400 max-w-48 truncate">{pf.comment}</td>
                  <td class="text-right whitespace-nowrap">
                    <button class="btn preset-tonal btn-sm" onclick={() => openEditPf(pf)}>Edit</button>
                    <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeletePf(pf.id)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- nftables Sets -->
    <section class="mb-6">
      <div class="flex items-center justify-between mb-3">
        <h3 class="h4">nftables Sets</h3>
        <button class="btn preset-filled-primary-500 btn-sm" onclick={openAddSet}>+ Add Set</button>
      </div>
      {#if nftSets.length === 0}
        <p class="text-surface-500 italic">No sets configured</p>
      {:else}
        <div class="table-wrap">
          <table class="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Interval</th>
                <th>Elements</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {#each nftSets as set}
                <tr>
                  <td class="font-mono text-sm">@{set.name}</td>
                  <td class="text-sm">{set.set_type}</td>
                  <td class="text-sm">{set.interval ? 'Yes' : 'No'}</td>
                  <td class="font-mono text-sm">{(set.elements || '').split('\n').filter((e: string) => e.trim()).length}</td>
                  <td class="text-right whitespace-nowrap">
                    <button class="btn preset-tonal btn-sm" onclick={() => openEditSet(set)}>Edit</button>
                    <button class="btn preset-filled-error-500 btn-sm" onclick={() => handleDeleteSet(set.name)}>Delete</button>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>

    <!-- Apply -->
    <div class="flex gap-2 mt-6">
      <button class="btn preset-filled-primary-500" onclick={handleApply} disabled={applying}>
        {applying ? 'Applying...' : 'Apply Firewall Rules'}
      </button>
    </div>
  {/if}
</div>

<!-- Rule Modal -->
<Dialog open={showRuleModal} onOpenChange={(e) => showRuleModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[680px] max-h-[85vh] overflow-y-auto shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">{editingRule ? 'Edit Rule' : 'Add Rule'}</Dialog.Title>
      <div class="grid grid-cols-2 gap-3">
        <label class="label">
          <span class="label-text">Action</span>
          <select class="input" bind:value={ruleForm.action}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
            <option value="tproxy">TPROXY</option>
          </select>
        </label>
        {#if ruleForm.action === 'tproxy'}
          <label class="label">
            <span class="label-text">Mark (fwmark)</span>
            <input class="input" type="number" bind:value={ruleForm.mark} placeholder="e.g. 1" />
          </label>
          <label class="label">
            <span class="label-text">TPROXY Port</span>
            <input class="input" type="number" bind:value={ruleForm.tproxy_port} placeholder="e.g. 12345" />
          </label>
        {/if}

        <label class="label col-span-2">
          <span class="label-text">Interfaces</span>
          <InterfaceSelect bind:value={ruleForm.interfaces} multiple placeholder="Select interfaces" items={allInterfaces} />
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={ruleForm.interfaces_invert} />
            <span class="text-sm">Invert (NOT these interfaces)</span>
          </label>
        </label>
        <label class="label">
          <span class="label-text">Out Interface (oif)</span>
          <input class="input" bind:value={ruleForm.oif} placeholder="e.g. wan0 (sets chain to forward)" />
        </label>
        <label class="label col-span-2">
          <InterfaceSelect
            bind:value={ruleForm.proto}
            multiple
            placeholder="Select protocols"
            items={['tcp', 'udp', 'icmp', 'ip', 'ip6', 'gre', 'esp', 'ah']}
          />
        </label>
        <label class="label">
          <span class="label-text">Source Address</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={ruleForm.saddr} placeholder="e.g. 192.168.1.0/24" />
            <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.saddr = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr' || s.set_type === 'ether_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={ruleForm.saddr_invert} />
            <span class="text-sm">Invert (NOT this address)</span>
          </label>
        </label>
        <label class="label">
          <span class="label-text">Source Port</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={ruleForm.sport} placeholder="e.g. 53" />
            {#if nftSets.length > 0}
              <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.sport = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
                <option value="">@set</option>
                {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                  <option value={s.name}>{s.name}</option>
                {/each}
              </select>
            {/if}
          </div>
        </label>
        <label class="label">
          <span class="label-text">Dest Address</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={ruleForm.daddr} placeholder="e.g. 10.0.0.1" />
            <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.daddr = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr' || s.set_type === 'ether_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={ruleForm.daddr_invert} />
            <span class="text-sm">Invert (NOT this address)</span>
          </label>
        </label>
        <label class="label">
          <span class="label-text">Dest Port</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={ruleForm.dport} placeholder="80, 443, 8000-9000" />
            {#if nftSets.length > 0}
              <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.dport = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
                <option value="">@set</option>
                {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                  <option value={s.name}>{s.name}</option>
                {/each}
              </select>
            {/if}
          </div>
        </label>
        <label class="label col-span-2">
          <span class="label-text">State</span>
          <InterfaceSelect bind:value={ruleForm.state} multiple placeholder="Select states" items={['established', 'related', 'new', 'invalid']} />
        </label>

        <label class="label">
          <span class="label-text">Rate Limit</span>
          <input class="input" bind:value={ruleForm.rate} placeholder="e.g. 10/second" />
        </label>
        <label class="flex items-center gap-2 mt-6">
          <input type="checkbox" class="checkbox" bind:checked={ruleForm.log} />
          <span>Log</span>
        </label>
        {#if ruleForm.log}
          <label class="label">
            <span class="label-text">Log Prefix</span>
            <input class="input" bind:value={ruleForm.log_prefix} placeholder="e.g. [SSH]" />
          </label>
        {/if}
        <label class="flex items-center gap-2 mt-6">
          <input type="checkbox" class="checkbox" bind:checked={ruleForm.counter} />
          <span>Counter</span>
        </label>
        <label class="flex items-center gap-2 mt-6">
          <input type="checkbox" class="checkbox" bind:checked={ruleForm.enabled} />
          <span>Enabled</span>
        </label>

        <label class="label col-span-2">
          <span class="label-text">Comment</span>
          <input class="input" bind:value={ruleForm.comment} placeholder="e.g. allow-ssh" />
        </label>
      </div>
      <div class="flex justify-end gap-2 mt-6">
        <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
        <button class="btn preset-filled-primary-500" onclick={handleSaveRule}>
          {editingRule ? 'Update' : 'Add'}
        </button>
      </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

<!-- Port Forward Modal -->
<Dialog open={showPfModal} onOpenChange={(e) => showPfModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[520px] max-h-[85vh] overflow-y-auto shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">{editingPf ? 'Edit Port Forward' : 'Add Port Forward'}</Dialog.Title>
      <div class="grid grid-cols-2 gap-3">
        <label class="label">
          <span class="label-text">Protocol</span>
          <select class="input" bind:value={pfForm.proto}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="tcp+udp">TCP + UDP</option>
            <option value="icmp">ICMP</option>
            <option value="gre">GRE</option>
            <option value="esp">ESP</option>
            <option value="ah">AH</option>
          </select>
        </label>
        <label class="label col-span-2">
          <span class="label-text">Interfaces</span>
          <InterfaceSelect bind:value={pfForm.interfaces} multiple placeholder="Select interfaces" items={allInterfaces} />
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={pfForm.interfaces_invert} />
            <span class="text-sm">Invert (NOT these interfaces)</span>
          </label>
        </label>
        <label class="label">
          <span class="label-text">Source Address (optional)</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={pfForm.source_address} placeholder="e.g. 10.0.0.0/8 (any)" />
            <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.source_address = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr' || s.set_type === 'ether_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={pfForm.source_address_invert} />
            <span class="text-sm">Invert (NOT this address)</span>
          </label>
        </label>
        <label></label>
        <label class="label">
          <span class="label-text">Target Address (optional)</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={pfForm.target_address} placeholder="e.g. 1.2.3.4 (any)" />
            <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.target_address = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr' || s.set_type === 'ether_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
          <label class="flex items-center gap-2 mt-1">
            <input type="checkbox" class="checkbox" bind:checked={pfForm.target_address_invert} />
            <span class="text-sm">Invert (NOT this address)</span>
          </label>
        </label>
        {#if pfForm.proto === 'tcp' || pfForm.proto === 'udp' || pfForm.proto === 'tcp+udp'}
        <label class="label">
          <span class="label-text">Target Port</span>
          <div class="flex flex-col gap-1">
            <input class="input" bind:value={pfForm.target_port} placeholder="80" />
            <select class="input text-xs" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.target_port = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>
        {/if}

        <label class="label">
          <span class="label-text">Redirect Address</span>
          <input class="input" bind:value={pfForm.redirect_address} placeholder="192.168.1.100" />
        </label>
        {#if pfForm.proto === 'tcp' || pfForm.proto === 'udp' || pfForm.proto === 'tcp+udp'}
        <label class="label">
          <span class="label-text">Redirect Port</span>
          <input class="input" bind:value={pfForm.redirect_port} placeholder="8080" />
        </label>
        {/if}

        <label class="flex items-center gap-2 mt-6">
          <input type="checkbox" class="checkbox" bind:checked={pfForm.enabled} />
          <span>Enabled</span>
        </label>

        <label class="label">
          <span class="label-text">Comment</span>
          <input class="input" bind:value={pfForm.comment} placeholder="e.g. web-server" />
        </label>
      </div>
      <div class="flex justify-end gap-2 mt-6">
        <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
        <button class="btn preset-filled-primary-500" onclick={handleSavePf}>
          {editingPf ? 'Update' : 'Add'}
        </button>
      </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

<!-- nftables Set Modal -->
<Dialog open={showSetModal} onOpenChange={(e) => showSetModal = e.open}>
  <Portal>
    <Dialog.Backdrop class="fixed inset-0 z-50 bg-black/30" />
    <Dialog.Positioner class="fixed inset-0 z-50 flex items-center justify-center p-4">
      <Dialog.Content class="card bg-white p-6 w-[480px] max-h-[85vh] overflow-y-auto shadow-xl border border-surface-200">
        <Dialog.Title class="h3 mb-4">{editingSet ? 'Edit Set' : 'Add Set'}</Dialog.Title>
      <div class="grid grid-cols-2 gap-3">
        <label class="label">
          <span class="label-text">Set Name</span>
          <input class="input" bind:value={setForm.name} placeholder="e.g. blocked_ips" disabled={!!editingSet} />
        </label>
        <label class="label">
          <span class="label-text">Element Type</span>
          <select class="input" bind:value={setForm.set_type}>
            <option value="ipv4_addr">IPv4 Address</option>
            <option value="ipv6_addr">IPv6 Address</option>
            <option value="inet_service">Port (inet_service)</option>
            <option value="ether_addr">MAC Address</option>
          </select>
        </label>
        <label class="label col-span-2">
          <span class="label-text">Elements (one per line)</span>
          <textarea
            class="textarea font-mono text-sm"
            bind:value={setForm.elements}
            rows="8"
            placeholder="192.168.1.100&#10;10.0.0.0/8&#10;172.16.0.0/12"
            spellcheck="false"
          ></textarea>
        </label>
        <label class="flex items-center gap-2 col-span-2">
          <input type="checkbox" class="checkbox" bind:checked={setForm.interval} />
          <span>Interval (support CIDR ranges)</span>
        </label>
        <label class="label col-span-2">
          <span class="label-text">Comment</span>
          <input class="input" bind:value={setForm.comment} placeholder="Optional description" />
        </label>
      </div>
      <div class="flex justify-end gap-2 mt-6">
        <Dialog.CloseTrigger class="btn preset-tonal">Cancel</Dialog.CloseTrigger>
        <button class="btn preset-filled-primary-500" onclick={handleSaveSet}>
          {editingSet ? 'Update' : 'Add'}
        </button>
      </div>
      </Dialog.Content>
    </Dialog.Positioner>
  </Portal>
</Dialog>

<style>
  .btn-icon { min-width: 2rem; padding: 0.25rem 0.5rem; }
</style>

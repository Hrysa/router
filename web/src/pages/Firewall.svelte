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
      action: 'accept', comment: '', interfaces: [] as string[], oif: '', proto: '',
      dport: '', sport: '', saddr: '', daddr: '',
      state: '', rate: '', log: false, log_prefix: '',
      mark: '', tproxy_port: '', counter: false, enabled: true,
    };
  }

  function emptyPortForward() {
    return { comment: '', proto: 'tcp', target_port: '', target_address: '', source_address: '', interfaces: [] as string[], redirect_address: '', redirect_port: '', enabled: true };
  }

  function emptyNftSet() {
    return { name: '', set_type: 'ipv4_addr', elements: '', interval: false, comment: '' };
  }

  function ruleToPayload(form: any) {
    const rule: any = { id: form.id ?? 0, action: form.action, comment: form.comment, log: form.log, enabled: form.enabled };
    if (form.interfaces.length > 0) rule.interfaces = [...form.interfaces];
    if (form.oif) rule.oif = form.oif;
    if (form.proto) rule.proto = form.proto;
    if (form.dport) rule.dport = parsePort(form.dport);
    if (form.sport) rule.sport = parsePort(form.sport);
    if (form.saddr) rule.saddr = form.saddr;
    if (form.daddr) rule.daddr = form.daddr;
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
      oif: rule.oif || '',
      proto: rule.proto || '',
      dport: formatPort(rule.dport),
      sport: formatPort(rule.sport),
      saddr: rule.saddr || '',
      daddr: rule.daddr || '',
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
    if (form.target_address) payload.target_address = form.target_address;
    if (form.source_address) payload.source_address = form.source_address;
    if (form.interfaces.length > 0) payload.interfaces = [...form.interfaces];
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
      // Build available interfaces list from config
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
    // Poll counter stats every 3 seconds
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
      source_address: pf.source_address || '',
      interfaces: [...(pf.interfaces || [])],
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

<div class="firewall-page">
  <h2>Firewall</h2>

  {#if loading}
    <p class="loading">Loading...</p>
  {:else if firewall}
    <!-- ── Default Policies ──────────────────────────────────────────────── -->
    <section>
      <h3>Default Policies</h3>
      <div class="policies">
        <div class="policy">
          <label>Input</label>
          <select bind:value={firewall.default_policy.input}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </div>
        <div class="policy">
          <label>Forward</label>
          <select bind:value={firewall.default_policy.forward}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </div>
        <div class="policy">
          <label>Output</label>
          <select bind:value={firewall.default_policy.output}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
          </select>
        </div>
        <button onclick={handleSavePolicies} disabled={saving} class="save-policies">
          {saving ? 'Saving...' : 'Save Policies'}
        </button>
      </div>
    </section>

    <!-- ── Input Rules ──────────────────────────────────────────────────── -->
    <section>
      <div class="section-header">
        <h3>Input Rules</h3>
        <button onclick={() => openAddRule()} class="btn-add">+ Add Rule</button>
      </div>
      {#if inputRules.length === 0}
        <p class="empty">No input rules</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>Interface</th>
              <th>Protocol</th>
              <th>Match</th>
              <th>Log</th>
              <th>Counter</th>
              <th>Enabled</th>
              <th>Comment</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each inputRules as rule, idx}
              <tr class:disabled={rule.enabled === false}>
                <td><span class="action {rule.action}">{rule.action}</span></td>
                <td>{(rule.interfaces && rule.interfaces.length) ? rule.interfaces.join(', ') : '*'}</td>
                <td>{rule.proto || '*'}</td>
                <td class="match">{formatMatch(rule)}</td>
                <td>{rule.log ? '✓' : ''}</td>
                <td class="stat">{rule.counter ? formatStat(rule.comment) : ''}</td>
                <td><label class="switch"><input type="checkbox" checked={rule.enabled !== false} onchange={() => toggleRuleEnabled(rule)} /><span class="slider"></span></label></td>
                <td class="comment-cell">{rule.comment}</td>
                <td class="actions">
                  <button class="btn-icon" disabled={idx === 0} onclick={() => handleMoveRule(rule.id, 'up')} title="Move up">↑</button>
                  <button class="btn-icon" disabled={idx === inputRules.length - 1} onclick={() => handleMoveRule(rule.id, 'down')} title="Move down">↓</button>
                  <button class="btn-sm" onclick={() => openEditRule(rule)}>Edit</button>
                  <button class="btn-sm btn-danger" onclick={() => handleDeleteRule(rule.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <!-- ── Forward Rules ────────────────────────────────────────────────── -->
    <section>
      <div class="section-header">
        <h3>Forward Rules</h3>
        <button onclick={() => openAddRule('forward')} class="btn-add">+ Add Rule</button>
      </div>
      {#if forwardRules.length === 0}
        <p class="empty">No forward rules</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Action</th>
              <th>In Interface</th>
              <th>Out Interface</th>
              <th>Protocol</th>
              <th>Match</th>
              <th>Log</th>
              <th>Counter</th>
              <th>Enabled</th>
              <th>Comment</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each forwardRules as rule, idx}
              <tr class:disabled={rule.enabled === false}>
                <td><span class="action {rule.action}">{rule.action}</span></td>
                <td>{(rule.interfaces && rule.interfaces.length) ? rule.interfaces.join(', ') : '*'}</td>
                <td>{rule.oif || '*'}</td>
                <td>{rule.proto || '*'}</td>
                <td class="match">{formatMatch(rule)}</td>
                <td>{rule.log ? '✓' : ''}</td>
                <td class="stat">{rule.counter ? formatStat(rule.comment) : ''}</td>
                <td><label class="switch"><input type="checkbox" checked={rule.enabled !== false} onchange={() => toggleRuleEnabled(rule)} /><span class="slider"></span></label></td>
                <td class="comment-cell">{rule.comment}</td>
                <td class="actions">
                  <button class="btn-icon" disabled={idx === 0} onclick={() => handleMoveRule(rule.id, 'up')} title="Move up">↑</button>
                  <button class="btn-icon" disabled={idx === forwardRules.length - 1} onclick={() => handleMoveRule(rule.id, 'down')} title="Move down">↓</button>
                  <button class="btn-sm" onclick={() => openEditRule(rule)}>Edit</button>
                  <button class="btn-sm btn-danger" onclick={() => handleDeleteRule(rule.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <!-- ── Port Forwarding ──────────────────────────────────────────────── -->
    <section>
      <div class="section-header">
        <h3>Port Forwarding (DNAT)</h3>
        <button onclick={openAddPf} class="btn-add">+ Add Port Forward</button>
      </div>
      {#if portForwards.length === 0}
        <p class="empty">No port forwards configured</p>
      {:else}
        <table>
          <thead>
            <tr>
              <th>Source</th>
              <th>Target</th>
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
              <tr class:disabled={!pf.enabled}>
                <td class="match">{pf.source_address ? pf.source_address + ' ' : ''}</td>
                <td class="match">{pf.target_address ? pf.target_address + ':' : ''}{formatPort(pf.target_port)}</td>
                <td>{pf.proto}</td>
                <td>{(pf.interfaces && pf.interfaces.length) ? pf.interfaces.join(', ') : '*'}</td>
                <td class="match">{pf.redirect_address}:{formatPort(pf.redirect_port)}</td>
                <td><label class="switch"><input type="checkbox" checked={pf.enabled} onchange={() => togglePfEnabled(pf)} /><span class="slider"></span></label></td>
                <td class="comment-cell">{pf.comment}</td>
                <td class="actions">
                  <button class="btn-sm" onclick={() => openEditPf(pf)}>Edit</button>
                  <button class="btn-sm btn-danger" onclick={() => handleDeletePf(pf.id)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <!-- ── nftables Sets ───────────────────────────────────────────────── -->
    <section>
      <div class="section-header">
        <h3>nftables Sets</h3>
        <button onclick={openAddSet} class="btn-add">+ Add Set</button>
      </div>
      {#if nftSets.length === 0}
        <p class="empty">No sets configured</p>
      {:else}
        <table>
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
                <td class="match">@{set.name}</td>
                <td>{set.set_type}</td>
                <td>{set.interval ? 'Yes' : 'No'}</td>
                <td class="elements-cell">{(set.elements || '').split('\n').filter((e: string) => e.trim()).length}</td>
                <td class="actions">
                  <button class="btn-sm" onclick={() => openEditSet(set)}>Edit</button>
                  <button class="btn-sm btn-danger" onclick={() => handleDeleteSet(set.name)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    <!-- ── Apply ───────────────────────────────────────────────────────── -->
    <div class="toolbar">
      <button class="primary" onclick={handleApply} disabled={applying}>
        {applying ? 'Applying...' : 'Apply Firewall Rules'}
      </button>
    </div>
  {/if}
</div>

<!-- ── Rule Modal ─────────────────────────────────────────────────────────── -->
{#if showRuleModal}
  <div class="modal-backdrop" onclick={() => showRuleModal = false}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>{editingRule ? 'Edit Rule' : 'Add Rule'}</h3>
      <div class="form-grid">
        <!-- Action -->
        <label>
          Action
          <select bind:value={ruleForm.action}>
            <option value="accept">Accept</option>
            <option value="drop">Drop</option>
            <option value="reject">Reject</option>
            <option value="tproxy">TPROXY</option>
          </select>
        </label>
        {#if ruleForm.action === 'tproxy'}
          <label>
            Mark (fwmark)
            <input type="number" bind:value={ruleForm.mark} placeholder="e.g. 1" />
          </label>
          <label>
            TPROXY Port
            <input type="number" bind:value={ruleForm.tproxy_port} placeholder="e.g. 12345" />
          </label>
        {/if}

        <!-- Match -->
        <label>
          Interfaces
          <InterfaceSelect bind:value={ruleForm.interfaces} multiple placeholder="Select interfaces" items={allInterfaces} />
        </label>
        <label>
          Out Interface (oif)
          <input bind:value={ruleForm.oif} placeholder="e.g. wan0 (sets chain to forward)" />
        </label>
        <label>
          Protocol
          <input bind:value={ruleForm.proto} placeholder="tcp, udp, icmp" />
        </label>
        <label>
          Source Address
          <div class="input-with-set">
            <input bind:value={ruleForm.saddr} placeholder="e.g. 192.168.1.0/24" />
            <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.saddr = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>
        <label>
          Source Port
          <div class="input-with-set">
            <input bind:value={ruleForm.sport} placeholder="e.g. 53" />
            {#if nftSets.length > 0}
              <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.sport = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
                <option value="">@set</option>
                {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                  <option value={s.name}>{s.name}</option>
                {/each}
              </select>
            {/if}
          </div>
        </label>
        <label>
          Dest Address
          <div class="input-with-set">
            <input bind:value={ruleForm.daddr} placeholder="e.g. 10.0.0.1" />
            <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.daddr = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>
        <label>
          Dest Port
          <div class="input-with-set">
            <input bind:value={ruleForm.dport} placeholder="80, 443, 8000-9000" />
            {#if nftSets.length > 0}
              <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { ruleForm.dport = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
                <option value="">@set</option>
                {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                  <option value={s.name}>{s.name}</option>
                {/each}
              </select>
            {/if}
          </div>
        </label>
        <label>
          State
          <InterfaceSelect bind:value={ruleForm.state} multiple placeholder="Select states" items={['established', 'related', 'new', 'invalid']} />
        </label>

        <!-- Options -->
        <label>
          Rate Limit
          <input bind:value={ruleForm.rate} placeholder="e.g. 10/second" />
        </label>
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={ruleForm.log} />
          Log
        </label>
        {#if ruleForm.log}
          <label>
            Log Prefix
            <input bind:value={ruleForm.log_prefix} placeholder="e.g. [SSH]" />
          </label>
        {/if}
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={ruleForm.counter} />
          Counter
        </label>
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={ruleForm.enabled} />
          Enabled
        </label>

        <!-- Metadata -->
        <label>
          Comment
          <input bind:value={ruleForm.comment} placeholder="e.g. allow-ssh" />
        </label>
      </div>
      <div class="modal-actions">
        <button onclick={() => showRuleModal = false}>Cancel</button>
        <button class="primary" onclick={handleSaveRule}>
          {editingRule ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ── Port Forward Modal ──────────────────────────────────────────────────── -->
{#if showPfModal}
  <div class="modal-backdrop" onclick={() => showPfModal = false}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>{editingPf ? 'Edit Port Forward' : 'Add Port Forward'}</h3>
      <div class="form-grid">
        <!-- Match -->
        <label>
          Protocol
          <select bind:value={pfForm.proto}>
            <option value="tcp">TCP</option>
            <option value="udp">UDP</option>
            <option value="tcp+udp">TCP + UDP</option>
          </select>
        </label>
        <label>
          Interfaces
          <InterfaceSelect bind:value={pfForm.interfaces} multiple placeholder="Select interfaces" items={allInterfaces} />
        </label>
        <label>
          Source Address (optional)
          <div class="input-with-set">
            <input bind:value={pfForm.source_address} placeholder="e.g. 10.0.0.0/8 (any)" />
            <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.source_address = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>
        <label></label>
        <label>
          Target Address (optional)
          <div class="input-with-set">
            <input bind:value={pfForm.target_address} placeholder="e.g. 1.2.3.4 (any)" />
            <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.target_address = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              <option value="local">local (fib)</option>
              {#each nftSets.filter(s => s.set_type === 'ipv4_addr' || s.set_type === 'ipv6_addr') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>
        <label>
          Target Port
          <div class="input-with-set">
            <input bind:value={pfForm.target_port} placeholder="80" />
            <select class="set-picker" oninput={(e) => { const v = (e.target as HTMLSelectElement).value; if (v) { pfForm.target_port = '@' + v; (e.target as HTMLSelectElement).value = ''; } }}>
              <option value="">@set</option>
              {#each nftSets.filter(s => s.set_type === 'inet_service') as s}
                <option value={s.name}>{s.name}</option>
              {/each}
            </select>
          </div>
        </label>

        <!-- Redirect -->
        <label>
          Redirect Address
          <input bind:value={pfForm.redirect_address} placeholder="192.168.1.100" />
        </label>
        <label>
          Redirect Port
          <input bind:value={pfForm.redirect_port} placeholder="8080" />
        </label>

        <!-- Options -->
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={pfForm.enabled} />
          Enabled
        </label>

        <!-- Metadata -->
        <label>
          Comment
          <input bind:value={pfForm.comment} placeholder="e.g. web-server" />
        </label>
      </div>
      <div class="modal-actions">
        <button onclick={() => showPfModal = false}>Cancel</button>
        <button class="primary" onclick={handleSavePf}>
          {editingPf ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ── nftables Set Modal ──────────────────────────────────────────────────── -->
{#if showSetModal}
  <div class="modal-backdrop" onclick={() => showSetModal = false}>
    <div class="modal" onclick={(e) => e.stopPropagation()}>
      <h3>{editingSet ? 'Edit Set' : 'Add Set'}</h3>
      <div class="form-grid">
        <label>
          Set Name
          <input bind:value={setForm.name} placeholder="e.g. blocked_ips" disabled={!!editingSet} />
        </label>
        <label>
          Element Type
          <select bind:value={setForm.set_type}>
            <option value="ipv4_addr">IPv4 Address</option>
            <option value="ipv6_addr">IPv6 Address</option>
            <option value="inet_service">Port (inet_service)</option>
            <option value="ether_addr">MAC Address</option>
          </select>
        </label>
        <label>
          Elements (one per line)
          <textarea
            bind:value={setForm.elements}
            rows="8"
            placeholder="192.168.1.100&#10;10.0.0.0/8&#10;172.16.0.0/12"
            spellcheck="false"
          ></textarea>
        </label>
        <label class="checkbox-label">
          <input type="checkbox" bind:checked={setForm.interval} />
          Interval (support CIDR ranges)
        </label>
        <label>
          Comment
          <input bind:value={setForm.comment} placeholder="Optional description" />
        </label>
      </div>
      <div class="modal-actions">
        <button onclick={() => showSetModal = false}>Cancel</button>
        <button class="primary" onclick={handleSaveSet}>
          {editingSet ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .firewall-page { max-width: 1200px; }
  h2 { margin: 0 0 1.5rem; color: #f1f5f9; }
  h3 { margin: 0; color: #94a3b8; font-size: 1rem; }
  .loading { color: #64748b; }

  /* Section header */
  .section-header { display: flex; align-items: center; justify-content: space-between; margin: 1.5rem 0 0.75rem; }
  .btn-add { padding: 0.375rem 0.75rem; background: #1e40af; color: #e2e8f0; border: none; border-radius: 4px; cursor: pointer; font-size: 0.8125rem; }
  .btn-add:hover { background: #2563eb; }

  /* Toolbar */
  .toolbar { margin-top: 1.5rem; display: flex; gap: 0.5rem; }

  /* Policies */
  .policies { display: flex; align-items: flex-end; gap: 1rem; margin-top: 0.75rem; }
  .policy { display: flex; flex-direction: column; gap: 0.25rem; }
  .policy label { color: #94a3b8; font-size: 0.875rem; }
  .save-policies { align-self: flex-end; }

  /* Buttons */
  button { padding: 0.5rem 1rem; background: #334155; color: #e2e8f0; border: none; border-radius: 6px; cursor: pointer; }
  button:hover { background: #475569; }
  button.primary { background: #3b82f6; }
  button.primary:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .btn-sm { padding: 0.25rem 0.5rem; font-size: 0.75rem; }
  .btn-icon { padding: 0.25rem 0.375rem; font-size: 0.75rem; min-width: 1.5rem; }
  .btn-danger { background: #991b1b; }
  .btn-danger:hover { background: #dc2626; }

  /* Select / input */
  select, input { background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; padding: 0.5rem; font-size: 0.875rem; }
  select:focus, input:focus { outline: none; border-color: #3b82f6; }

  /* Table */
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }
  th, td { padding: 0.625rem 1rem; text-align: left; border-bottom: 1px solid #334155; }
  th { background: #334155; color: #94a3b8; font-weight: 600; font-size: 0.8rem; text-transform: uppercase; }
  .actions { text-align: right; white-space: nowrap; }
  tr.disabled td { opacity: 0.5; }

  /* Action badges */
  .action { padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .action.accept { background: #059669; color: white; }
  .action.drop { background: #dc2626; color: white; }
  .action.reject { background: #d97706; color: white; }
  .empty { color: #64748b; font-style: italic; }
  .match { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.8125rem; white-space: nowrap; }
  .comment-cell { color: #94a3b8; font-size: 0.8125rem; max-width: 12rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .stat { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.75rem; color: #94a3b8; white-space: nowrap; }

  /* Toggle switch */
  .switch { position: relative; display: inline-block; width: 2rem; height: 1.125rem; cursor: pointer; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; inset: 0; background: #475569; border-radius: 1.125rem; transition: background 0.2s; }
  .slider::before { content: ''; position: absolute; width: 0.875rem; height: 0.875rem; left: 0.125rem; bottom: 0.125rem; background: #e2e8f0; border-radius: 50%; transition: transform 0.2s; }
  .switch input:checked + .slider { background: #3b82f6; }
  .switch input:checked + .slider::before { transform: translateX(0.875rem); }

  /* Modal */
  .modal-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; z-index: 100; }
  .modal { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 1.5rem; width: min(680px, 92vw); max-height: 85vh; overflow-y: auto; }
  .modal h3 { margin-bottom: 1rem; color: #f1f5f9; }
  .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
  .form-grid .full { grid-column: 1 / -1; }
  .form-grid label { display: flex; flex-direction: column; gap: 0.25rem; color: #94a3b8; font-size: 0.8125rem; }
  .form-grid input, .form-grid select, .form-grid textarea { width: 100%; box-sizing: border-box; }
  textarea { background: #0f172a; color: #e2e8f0; border: 1px solid #334155; border-radius: 4px; padding: 0.5rem; font-size: 0.875rem; font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; resize: vertical; }
  textarea:focus { outline: none; border-color: #3b82f6; }
  .elements-cell { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8125rem; }
  .checkbox-label { flex-direction: row !important; align-items: center; gap: 0.5rem !important; padding-top: 1.25rem; }
  .checkbox-label input { width: auto; }
  fieldset { grid-column: 1 / -1; border: 1px solid #334155; border-radius: 6px; padding: 0.5rem 0.75rem; }
  fieldset legend { color: #94a3b8; font-size: 0.8125rem; padding: 0 0.25rem; }
  .iface-checks { display: flex; gap: 1rem; flex-wrap: wrap; }
  .iface-check { display: flex; align-items: center; gap: 0.375rem; color: #e2e8f0; font-size: 0.875rem; cursor: pointer; }
  .iface-check input { width: auto; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.25rem; }

  /* Set picker */
  .input-with-set { display: flex; flex-direction: column; gap: 0.25rem; }
  .input-with-set input { width: 100%; box-sizing: border-box; }
  .set-picker { width: 100%; padding: 0.25rem 0.5rem; font-size: 0.75rem; background: #1e40af; color: #93c5fd; border: 1px solid #2563eb; border-radius: 4px; cursor: pointer; }
  .set-picker:hover { background: #2563eb; }
</style>

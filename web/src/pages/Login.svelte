<script lang="ts">
  import { onMount } from 'svelte';
  import { login, setupPassword, getAuthStatus, getToken } from '../lib/api';
  import { notify } from '../lib/stores';

  let password = $state('');
  let confirmPassword = $state('');
  let isSetup = $state(false);
  let loading = $state(false);

  interface Props {
    onLogin: () => void;
  }

  let { onLogin }: Props = $props();

  onMount(async () => {
    if (getToken()) {
      onLogin();
      return;
    }

    try {
      const status = await getAuthStatus();
      if (!status.password_configured) {
        isSetup = true;
      }
    } catch {
      // API unreachable or error — show login form as fallback.
    }
  });

  async function handleLogin() {
    if (!password) return;
    loading = true;
    try {
      await login(password);
      onLogin();
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Login failed');
    } finally {
      loading = false;
    }
  }

  async function handleSetup() {
    if (!password || password !== confirmPassword) {
      notify('error', 'Passwords do not match');
      return;
    }
    loading = true;
    try {
      await setupPassword(password);
      await login(password);
      onLogin();
    } catch (e: any) {
      notify('error', e.response?.data?.error?.message || 'Setup failed');
    } finally {
      loading = false;
    }
  }
</script>

<div class="login-page">
  <div class="login-card">
    <h1>routerd</h1>
    <p class="subtitle">{isSetup ? 'Create admin password' : 'Admin sign in'}</p>

    {#if isSetup}
      <label>
        Password
        <input type="password" bind:value={password} placeholder="Enter password" />
      </label>
      <label>
        Confirm Password
        <input type="password" bind:value={confirmPassword} placeholder="Confirm password" />
      </label>
      <button class="primary" onclick={handleSetup} disabled={loading}>
        {loading ? 'Setting up...' : 'Create Password'}
      </button>
    {:else}
      <label>
        Password
        <input type="password" bind:value={password} placeholder="Enter password" onkeydown={(e) => e.key === 'Enter' && handleLogin()} />
      </label>
      <button class="primary" onclick={handleLogin} disabled={loading}>
        {loading ? 'Signing in...' : 'Sign In'}
      </button>
    {/if}
  </div>
</div>

<style>
  .login-page {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0f172a;
  }
  .login-card {
    width: 320px;
    padding: 2rem;
    background: #1e293b;
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
  }
  h1 { margin: 0 0 0.25rem; color: #f1f5f9; font-size: 1.75rem; }
  .subtitle { margin: 0 0 1.5rem; color: #64748b; font-size: 0.875rem; }
  label { display: block; color: #94a3b8; font-size: 0.8125rem; margin-bottom: 1rem; }
  input {
    width: 100%;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: #0f172a;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    box-sizing: border-box;
  }
  input:focus { outline: none; border-color: #3b82f6; }
  button {
    width: 100%;
    padding: 0.625rem;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9375rem;
  }
  button:hover { background: #2563eb; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
</style>

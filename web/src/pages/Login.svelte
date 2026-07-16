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

<div class="flex items-center justify-center min-h-screen bg-surface-50">
  <div class="card p-8 w-96 shadow-xl">
    <div class="text-center mb-6">
      <h1 class="h2">routerd</h1>
      <p class="text-surface-500 mt-1">{isSetup ? 'Create admin password' : 'Admin sign in'}</p>
    </div>

    {#if isSetup}
      <label class="label mb-4">
        <span class="label-text">Password</span>
        <input type="password" class="input" bind:value={password} placeholder="Enter password" />
      </label>
      <label class="label mb-6">
        <span class="label-text">Confirm Password</span>
        <input type="password" class="input" bind:value={confirmPassword} placeholder="Confirm password" />
      </label>
      <button class="btn preset-filled-primary-500 w-full" onclick={handleSetup} disabled={loading}>
        {loading ? 'Setting up...' : 'Create Password'}
      </button>
    {:else}
      <label class="label mb-6">
        <span class="label-text">Password</span>
        <input type="password" class="input" bind:value={password} placeholder="Enter password" onkeydown={(e) => e.key === 'Enter' && handleLogin()} />
      </label>
      <button class="btn preset-filled-primary-500 w-full" onclick={handleLogin} disabled={loading}>
        {loading ? 'Signing in...' : 'Sign In'}
      </button>
    {/if}
  </div>
</div>

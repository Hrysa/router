<script lang="ts">
  import { isAuthenticated, notifications, markAuthenticated } from './lib/stores';
  import Dashboard from './pages/Dashboard.svelte';
  import Firewall from './pages/Firewall.svelte';
  import Dhcp from './pages/Dhcp.svelte';
  import Interfaces from './pages/Interfaces.svelte';
  import Services from './pages/Services.svelte';
  import Monitoring from './pages/Monitoring.svelte';
  import Hooks from './pages/Hooks.svelte';
  import SingBox from './pages/SingBox.svelte';
  import Login from './pages/Login.svelte';
  import { Navigation } from '@skeletonlabs/skeleton-svelte';

  let currentPath = $state(window.location.hash.slice(1) || '/');

  function navigate(path: string) {
    window.location.hash = path;
  }

  $effect(() => {
    const handler = () => {
      currentPath = window.location.hash.slice(1) || '/';
    };
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  });

  const navItems = [
    { path: '/', label: 'Dashboard', icon: '📊' },
    { path: '/firewall', label: 'Firewall', icon: '🛡️' },
    { path: '/dhcp', label: 'DHCP', icon: '📡' },
    { path: '/interfaces', label: 'Interfaces', icon: '🌐' },
    { path: '/singbox', label: 'sing-box', icon: '🚀' },
    { path: '/services', label: 'Services', icon: '🔧' },
    { path: '/monitoring', label: 'Monitoring', icon: '📈' },
    { path: '/hooks', label: 'Hooks', icon: '⚡' },
  ];

  function notifColor(type: string) {
    switch (type) {
      case 'success': return 'preset-filled-success-500';
      case 'error': return 'preset-filled-error-500';
      case 'warning': return 'preset-filled-warning-500';
      case 'info': return 'preset-filled-primary-500';
      default: return 'preset-tonal-surface';
    }
  }
</script>

{#if $isAuthenticated}
  <div class="grid grid-cols-[auto_1fr] min-h-screen">
    <!-- Sidebar -->
    <Navigation layout="sidebar" class="grid grid-rows-[auto_1fr_auto] gap-4 p-4">
      <Navigation.Header>
        <a href="#/" class="text-xl font-bold text-primary-500">routerd</a>
      </Navigation.Header>
      <Navigation.Content>
        <Navigation.Group>
          <Navigation.Menu>
            {#each navItems as item}
              <Navigation.TriggerAnchor
                href="#{item.path}"
                class="w-full justify-start {currentPath === item.path ? 'preset-filled-primary-500' : ''}"
              >
                <span>{item.icon}</span>
                <Navigation.TriggerText>{item.label}</Navigation.TriggerText>
              </Navigation.TriggerAnchor>
            {/each}
          </Navigation.Menu>
        </Navigation.Group>
      </Navigation.Content>
    </Navigation>

    <!-- Main content -->
    <main class="p-6 overflow-y-auto">
      <!-- Notifications -->
      <div class="fixed top-4 right-4 z-50 flex flex-col gap-2">
        {#each $notifications as notif (notif.id)}
          <div class="alert {notifColor(notif.type)} shadow-lg">
            <span>{notif.message}</span>
          </div>
        {/each}
      </div>

      {#if currentPath === '/'}
        <Dashboard />
      {:else if currentPath === '/firewall'}
        <Firewall />
      {:else if currentPath === '/dhcp'}
        <Dhcp />
      {:else if currentPath === '/interfaces'}
        <Interfaces />
      {:else if currentPath === '/singbox'}
        <SingBox />
      {:else if currentPath === '/services'}
        <Services />
      {:else if currentPath === '/monitoring'}
        <Monitoring />
      {:else if currentPath === '/hooks'}
        <Hooks />
      {:else}
        <Dashboard />
      {/if}
    </main>
  </div>
{:else}
  <Login onLogin={markAuthenticated} />
{/if}

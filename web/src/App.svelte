<script lang="ts">
  import { isAuthenticated, notifications } from './lib/stores';
  import Dashboard from './pages/Dashboard.svelte';
  import Firewall from './pages/Firewall.svelte';
  import Dhcp from './pages/Dhcp.svelte';
  import Interfaces from './pages/Interfaces.svelte';
  import Services from './pages/Services.svelte';
  import Monitoring from './pages/Monitoring.svelte';
  import Hooks from './pages/Hooks.svelte';
  import Login from './pages/Login.svelte';

  let sidebarOpen = $state(true);
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
    { path: '/services', label: 'Services', icon: '🔧' },
    { path: '/monitoring', label: 'Monitoring', icon: '📈' },
    { path: '/hooks', label: 'Hooks', icon: '⚡' },
  ];
</script>

{#if $isAuthenticated}
  <div class="app">
    <aside class="sidebar" class:collapsed={!sidebarOpen}>
      <div class="sidebar-header">
        <h1>routerd</h1>
        <button class="toggle-btn" onclick={() => sidebarOpen = !sidebarOpen}>
          {sidebarOpen ? '←' : '→'}
        </button>
      </div>

      <nav>
        {#each navItems as item}
          <button
            class="nav-link"
            class:active={currentPath === item.path}
            onclick={() => navigate(item.path)}
          >
            <span class="icon">{item.icon}</span>
            {#if sidebarOpen}
              <span class="label">{item.label}</span>
            {/if}
          </button>
        {/each}
      </nav>
    </aside>

    <main class="content">
      <div class="notifications">
        {#each $notifications as notif (notif.id)}
          <div class="notification {notif.type}">
            {notif.message}
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
  <Login />
{/if}

<style>
  :global(body) {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
  }

  .app {
    display: flex;
    min-height: 100vh;
  }

  .sidebar {
    width: 240px;
    background: #1e293b;
    padding: 1.5rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
    transition: width 0.2s;
  }

  .sidebar.collapsed {
    width: 64px;
    padding: 1.5rem 0.75rem;
  }

  .sidebar-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .sidebar-header h1 {
    font-size: 1.25rem;
    color: #60a5fa;
    margin: 0;
  }

  .collapsed .sidebar-header h1 {
    display: none;
  }

  .toggle-btn {
    background: #334155;
    border: none;
    color: #94a3b8;
    padding: 0.25rem 0.5rem;
    cursor: pointer;
    border-radius: 4px;
  }

  nav {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .nav-link {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    color: #94a3b8;
    background: none;
    border: none;
    padding: 0.75rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 1rem;
    text-align: left;
    width: 100%;
    transition: background 0.2s;
  }

  .nav-link:hover {
    background: #334155;
    color: #e2e8f0;
  }

  .nav-link.active {
    background: #3b82f6;
    color: white;
  }

  .collapsed .nav-link {
    justify-content: center;
    padding: 0.75rem;
  }

  .icon {
    font-size: 1.25rem;
  }

  .content {
    flex: 1;
    padding: 2rem 2.5rem;
    overflow-y: auto;
  }

  .notifications {
    position: fixed;
    top: 1rem;
    right: 1rem;
    z-index: 1000;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .notification {
    padding: 0.75rem 1rem;
    border-radius: 6px;
    animation: slideIn 0.3s ease;
  }

  .notification.success { background: #059669; }
  .notification.error { background: #dc2626; }
  .notification.warning { background: #d97706; }
  .notification.info { background: #2563eb; }

  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
</style>

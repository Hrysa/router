# Remove DHCP Leases from Monitoring

## Scope

Remove the DHCP lease display and its data request from the WebUI monitoring page. Preserve the reusable `getLeases()` API helper and the backend `GET /api/monitor/leases` endpoint for non-UI consumers and possible future use.

## Design

Update `web/src/pages/Monitoring.svelte` only:

- Remove `getLeases` from the API imports.
- Remove the page-local `leases` state.
- Remove the lease request and response assignment from the initial parallel load.
- Remove the complete DHCP Leases section, including its empty state and table.

The System, Interface Traffic, Firewall Traffic, and Interfaces sections retain their current layout and behavior. Monitoring continues to load its remaining initial resources in parallel and poll metrics every five seconds.

## Error Handling

No new error behavior is needed. Removing the lease request also prevents a lease endpoint failure from causing the monitoring page's shared initial-load error notification.

## Verification

Run `npm run check` in `web/` to validate Svelte and TypeScript, then run `npm run build` to verify the production bundle and refresh the embedded UI output. Confirm there are no remaining lease references in `Monitoring.svelte` and that backend/API helper code is unchanged.

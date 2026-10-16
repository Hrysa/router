import { list } from './format';
import type { InterfaceConfig, InterfaceDetail } from './types';

export interface InterfaceOption {
  name: string;
  label?: string;
  up?: boolean;
  source: 'Configured' | 'Referenced' | 'Detected' | 'Custom';
}

export function interfaceDisplayName(
  name: string,
  configured: InterfaceConfig[] = [],
): string {
  const iface =
    configured.find((item) => item.name === name) ??
    (name === 'ppp0'
      ? configured.find((item) => item.method === 'pppoe')
      : undefined);
  return iface?.label?.trim() || name;
}

export function interfaceOptions(
  configured: InterfaceConfig[] = [],
  detected: InterfaceDetail[] = [],
  selected: string[] = [],
  exclude?: string,
): InterfaceOption[] {
  const options = new Map<string, InterfaceOption>();
  for (const name of configured.flatMap((iface) => [
    ...(iface.bridge_ports ?? []),
    ...(iface.parent ? [iface.parent] : []),
  ]))
    options.set(name, { name, source: 'Referenced' });
  for (const iface of configured)
    options.set(iface.name, {
      name: iface.name,
      label: iface.label,
      source: 'Configured',
    });
  for (const iface of detected)
    options.set(iface.name, {
      name: iface.name,
      source: 'Detected',
      ...options.get(iface.name),
      up: iface.up,
    });
  for (const name of selected)
    if (!options.has(name)) options.set(name, { name, source: 'Custom' });
  return [...options.values()]
    .filter(
      (option) => option.name !== exclude || selected.includes(option.name),
    )
    .sort((first, second) => first.name.localeCompare(second.name));
}

export function toggleInterface(
  value: string,
  name: string,
  multiple: boolean,
) {
  const selected = [...new Set(list(value))];
  if (!multiple) return selected.includes(name) ? '' : name;
  return (
    selected.includes(name)
      ? selected.filter((item) => item !== name)
      : [...selected, name]
  ).join(', ');
}

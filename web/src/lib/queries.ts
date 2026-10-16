import { useQuery } from '@tanstack/react-query';
import { getConfig, request } from './api';
import type {
  InterfaceDetail,
  Metrics,
  Service,
  SystemInfo,
  SystemStats,
  Status,
} from './types';
export function useApi<Result>(path: string, interval?: number) {
  return useQuery({
    queryKey: [path],
    queryFn: ({ signal }) => request<Result>(path, { signal }),
    refetchInterval: interval,
  });
}
export const useConfig = () =>
  useQuery({
    queryKey: ['/config'],
    queryFn: ({ signal }) => getConfig(signal),
  });
export const useInterfaces = () =>
  useApi<{ interfaces: InterfaceDetail[] }>('/monitor/interfaces', 2000);
export const useServices = () =>
  useApi<{ services: Service[] }>('/services', 10000);
export const useMetrics = () => useApi<Metrics>('/metrics', 2000);
export const useSystem = () => useApi<SystemInfo>('/monitor/system', 10000);
export const useSystemStats = () => useApi<SystemStats>('/status/system', 2000);
export const useStatus = () => useApi<Status>('/status', 10000);
export const useApplyStatus = () =>
  useApi<{ pending: boolean }>('/config/apply/status', 5000);

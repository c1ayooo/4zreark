import api from '@/lib/api'

export interface Site {
  id: number
  project_id: number
  project_code: string
  project_name: string
  host: string
  port: number
  protocol: string
  value: string
  ip: string
  http_status: number
  title: string
  icon_sha256: string
  technology_stack: string[]
  discovery_type: string
  state: string
  consecutive_failures: number
  retry_step: number
  cleanup_eligible: boolean
  verification_status: string
  verification_reason: string
  attempts: number
  max_attempts: number
  first_seen: string
  last_seen: string
  verified_at: string | null
  next_verification_at: string | null
}

export interface OverviewData {
  projects: number
  assets: number
  domains: number
  sites: number
  verified_sites: number
  record_count: number
  lost_count: number
  new_today: number
  technology_counts: { key: string; name: string; site_count: number }[]
  recent_events: {
    id: number
    event_type: string
    title: string
    asset_value: string
    project_name: string
    created_at: string
  }[]
}

export interface AssetProject {
  id: number
  code: string
  name: string
  region: string
  description: string
  homepage_url: string
  color: string
  collection_paused: boolean
  cycle_interval_days: number
  asset_count: number
  record_count: number
  lost_count: number
}

export const assetApi = {
  overview: () => api.get<unknown, { code: number; data: OverviewData }>('/overview'),
  projects: () => api.get<unknown, { code: number; data: AssetProject[] }>('/projects'),
  list: (params: { page: number; page_size: number; q?: string; project_id?: number }) =>
    api.get<unknown, { code: number; data: { items: Site[] }; total: number; page: number; size: number }>(
      '/assets',
      { params }
    ),
  checkQuery: (q: string) =>
    api.get<unknown, { code: number; data: { valid: boolean; compiled: string } }>('/assets/query-check', {
      params: { q },
    }),
  verify: (id: number, body: { reachable: boolean; status_code?: number; reason?: string }) =>
    api.post<unknown, { code: number; message: string }>(`/assets/${id}/verify`, body),
  events: (limit = 50) => api.get<unknown, { code: number; data: { items: any[] } }>('/events', { params: { limit } }),
}

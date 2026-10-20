import api from '@/lib/api'

export interface AssetEndpoint {
  scheme: string
  port: number
  status_code: number
}

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
  /** 站点的全部入口。站点按 host 归并，端口视图只能从这里读。 */
  endpoints: AssetEndpoint[]
}

/** kind=domain 的一行 */
export interface DomainRow {
  host: string
  site_count: number
  project_id: number
  project_code: string
  project_name: string
  reachable_count: number
  last_seen: string
}

/** kind=ip 的一行 */
export interface IPRow {
  ip: string
  site_count: number
  domain_count: number
  project_id: number
  last_seen: string
}

/** site_group=0（展开到入口）的一行 */
export interface EndpointRow {
  site_id: number
  host: string
  port: number
  protocol: string
  value: string
  title: string
  http_status: number
  state: string
  project_id: number
  project_name: string
  record_count: number
  last_seen: string
}

export interface ConnectivityPolicy {
  failure_threshold: number
  first_hours: number
  second_hours: number
  repeat_hours: number
  cleanup_days: number
  auto_cleanup: boolean
}

export type AssetKind = 'site' | 'domain' | 'ip'
export type AssetCatalog = 'all' | 'verified' | 'candidates'
export type AssetView = '' | 'clues' | 'candidates' | 'lost' | 'icons' | 'technologies' | 'apps' | 'media'

export interface AssetPage {
  items: (Site | DomainRow | IPRow | EndpointRow)[]
  total: number
  page: number
  page_size: number
  kind: AssetKind
  catalog: string
  view: string
  lifecycle: string
  site_group: boolean
  /** false 表示这个视图还没实现，note 里写了替代接口或无数据源 */
  view_supported: boolean
  note?: string
  connectivity_policy?: ConnectivityPolicy
}

export interface ProbeEndpointResult {
  scheme: string
  port: number
  outcome: string
  reason_code: string
  status_code: number
  addr: string
  elapsed_ms: number
  detail: string
}

export interface ProbeReport {
  site_id: number
  host: string
  verdict: 'reachable' | 'unreachable' | 'inconclusive'
  reason_code: string
  status_code: number
  endpoints: ProbeEndpointResult[]
  tech?: string[]
  matched_rules?: string[]
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

export interface AssetQueryParams {
  page: number
  page_size: number
  q?: string
  project_id?: number
  kind?: AssetKind
  catalog?: AssetCatalog
  view?: AssetView
  site_group?: 0 | 1
}

export const assetApi = {
  overview: () => api.get<unknown, { code: number; data: OverviewData }>('/overview'),
  projects: () => api.get<unknown, { code: number; data: AssetProject[] }>('/projects'),
  list: (params: AssetQueryParams) =>
    api.get<unknown, { code: number; data: AssetPage }>('/assets', { params }),
  checkQuery: (q: string) =>
    api.get<unknown, { code: number; data: { valid: boolean; compiled: string } }>('/assets/query-check', {
      params: { q },
    }),
  /** 人工判定，不发网络请求 */
  verify: (id: number, body: { reachable: boolean; status_code?: number; reason?: string }) =>
    api.post<unknown, { code: number; message: string }>(`/assets/${id}/verify`, body),
  /** 真实探测：服务端会发 HTTP 请求，并写回连通性、指纹与验证流水 */
  probe: (id: number) =>
    api.post<unknown, { code: number; message: string; data: ProbeReport }>(`/assets/${id}/probe`),
  /** 人工删除保护期（这段时间内不会被自动归档） */
  protect: (id: number, days = 90) =>
    api.post<unknown, { code: number; message: string }>(`/assets/${id}/protect`, { days }),
  events: (limit = 50) => api.get<unknown, { code: number; data: { items: any[] } }>('/events', { params: { limit } }),
}

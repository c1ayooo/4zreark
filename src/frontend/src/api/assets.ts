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
  /** 读时按观测证据实时评分（0-100 / p0-p4），不落库 */
  risk_score: number
  priority: string
  /** 评分因子明细：为什么是这个档位 */
  risk_factors?: RiskFactor[]
}

export interface RiskFactor {
  factor: string
  points: number
  detail: string
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

/** 按图标聚类的一行（view=icons） */
export interface IconCluster {
  icon_sha256: string
  icon_mmh3: number
  site_count: number
  sample_host: string
  sample_title: string
  last_seen: string
}

/** 按技术栈聚类的一行（view=technologies） */
export interface TechCluster {
  name: string
  site_count: number
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
  /** 实际生效的排序（risk 表示按评分倒序） */
  sort?: string
  /** false 表示这个视图还没实现，note 里写了替代接口或无数据源 */
  view_supported: boolean
  note?: string
  connectivity_policy?: ConnectivityPolicy
  /** keyset 分页游标；空字符串表示没有下一页 */
  next_cursor?: string
  has_more?: boolean
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
  page?: number
  page_size: number
  /** keyset 分页；传空字符串表示第一页 */
  cursor?: string
  q?: string
  project_id?: number
  kind?: AssetKind
  catalog?: AssetCatalog
  view?: AssetView
  site_group?: 0 | 1
  /** risk=按资产 P0-P4 评分倒序；缺省按首次发现时间 */
  sort?: 'risk'
}

export const assetApi = {
  overview: () => api.get<unknown, { code: number; data: OverviewData }>('/overview'),
  projects: () => api.get<unknown, { code: number; data: AssetProject[] }>('/projects'),
  list: (params: AssetQueryParams) =>
    api.get<unknown, { code: number; data: AssetPage }>('/assets', { params }),
  /** 图标聚类（T4 第二步） */
  icons: (params: { project_id?: number; q?: string; page?: number; page_size?: number }) =>
    api.get<unknown, { code: number; data: { items: IconCluster[]; total: number } }>('/assets/icons', {
      params,
    }),
  /** 技术栈聚类（T4 第二步） */
  technologies: (params: { project_id?: number; q?: string; page?: number; page_size?: number }) =>
    api.get<unknown, { code: number; data: { items: TechCluster[]; total: number } }>('/assets/technologies', {
      params,
    }),
  /** 图标字节地址（公开路由，可直接放 <img src>） */
  iconURL: (sha256: string) => `/api/asset-icons/${sha256}`,
  /** 资产星图：不分页、保留父子关系，供分层布局 */
  graph: (params: { project_id?: number; q?: string; mode?: 'summary' | 'full' } = {}) =>
    api.get<unknown, { code: number; data: AssetGraphData }>('/assets/graph', { params }),
  /** 资产详情：站点 + 入口 + 证据链（验证/指纹/原始记录/事件/关系） */
  detail: (id: number) =>
    api.get<unknown, { code: number; message: string; data: AssetDetail }>(`/assets/${id}`),
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

// ---- 资产星图（分层图）----

export type AssetGraphKind =
  | 'project'
  | 'root_domain'
  | 'subdomain'
  | 'ip'
  | 'service'
  | 'endpoint'
  | 'route'

export type AssetGraphRel = 'owns' | 'contains' | 'resolves' | 'exposes' | 'routes'

export interface AssetGraphNode {
  key: string
  kind: AssetGraphKind
  label: string
  project_id?: number
  site_id?: number
  host?: string
  port?: number
  protocol?: string
  ip?: string
  title?: string
  status_code?: number
  method?: string
  path?: string
  state?: string
  verification_status?: string
  tech?: string[]
}

export interface AssetGraphEdge {
  src: string
  dst: string
  rel: AssetGraphRel
}

export interface AssetGraphData {
  nodes: AssetGraphNode[]
  edges: AssetGraphEdge[]
  /** 站点数超过上限时为 true，图只包含最近发现的那一批 */
  truncated: boolean
  limit: number
  /** 摘要模式：只含项目/根域名，子域/服务/入口折叠为 counts */
  summary?: boolean
  counts?: Record<string, Record<string, number>>
  totals?: Record<string, number>
}

// ---- 资产详情（证据链）----

export interface AssetVerification {
  id: number
  status: string
  reason_code: string
  http_status: number
  attempts: number
  detail: Record<string, unknown>
  observed_at: string
}

export interface AssetFingerprintHit {
  rule_id: string
  rule_name: string
  category: string
  observed_at: string
  record_id: number | null
  evidence: Record<string, unknown>
}

export interface AssetRawRecord {
  id: number
  source: string
  host: string
  port: number
  protocol: string
  value: string
  status_code: number
  title: string
  ip: string
  evidence: Record<string, unknown>
  observed_at: string
}

export interface AssetEvent {
  id: number
  event_type: string
  title: string
  before: Record<string, unknown>
  after: Record<string, unknown>
  record_id: number | null
  created_at: string
}

export interface AssetRelationEvidence {
  record_id: number
  source: string
  value: string
  note: string
  observed_at: string
}

export interface AssetRelation {
  id: number
  type: string
  key: string
  confidence: number
  peer: {
    id: number
    host: string
    value: string
    title: string
    ip: string
  }
  evidence: AssetRelationEvidence[]
}

export interface AssetDetail {
  site: Site
  verifications: AssetVerification[]
  fingerprints: AssetFingerprintHit[]
  records: AssetRawRecord[]
  events: AssetEvent[]
  relations: AssetRelation[]
}


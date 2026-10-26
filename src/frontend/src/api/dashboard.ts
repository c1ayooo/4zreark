import api, { ApiResponse } from '@/lib/api'

export interface DashboardStats {
  assets: {
    total: number
    active?: number
    byType: Record<string, number>
    recentlyAdded: number
  }
  tasks: {
    total: number
    running: number
    completed: number
    failed: number
  }
  vulnerabilities: {
    total: number
    open: number
    bySeverity: Record<string, number>
    recentlyFound: number
  }
  nodes: {
    total: number
    online: number
    offline: number
  }
}

export interface ActivityLog {
  id: string
  type: string
  action: string
  target: string
  targetId: string
  userId: string
  username: string
  details?: string
  createdAt: string
}

export interface TrendData {
  date: string
  assets: number
  vulnerabilities: number
  tasks: number
}

export interface CollectionPanels {
  seed_jobs: Record<string, number>
  seed_found_24h: number
  discovery_runs_24h: number
  discovery_new_24h: number
  last_discovery?: {
    ran_at: string
    from_ctlog: number
    from_engines: number
    new_count: number
  }
  watch_reachable: number
  watch_checked_24h: number
  watch_changed_24h: number
}

export interface ProjectBreakdownRow {
  id: number
  name: string
  code: string
  seeds: number
  sites: number
  reachable: number
  checked_24h: number
  changed_24h: number
  routes: number
  pending_candidates: number
  collecting: number
  last_discovery_at?: string
}

export interface RouteSurfacePanels {
  total: number
  distinct_paths: number
  methods: Record<string, number>
  top_hosts: Array<{ host: string; routes: number }>
}

export interface JSSecretPanels {
  total: number
  recent: Array<{ name: string; target: string; severity: string; created_at?: string }>
}

export interface CapabilityPanels {
  dict_sets: number
  dict_words: number
  dict_learning_pending: number
  fingerprint_rules: number
  fingerprint_sources: number
  fingerprint_hits_24h: number
  pocs_enabled: number
  pocs_total: number
  intel_total: number
  intel_7d: number
  github_leak_rules: number
  github_leak_findings: number
  verifications_24h: number
  relations: number
  digital_assets: number
  enterprise_entities: number
}

export interface AssetChangePanels {
  counts_24h: Record<string, number>
  recent: Array<{
    event_type: string
    title: string
    site_id: number
    host: string
    project: string
    project_id: number
    created_at?: string
  }>
}

export interface SiteStatusPanels {
  http_buckets: Record<string, number>
  states: Record<string, number>
}

export interface DashboardPanels {
  collection: CollectionPanels
  projects: ProjectBreakdownRow[]
  routes: RouteSurfacePanels
  js_secrets: JSSecretPanels
  capabilities: CapabilityPanels
  changes: AssetChangePanels
  site_status: SiteStatusPanels
  engine_usage: Array<{ engine: string; queries: number }>
  tech_top: Array<{ name: string; count: number }>
  port_top: Array<{ port: number; count: number }>
}

export const dashboardApi = {
  getStats: (): Promise<ApiResponse<DashboardStats>> =>
    api.get('/dashboard/stats'),

  getPanels: (): Promise<ApiResponse<DashboardPanels>> =>
    api.get('/dashboard/panels'),

  getRecentAssets: (limit?: number): Promise<ApiResponse<Array<{
    id: number
    value: string
    http_status: number
    title: string
    project_name: string
    first_seen: string
  }>>> => api.get('/dashboard/recent-assets', { params: { limit: limit || 8 } }),

  getRecentActivities: async (limit?: number): Promise<ApiResponse<ActivityLog[]>> => {
    const response = (await api.get('/dashboard/activities', {
      params: { limit: limit || 10 },
    })) as unknown as ApiResponse<Array<Record<string, unknown>>>
    return {
      ...response,
      data: (response.data || []).map((a) => ({
        id: String(a.id ?? ''),
        type: String(a.module ?? 'system'),
        action: String(a.action ?? ''),
        target: String(a.target ?? ''),
        targetId: '',
        userId: '',
        username: String(a.username ?? '系统'),
        details: '',
        createdAt: String(a.created_at ?? ''),
      })),
    }
  },

  getTrends: (days?: number): Promise<ApiResponse<TrendData[]>> =>
    api.get('/dashboard/trends', { params: { days: days || 7 } }),

  getTopVulnerabilities: (limit?: number): Promise<ApiResponse<Array<{
    type: string
    count: number
    severity: string
  }>>> =>
    api.get('/dashboard/top-vulnerabilities', { params: { limit: limit || 10 } }),

  getAssetDistribution: (): Promise<ApiResponse<Array<{
    type: string
    count: number
  }>>> =>
    api.get('/dashboard/asset-distribution'),
}

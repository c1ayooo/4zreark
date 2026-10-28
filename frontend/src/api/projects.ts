import api, { ApiResponse } from '@/lib/api'

// 采集概览（项目详情「采集详情」卡片）
export interface CollectJobRow {
  provider: string
  keyword: string
  status: string
  nodes: number
  entities: number
  domains: number
  digital: number
  error: string
  created_at: string
  finished_at?: string
}

export interface CollectQualityNote {
  level: 'error' | 'warn' | 'info' | string
  message: string
}

export interface CollectOverview {
  entity_total: number
  entity_type: Record<string, number>
  seed_count: number
  candidates: Record<string, number>
  candidate_no_icp: number
  site_count: number
  jobs: CollectJobRow[]
  quality: CollectQualityNote[]
}

export interface Project {
  id: number
  code: string
  name: string
  region: string
  description: string
  homepage_url: string
  color: string
  icon_sha256: string
  collection_paused: boolean
  collection_pause_reason: string
  cycle_interval_days: number
  seed_count: number
  asset_count: number
  record_count: number
  lost_count: number
  updated_at: string
}

export interface ProjectInput {
  code: string
  name: string
  region: string
  description: string
  homepage_url: string
  color: string
  cycle_interval_days: number
}

export type SeedKind = 'domain' | 'cidr' | 'company' | 'cert' | 'repo' | 'app' | 'dict'

export interface Seed {
  id: number
  project_id: number
  kind: SeedKind
  value: string
  capability: Record<string, unknown>
  enabled: boolean
  created_at: string
}

export interface SeedDomainCount {
  seed_id: number
  value: string
  site_count: number
}

export type PlanTriggerMode = 'interval' | 'on_change' | 'both'

export const planTriggerModeLabel: Record<PlanTriggerMode, string> = {
  interval: '固定周期',
  on_change: '资产变化',
  both: '周期 + 变化',
}

export interface Plan {
  id: number
  seed_id: number
  seed_kind: SeedKind
  seed_value: string
  project_id: number
  interval_hours: number
  budget: Record<string, unknown>
  trigger_mode: PlanTriggerMode
  change_cooldown_minutes: number
  enabled: boolean
  next_run_at: string | null
  last_run_at: string | null
  created_at: string
}

export interface Run {
  id: number
  plan_id: number
  project_id: number
  cycle_start: string
  status: 'queued' | 'running' | 'partial' | 'done' | 'failed'
  budget: Record<string, unknown>
  started_at: string | null
  ended_at: string | null
  stats: Record<string, unknown>
}

export interface SeedPreviewTarget {
  host: string
  port: number
  capability?: Record<string, unknown>
}

export interface SeedPreviewResult {
  kind: SeedKind
  normalized_value: string
  mode: 'static' | 'live'
  source: string
  total: number
  shown: number
  truncated: boolean
  targets: SeedPreviewTarget[]
  warnings: string[]
  empty_reason?: string
}

export interface ProjectDeleteResult {
  project_id: number
  code: string
  name: string
  sites: number
  records: number
  endpoints: number
  seeds: number
  plans: number
  runs: number
  run_targets: number
  tasks: number
  scan_results: number
  cruise_tasks: number
}

export const projectApi = {
  list: () => api.get<unknown, ApiResponse<Project[]>>('/projects'),
  get: (id: number) => api.get<unknown, ApiResponse<Project>>(`/projects/${id}`),
  create: (body: ProjectInput) =>
    api.post<unknown, ApiResponse<Project>>('/projects', body),
  // 一键侦察：公司名称或域名 → 多平台并行采集（归一去重）→ 完成后自动创建扫描任务
  onboard: (
    id: number,
    body: {
      keyword: string
      providers?: string[]
      depth?: number
      max_nodes?: number
      cookie?: string
      username?: string
      password?: string
      proxy_url?: string
    }
  ) =>
    api.post<unknown, ApiResponse<{ mode: string; keyword: string; jobs: { id: string; status: string }[]; job_errors: string[]; domain?: string; tasks_created: number }>>(
      `/projects/${id}/onboard`,
      body
    ),

  // 采集概览：采集到了什么 / 任务状态 / 质量信号（发现漏采、上限中止、待确认候选）
  collectOverview: (id: number) =>
    api.get<unknown, ApiResponse<CollectOverview>>(`/projects/${id}/collect-overview`),
  update: (id: number, body: ProjectInput) =>
    api.put<unknown, ApiResponse<Project>>(`/projects/${id}`, body),
  pause: (id: number, reason = '') =>
    api.post<unknown, ApiResponse<Project>>(`/projects/${id}/pause`, { reason }),
  resume: (id: number) =>
    api.post<unknown, ApiResponse<Project>>(`/projects/${id}/resume`),
  uploadIcon: (id: number, file: File) =>
    api.put<unknown, ApiResponse<Project>>(`/projects/${id}/icon`, file, {
      headers: { 'Content-Type': file.type || 'image/png' },
    }),
  clearIcon: (id: number) =>
    api.delete<unknown, ApiResponse<Project>>(`/projects/${id}/icon`),
  // 永久删除项目：confirm_code 必须与项目编码完全一致；级联清任务/资产/巡航等全部归属数据
  delete: (id: number, confirm_code: string) =>
    api.delete<unknown, ApiResponse<ProjectDeleteResult>>(`/projects/${id}`, {
      data: { confirm_code },
    }),

  seeds: (projectId: number) =>
    api.get<unknown, ApiResponse<Seed[]>>('/seeds', { params: { project_id: projectId } }),
  previewSeed: (body: {
    project_id: number
    kind: SeedKind
    value: string
    capability?: Record<string, unknown>
    live?: boolean
  }) => api.post<unknown, ApiResponse<SeedPreviewResult>>('/seeds/preview', body),
  createSeed: (body: {
    project_id: number
    kind: SeedKind
    value: string
    capability?: Record<string, unknown>
  }) => api.post<unknown, ApiResponse<Seed>>('/seeds', body),
  deleteSeed: (id: number) => api.delete<unknown, ApiResponse<null>>(`/seeds/${id}`),
  domainCounts: (projectId: number) =>
    api.get<unknown, ApiResponse<{ items: SeedDomainCount[]; total: number }>>(
      '/seeds/domain-counts',
      { params: { project_id: projectId } }
    ),

  plans: (projectId: number) =>
    api.get<unknown, ApiResponse<Plan[]>>('/plans', { params: { project_id: projectId } }),
  createPlan: (
    body: {
      seed_id: number
      interval_hours: number
      budget?: Record<string, unknown>
      trigger_mode?: PlanTriggerMode
      change_cooldown_minutes?: number
    }
  ) => api.post<unknown, ApiResponse<Plan>>('/plans', body),
  updatePlan: (
    id: number,
    body: {
      enabled?: boolean
      interval_hours?: number
      trigger_mode?: PlanTriggerMode
      change_cooldown_minutes?: number
    }
  ) => api.put<unknown, ApiResponse<null>>(`/plans/${id}`, body),
  deletePlan: (id: number) => api.delete<unknown, ApiResponse<null>>(`/plans/${id}`),
  triggerPlan: (id: number) =>
    api.post<unknown, ApiResponse<Run>>(`/plans/${id}/trigger`),

  runs: (projectId: number, limit = 30) =>
    api.get<unknown, ApiResponse<Run[]>>('/runs', { params: { project_id: projectId, limit } }),
  executeRun: (id: number, limit = 50) =>
    api.post<unknown, ApiResponse<Record<string, unknown>>>(`/runs/${id}/execute`, null, {
      params: { limit },
    }),
}

export const seedKindLabel: Record<SeedKind, string> = {
  domain: '域名',
  cidr: '网段',
  cert: '证书组织',
  company: '公司(ICP)',
  repo: '代码仓库',
  app: '应用',
  dict: '字典',
}

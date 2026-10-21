import api, { ApiResponse } from '@/lib/api'

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

export type SeedKind = 'domain' | 'cidr' | 'company' | 'repo' | 'app' | 'dict'

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

export const projectApi = {
  list: () => api.get<unknown, ApiResponse<Project[]>>('/projects'),
  get: (id: number) => api.get<unknown, ApiResponse<Project>>(`/projects/${id}`),
  create: (body: ProjectInput) =>
    api.post<unknown, ApiResponse<Project>>('/projects', body),
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
  company: '公司',
  repo: '代码仓库',
  app: '应用',
  dict: '字典',
}

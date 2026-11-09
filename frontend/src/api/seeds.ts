import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 种子（seed）是资产治理的入口对象：项目下声明「要盯什么」，
// 由计划（plan）与批次（run）负责展开与采集。与 ScopesHub 的种子页同构。
export type SeedKind = 'domain' | 'cidr' | 'company' | 'cert' | 'repo' | 'app' | 'dict'

export interface Seed {
  id: number
  project_id: number
  kind: SeedKind
  value: string
  capability: Record<string, unknown> | null
  enabled: boolean
  created_at: string
}

export const seedsApi = {
  list: (projectId?: number | string): Promise<ApiResponse<Seed[]>> =>
    api.get('/seeds', {
      params: projectId && String(projectId) !== '0' ? { project_id: projectId } : undefined,
    }),

  // 域名种子的覆盖站点数：后端返回 items:[{seed_id, site_count}]，不是 map。
  domainCounts: (projectId?: number | string): Promise<ApiResponse<{ items: { seed_id: number; site_count: number }[]; total: number }>> =>
    api.get('/seeds/domain-counts', {
      params: projectId && String(projectId) !== '0' ? { project_id: projectId } : undefined,
    }),

  // 批量建种子（可选同时建计划），逐条返回状态，不因一条失败中断整批。
  createBatch: (body: {
    project_id: number | string
    items: {
      kind: SeedKind
      value: string
      capability?: Record<string, unknown>
      enabled?: boolean
      interval_hours?: number
    }[]
  }): Promise<ApiResponse<SeedBatchResult>> => api.post('/seeds/batch', body),

  // 重建计划：先预览拿一次性 token（15 分钟有效），确认后执行。
  restartPreview: (
    seedId: number,
    body?: { interval_hours?: number }
  ): Promise<ApiResponse<SeedRestartPreview>> =>
    api.post(`/seeds/${seedId}/restart-preview`, body ?? {}),

  restart: (
    seedId: number,
    token: string
  ): Promise<ApiResponse<{ plan: PlanLike | null; deleted: SeedRestartCounts }>> =>
    api.post(`/seeds/${seedId}/restart`, { token }),
}

export interface SeedBatchResult {
  requested: number
  created: number
  duplicate: number
  invalid: number
  failed: number
  items: {
    index: number
    kind: string
    value: string
    status: string
    seed_id?: number
    plan_id?: number
    error?: string
  }[]
}

export interface SeedRestartPreview {
  seed: Seed | null
  plans: { id: number; interval_hours: number; enabled: boolean }[]
  runs: number
  run_targets: number
  interval_hours: number
  token: string
  expires_at: string
}

export interface SeedRestartCounts {
  plans?: number
  runs?: number
  targets?: number
  [k: string]: unknown
}

// 重启返回的计划体（前端只展示字段，避免引入 Plan 类型循环依赖）
export interface PlanLike {
  id: number
  seed_id: number
  interval_hours: number
  enabled: boolean
  [k: string]: unknown
}

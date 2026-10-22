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

export interface SeedCapabilities {
  kinds?: { value: SeedKind; label: string; hint?: string }[]
  [key: string]: unknown
}

export interface SeedPreview {
  targets?: { host?: string; value?: string; port?: number }[]
  total?: number
  shown?: number
  truncated?: boolean
  mode?: string
  warnings?: string[]
  note?: string
}

export const seedsApi = {
  list: (projectId?: number | string): Promise<ApiResponse<Seed[]>> =>
    api.get('/seeds', {
      params: projectId && String(projectId) !== '0' ? { project_id: projectId } : undefined,
    }),

  create: (body: {
    project_id: number | string
    kind: SeedKind
    value: string
    capability?: Record<string, unknown>
  }): Promise<ApiResponse<Seed>> => api.post('/seeds', body),

  remove: (id: number): Promise<ApiResponse<null>> => api.delete(`/seeds/${id}`),

  capabilities: (): Promise<ApiResponse<SeedCapabilities>> => api.get('/seeds/capabilities'),

  preview: (body: { project_id: number | string; kind: SeedKind; value: string }): Promise<ApiResponse<SeedPreview>> =>
    api.post('/seeds/preview', body),

  // 域名种子的覆盖站点数：后端返回 items:[{seed_id, site_count}]，不是 map。
  domainCounts: (projectId?: number | string): Promise<ApiResponse<{ items: { seed_id: number; site_count: number }[]; total: number }>> =>
    api.get('/seeds/domain-counts', {
      params: projectId && String(projectId) !== '0' ? { project_id: projectId } : undefined,
    }),
}

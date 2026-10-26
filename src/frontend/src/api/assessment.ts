import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 采集完成综合评估：最新评估 + 资产面趋势（快照）+ 风险下钻。

export interface CollectionAssessment {
  project_id: number
  project_name: string
  trigger: string
  entities: number
  entities_dead: number
  digital_assets: number
  digital_by_kind: Record<string, number>
  digital_pending: number
  domain_candidates: number
  domain_no_icp: number
  domain_group_pending: number
  seeds: number
  sites: number
  sites_odd_port: number
  sites_plain_http: number
  sites_cert_expiring: number
  expired_sessions: number
  risks: string[]
  summary: string
}

export interface AssessmentTrendPoint {
  taken_at: string
  stats: CollectionAssessment
}

export interface AssessmentSite {
  id: number
  host: string
  port: number
  protocol: string
  http_status: number
  title: string
}

export type AssessmentSiteFilter = 'plain_http' | 'odd_port' | 'cert_expiring'

export const assessmentApi = {
  get: (projectId: number) =>
    api.get<unknown, ApiResponse<{ latest: CollectionAssessment; trend: AssessmentTrendPoint[] }>>(
      `/projects/${projectId}/assessment`
    ),

  sites: (projectId: number, filter: AssessmentSiteFilter) =>
    api.get<unknown, ApiResponse<{ items: AssessmentSite[]; total: number }>>(
      `/projects/${projectId}/assessment/sites`,
      { params: { filter } }
    ),

  purgeDead: (projectId: number) =>
    api.post<unknown, ApiResponse<{ entities: number; digital_candidates: number; domain_candidates: number }>>(
      '/enterprise-entities/purge-dead',
      { project_id: projectId }
    ),
}

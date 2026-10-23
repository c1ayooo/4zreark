import api, { ApiResponse } from '@/lib/api'

export type CandidateStatus = 'pending' | 'accepted' | 'rejected'

/** 发现候选：自动发现出的疑似资产，人工确认后才转为项目种子 */
export interface DiscoveryCandidate {
  id: number
  project_id: number
  kind: string
  value: string
  source: string
  /** 0-100，来源给到的可信度 */
  confidence: number
  status: CandidateStatus
  created_at: string
  decided_at: string | null
}

export interface DiscoveryCandidatesResult {
  items: DiscoveryCandidate[]
  /** 待处理数，与 status 过滤无关，始终返回 */
  pending: number
}

export interface DiscoveryRunSummary {
  sources: number
  from_ctlog: number
  from_engines: number
  new_count: number
}

/** 站点内容巡检状态 */
export interface WatchStatus {
  content_hash: string
  content_text_hash: string
  content_checked_at: string | null
  content_changed_at: string | null
  watch_excluded: boolean
}

export const discoveryApi = {
  candidates: (projectId: number, status: CandidateStatus = 'pending', limit = 200) =>
    api.get<unknown, ApiResponse<DiscoveryCandidatesResult>>(
      `/projects/${projectId}/candidates`,
      { params: { status, limit } }
    ),
  decide: (projectId: number, ids: number[], accept: boolean) =>
    api.post<unknown, ApiResponse<{ updated: number }>>(
      `/projects/${projectId}/candidates/decide`,
      { ids, accept }
    ),
  runDiscovery: (projectId: number) =>
    api.post<unknown, ApiResponse<DiscoveryRunSummary>>(`/projects/${projectId}/discovery/run`),
  setWatchExcluded: (siteId: number, excluded: boolean) =>
    api.put<unknown, ApiResponse<{ excluded: boolean }>>(`/sites/${siteId}/watch-excluded`, {
      excluded,
    }),
  watchStatus: (siteId: number) =>
    api.get<unknown, ApiResponse<WatchStatus>>(`/sites/${siteId}/watch-status`),
}

import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 工信部 ICP 官方备案查询（异步单 worker + 全局限速）。

export interface ICPQuery {
  id: string
  project_id: number
  query: string
  service_type: number
  page_size: number
  status: 'queued' | 'running' | 'done' | 'error' | 'canceled' | string
  total: number
  pages: number
  fetched: number
  error: string
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface ICPFiling {
  id: number
  query_id: string
  project_id: number
  domain: string
  main_licence: string
  service_licence: string
  unit_name: string
  nature_name: string
  content_type: string
  leader_name: string
  update_record_time: string
  created_at: string
}

export const icpApi = {
  enqueue: (body: {
    project_id: number
    query: string
    service_type?: number
    page_size?: number
  }) => api.post<unknown, ApiResponse<ICPQuery>>('/icp/queries', body),

  list: (projectId?: number, limit = 50) =>
    api.get<unknown, ApiResponse<{ items: ICPQuery[]; total: number }>>('/icp/queries', {
      params: { project_id: projectId || undefined, limit },
    }),

  get: (id: string, limit = 500) =>
    api.get<unknown, ApiResponse<{ query: ICPQuery; filings: ICPFiling[]; total: number }>>(
      `/icp/queries/${encodeURIComponent(id)}`,
      { params: { limit } }
    ),

  cancel: (id: string) =>
    api.post<unknown, ApiResponse<{ id: string }>>(
      `/icp/queries/${encodeURIComponent(id)}/cancel`
    ),
}

import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

export interface MonitoringPreset {
  id: number
  name: string
  interval_hours: number
  budget: Record<string, unknown>
  is_default: boolean
  created_at: string
}

export const monitoringApi = {
  list: () =>
    api.get<unknown, ApiResponse<{ items: MonitoringPreset[]; total: number }>>(
      '/monitoring-presets'
    ),
  create: (body: {
    name: string
    interval_hours: number
    budget?: Record<string, unknown>
    is_default?: boolean
  }) => api.post<unknown, ApiResponse<MonitoringPreset>>('/monitoring-presets', body),
  update: (
    id: number,
    body: { name: string; interval_hours: number; budget?: Record<string, unknown>; is_default?: boolean }
  ) => api.put<unknown, ApiResponse<MonitoringPreset>>(`/monitoring-presets/${id}`, body),
  remove: (id: number) =>
    api.delete<unknown, ApiResponse<null>>(`/monitoring-presets/${id}`),
  previewBulk: (body: {
    project_id?: number
    plan_ids?: number[]
    enabled?: boolean
    interval_hours?: number
  }) => api.post<unknown, ApiResponse<{ total: number; sample: unknown[] }>>(
    '/monitoring-bulk/preview',
    body
  ),
  bulk: (body: {
    project_id?: number
    plan_ids?: number[]
    enabled?: boolean
    interval_hours?: number
  }) => api.post<unknown, ApiResponse<{ requested: number; updated: number }>>(
    '/monitoring-bulk',
    body
  ),
}

import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'
import type { Run } from '@/api/projects'

// v4 §15.2 / §17：治理批次（runs）列表、详情、执行单元与手动执行。

export interface RunTarget {
  id: number
  run_id: number
  project_id: number
  host: string
  port: number
  capability: Record<string, unknown>
  state: 'pending' | 'running' | 'done' | 'failed' | 'skipped' | string
  attempts: number
  lease_until: string | null
}

export interface RunDetail {
  run: Run
  target_stats: Record<string, number>
}

export const runStatusLabel: Record<string, string> = {
  queued: '待执行',
  running: '执行中',
  partial: '部分失败',
  done: '已完成',
  failed: '失败',
}

export const runStatusVariant = (
  status: string
): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (status === 'running') return 'default'
  if (status === 'done') return 'secondary'
  if (status === 'partial' || status === 'failed') return 'destructive'
  return 'outline'
}

export const targetStateLabel: Record<string, string> = {
  pending: '待执行',
  running: '执行中',
  done: '完成',
  failed: '失败',
  skipped: '跳过',
}

export const runApi = {
  list: (projectId?: number, limit = 100) =>
    api.get<unknown, ApiResponse<Run[]>>('/runs', {
      params: { project_id: projectId || undefined, limit },
    }),
  detail: (id: number) => api.get<unknown, ApiResponse<RunDetail>>(`/runs/${id}`),
  targets: (id: number, state?: string, limit = 200) =>
    api.get<unknown, ApiResponse<RunTarget[]>>(`/runs/${id}/targets`, {
      params: { state: state || undefined, limit },
    }),
  execute: (id: number, limit = 50) =>
    api.post<unknown, ApiResponse<Record<string, unknown>>>(`/runs/${id}/execute`, null, {
      params: { limit },
    }),
}

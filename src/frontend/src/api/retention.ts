import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// v4 §17：设置页展示数据留存策略并支持手动清理（后端策略由环境变量配置）。

export interface RetentionPolicy {
  scan_results_days: number
  raw_records_days: number
  verifications_days: number
  events_keep: number
  events_days: number
  batch_limit: number
}

export interface RetentionReport {
  policy: RetentionPolicy
  dry_run: boolean
  scan_results: number
  raw_records: number
  verifications: number
  events: number
  duration_ms: number
  errors?: string[]
}

export const retentionApi = {
  policy: () => api.get<unknown, ApiResponse<RetentionPolicy>>('/governance/retention'),
  run: (dryRun: boolean) =>
    api.post<unknown, ApiResponse<RetentionReport>>('/governance/retention/run', null, {
      params: { dry_run: dryRun ? 1 : 0 },
    }),
}

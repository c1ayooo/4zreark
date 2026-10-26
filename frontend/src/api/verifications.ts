import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

export interface VerificationRow {
  id: number
  site_id: number
  project_id: number
  host: string
  status: string
  reason_code: string
  http_status: number
  attempts: number
  detail: Record<string, unknown>
  observed_at: string
}

export interface VerificationStat {
  key: string
  count: number
}

export interface VerificationStats {
  by_status: VerificationStat[]
  by_reason: VerificationStat[]
}

export interface VerificationSample {
  site_id: number
  host: string
  state: string
  verification_status: string
  attempts: number
  next_verification_at: string | null
}

export interface VerificationBatchPreview {
  total: number
  sample: VerificationSample[]
  note?: string
}

export interface RecheckReport {
  requested: number
  reset: number
  skipped: number
  items: { site_id: number; host: string; before_state: string; before_attempts: number }[]
  skipped_items: { site_id: number; host: string; reason: string }[]
  warnings?: string[]
}

export interface VerificationBatchResult {
  matched: number
  requested: number
  truncated: boolean
  recheck: RecheckReport
}

const batchBody = (projectId: number) => ({ project_id: projectId || undefined })

export const verificationApi = {
  list: (params: {
    project_id?: number
    site_id?: number
    status?: string
    reason_code?: string
    page?: number
    page_size?: number
  }) =>
    api.get<
      unknown,
      ApiResponse<{
        items: VerificationRow[]
        total: number
        page: number
        page_size: number
      }>
    >('/verifications', { params }),

  stats: (projectId?: number) =>
    api.get<unknown, ApiResponse<VerificationStats>>('/verifications/stats', {
      params: { project_id: projectId || undefined },
    }),

  previewBatch: (projectId: number) =>
    api.post<unknown, ApiResponse<VerificationBatchPreview>>(
      '/verifications/batches/preview',
      batchBody(projectId)
    ),

  executeBatch: (projectId: number) =>
    api.post<unknown, ApiResponse<VerificationBatchResult>>(
      '/verifications/batches',
      batchBody(projectId)
    ),

  recheck: (siteIds: number[]) =>
    api.post<unknown, ApiResponse<RecheckReport>>('/assets/verification-recheck', {
      site_ids: siteIds,
    }),
}

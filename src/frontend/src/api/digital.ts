import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// v4 §14：数字资产名单（与站点库解耦）与本地文档两段式导入。

export type DigitalKind = 'app' | 'miniapp' | 'official_account' | 'newmedia'

export interface DigitalAsset {
  id: number
  project_id: number
  kind: DigitalKind | string
  name: string
  company: string
  platform: string
  source: string
  status: string
  batch_id: number | null
  created_at: string
}

export interface DigitalPreview {
  token: string
  expires_at: string
  project_id: number
  kind: string
  total: number
  unique: number
  duplicates: number
  existing: number
  invalid: number
  sample: Array<{ kind: string; name: string; company: string; platform: string }>
}

export interface ImportBatch {
  id: number
  project_id: number
  kind: string
  status: string
  summary: Record<string, unknown>
  created_by: string
  created_at: string
}

export interface LocalDocPreview {
  token: string
  expires_at: string
  project_id: number
  filename: string
  format: string
  total: number
  hosts: number
  names: number
  duplicates: number
  invalid: number
  sample_hosts: string[]
  sample_names: Array<{ kind: string; name: string; company: string; platform: string }>
}

export interface LocalDocCommit {
  batch: ImportBatch | null
  inserted: number
  hosts: { records: number; new_sites: number; dup_records: number; new_endpoints: number } | null
}

export const digitalKinds: Array<{ value: DigitalKind; label: string }> = [
  { value: 'app', label: 'APP' },
  { value: 'miniapp', label: '小程序' },
  { value: 'official_account', label: '公众号' },
  { value: 'newmedia', label: '新媒体' },
]

export const digitalKindLabel: Record<string, string> = Object.fromEntries(
  digitalKinds.map((k) => [k.value, k.label])
)

export interface DigitalListResponse {
  code: number
  message: string
  data: DigitalAsset[]
  total: number
  page: number
  size: number
}

export const digitalApi = {
  list: (params: {
    project_id?: number
    kind?: string
    q?: string
    page?: number
    page_size?: number
  }) => api.get<unknown, DigitalListResponse>('/digital-assets', { params }),

  preview: (body: {
    project_id: number
    kind: string
    text?: string
    names?: string[]
    company?: string
    platform?: string
    source?: string
  }) => api.post<unknown, ApiResponse<DigitalPreview>>('/digital-assets/preview', body),

  commit: (token: string) =>
    api.post<unknown, ApiResponse<{ batch: ImportBatch; inserted: number }>>(
      '/digital-assets/commit',
      { token }
    ),

  remove: (id: number) => api.delete<unknown, ApiResponse<null>>(`/digital-assets/${id}`),

  batches: (projectId?: number, limit = 50) =>
    api.get<unknown, ApiResponse<{ items: ImportBatch[]; total: number }>>('/digital-imports', {
      params: { project_id: projectId || undefined, limit },
    }),

  undo: (batchId: number) =>
    api.post<unknown, ApiResponse<{ deleted: number }>>('/digital-imports/undo', {
      batch_id: batchId,
    }),

  cancel: (token: string, kind: 'digital' | 'local_doc') =>
    api.post<unknown, ApiResponse<{ cancelled: boolean }>>('/digital-imports/cancel', {
      token,
      kind,
    }),
}

export const localDocApi = {
  preview: (projectId: number, file: File) => {
    const form = new FormData()
    form.append('project_id', String(projectId))
    form.append('file', file)
    return api.post<unknown, ApiResponse<LocalDocPreview>>('/local-documents/preview', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  import: (token: string) =>
    api.post<unknown, ApiResponse<LocalDocCommit>>('/local-documents/import', { token }),
}

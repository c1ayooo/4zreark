import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 后端 SuccessWithPagination 的形状（与 nodes/pocs 等保持一致）
interface BackendPaginatedResponse<T> {
  code: number
  message: string
  data: T[]
  total: number
  page: number
  size: number
}

// G4：数据源与字典接口。

export interface Source {
  id: number
  kind: string
  name: string
  endpoint: string
  enabled: boolean
  config: Record<string, unknown>
  has_secret: boolean
  last_ok_at: string | null
  last_error: string
  cooldown_until: string | null
  created_at: string
}

export interface SourceInput {
  kind: string
  name: string
  endpoint?: string
  enabled: boolean
  config?: Record<string, unknown>
  secret?: string
}

export interface SourceTestResult {
  ok: boolean
  status: number
  message: string
  elapsed_ms: number
}

export const sourceKinds = [
  'fofa',
  'hunter',
  'quake',
  'zoomeye',
  'shodan',
  'crtsh',
  'wayback',
  'github',
  'gitlab',
  'appstore',
  'import',
  'custom',
]

export const sourceApi = {
  list: () => api.get<unknown, ApiResponse<{ items: Source[]; total: number }>>('/sources'),
  create: (body: SourceInput) => api.post<unknown, ApiResponse<Source>>('/sources', body),
  update: (id: number, body: SourceInput) => api.put<unknown, ApiResponse<Source>>(`/sources/${id}`, body),
  remove: (id: number) => api.delete<unknown, ApiResponse<null>>(`/sources/${id}`),
  test: (id: number) => api.post<unknown, ApiResponse<SourceTestResult>>(`/sources/${id}/test`),
}

export interface Dictionary {
  id: string
  name: string
  type: string
  description: string
  file_path: string
  line_count: number
  is_builtin: boolean
  created_at: string
  updated_at: string
}

export interface DictionaryPreview {
  token: string
  name: string
  type: string
  expires_at: string
  total: number
  unique: number
  duplicates: number
  segments: number
  sample: string[]
}

export const dictionaryTypes = ['subdomain', 'directory', 'username', 'password', 'business', 'custom']

export const dictionaryApi = {
  list: (params: { type?: string; page?: number; page_size?: number }) =>
    api.get<unknown, BackendPaginatedResponse<Dictionary>>('/dictionaries', { params }),
  preview: (body: {
    name: string
    type: string
    text?: string
    format?: string
    content_base64?: string
  }) => api.post<unknown, ApiResponse<DictionaryPreview>>('/dictionaries/preview', body),
  import: (token: string) =>
    api.post<unknown, ApiResponse<{ dictionary: Dictionary; entries: number }>>('/dictionaries/import', {
      token,
    }),
  entries: (id: string, params: { segment?: number; page?: number; page_size?: number }) =>
    api.get<unknown, BackendPaginatedResponse<string>>(`/dictionaries/${id}/entries`, { params }),
  remove: (id: string) => api.delete<unknown, ApiResponse<null>>(`/dictionaries/${id}`),
}

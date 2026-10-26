import api from '@/lib/api'

// v4 §17：指纹库页面用的治理域规则接口（覆盖 expression 与条件树两种规则）。

export interface FpRule {
  id: string
  name: string
  category: string
  version: string
  enabled: boolean
  dsl_version: number
  condition_tree?: Record<string, unknown> | null
  rules?: Array<{ type: string; key?: string; pattern: string; operator: string }>
  expression?: string
  source: string
  created_at: string
  updated_at: string
}

export interface FpListResponse {
  code: number
  message: string
  data: FpRule[]
  total: number
  page: number
  size: number
}

export interface FpRuleInput {
  name: string
  category: string
  version?: string
  enabled: boolean
  expression?: string
  condition_tree?: Record<string, unknown> | null
  source?: string
}

export const fpApi = {
  list: (params: {
    q?: string
    category?: string
    source?: string
    enabled?: string
    page?: number
    page_size?: number
  }) => api.get<unknown, FpListResponse>('/governance/fingerprints', { params }),

  upsert: (body: FpRuleInput) =>
    api.post<unknown, { code: number; message: string; data: FpRule }>(
      '/governance/fingerprints',
      body
    ),

  remove: (name: string) =>
    api.delete<unknown, { code: number; message: string }>(
      `/governance/fingerprints/${encodeURIComponent(name)}`
    ),

  toggle: (name: string, enabled: boolean) =>
    api.post<unknown, { code: number; message: string }>(
      `/governance/fingerprints/${encodeURIComponent(name)}/toggle`,
      { enabled }
    ),

  sync: () =>
    api.post<unknown, { code: number; message: string; data: { sources: unknown } }>(
      '/governance/fingerprints/sync'
    ),

  sources: () =>
    api.get<unknown, { code: number; message: string; data: { sources: unknown; counts: Record<string, number> } }>(
      '/governance/fingerprints/sources'
    ),
}

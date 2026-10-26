import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 后端 /api/vuln-intel 的响应形状：
//   列表走 SuccessWithPagination：{ code, message, data: [...], total, page, size }
//   统计/详情/富化走 Success：{ code, message, data: {...} }
export interface IntelPOC {
  full_name: string
  url: string
  stars: number
  verdict: string
  triage_score: number
}

export interface IntelItem {
  unique_key: string
  title: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cve: string
  disclosure: string
  solutions: string
  source: string
  source_name: string
  source_url: string
  tags: string[]
  references: string[]
  created_at: string
  updated_at: string
  lab_only: boolean
  enriched_at?: string
  has_poc?: boolean
  cvss_score?: number
  cvss_vector?: string
  cwes?: number[]
  affected?: string[]
  github_poc?: IntelPOC[]
}

export interface IntelStats {
  total: number
  by_source: { source_name: string; count: number }[]
  by_severity: { severity: string; count: number }[]
}

export interface EnrichmentStatus {
  total: number
  enriched: number
  with_poc: number
  poc_total: number
  lab_only: number
  by_source: { source: string; total: number; enriched: number; poc_total: number }[]
}

export interface IntelListResult {
  items: IntelItem[]
  total: number
  page: number
  pageSize: number
}

export interface IntelQuery {
  severity?: string
  source_name?: string
  cve?: string
  q?: string
  page?: number
  pageSize?: number
}

interface BackendIntelPage {
  code: number
  message: string
  data: IntelItem[]
  total: number
  page: number
  size: number
}

export const intelApi = {
  list: async (params: IntelQuery = {}): Promise<IntelListResult> => {
    const raw = (await api.get('/vuln-intel', {
      params: {
        severity: params.severity || undefined,
        source_name: params.source_name || undefined,
        cve: params.cve || undefined,
        q: params.q || undefined,
        page: params.page || 1,
        page_size: params.pageSize || 20,
      },
    })) as unknown as BackendIntelPage
    return {
      items: raw.data || [],
      total: raw.total || 0,
      page: raw.page || 1,
      pageSize: raw.size || 20,
    }
  },

  stats: async (): Promise<IntelStats> => {
    const raw = (await api.get('/vuln-intel/stats')) as unknown as ApiResponse<IntelStats>
    return raw.data
  },

  enrichmentStatus: async (): Promise<EnrichmentStatus> => {
    const raw = (await api.get('/enrichment/status')) as unknown as ApiResponse<EnrichmentStatus>
    return raw.data
  },

  get: async (uniqueKey: string): Promise<IntelItem> => {
    const raw = (await api.get(`/vuln-intel/${encodeURIComponent(uniqueKey)}`)) as unknown as ApiResponse<IntelItem>
    return raw.data
  },

  // 富化会真实访问 GitHub API，可能耗时几十秒；超时单独放大。
  enrich: async (uniqueKey: string): Promise<{
    poc_count: number
    pocs: IntelPOC[]
    cvss_score: number
    cwes: string[]
    affected: string[]
    lab_only: boolean
  }> => {
    const raw = (await api.post(
      `/vuln-intel/${encodeURIComponent(uniqueKey)}/enrich`,
      {},
      { timeout: 120000 }
    )) as unknown as ApiResponse<{
      poc_count: number
      pocs: IntelPOC[]
      cvss_score: number
      cwes: string[]
      affected: string[]
      lab_only: boolean
    }>
    return raw.data
  },

  triggerPoll: async (): Promise<{ new: number; updated: number; failed: number; sources: number }> => {
    const raw = (await api.post('/vuln-intel/poll', {}, { timeout: 320000 })) as unknown as ApiResponse<{
      new: number
      updated: number
      failed: number
      sources: number
    }>
    return raw.data
  },
}

import api, { ApiResponse } from '@/lib/api'

// 与后端 scanner.TakeoverResult 的 json tag 严格对齐
export interface TakeoverResult {
  domain: string
  cname: string
  service: string
  vulnerable: boolean
  fingerprints: string[]
  reason: string
  discussion?: string
}

export interface BatchTakeoverResult {
  total: number
  vulnerable: number
  results: TakeoverResult[]
}

// 后端 GetFingerprints 的简化输出
export interface TakeoverFingerprint {
  service: string
  cnames: string[]
  vulnerable: boolean
  nxdomain: boolean
  http_check: boolean
}

export const takeoverApi = {
  // 单域名检测：POST /scan/takeover
  check: (domain: string): Promise<ApiResponse<TakeoverResult>> =>
    api.post('/scan/takeover', { domain }),

  // 批量检测：POST /scan/takeover/batch（单次最多 1000 个）
  batchCheck: (domains: string[]): Promise<ApiResponse<BatchTakeoverResult>> =>
    api.post('/scan/takeover/batch', { domains }),

  // 接管指纹库：GET /scan/takeover/fingerprints
  getFingerprints: (): Promise<ApiResponse<TakeoverFingerprint[]>> =>
    api.get('/scan/takeover/fingerprints'),
}

import api, { ApiResponse } from '@/lib/api'

/**
 * GitHub Token 池（统一池）。
 * 存储与监控面板的 Token 池是同一张 github_token_pool 表：设置页、监控面板、
 * 情报检索、sentinel 采集读写的都是同一个池子。
 * token 明文只在添加时提交，服务端存储后 GET 只回脱敏串。
 */
export interface GitHubToken {
  id: string
  label: string
  /** 脱敏串（如 ghp_05Q…n5W），明文永不回传 */
  masked: string
  enabled: boolean
  rate_limit: number
  /** -1 = 未采集 */
  rate_remaining: number
  rate_used: number
  rate_reset_at: string | null
  last_checked_at: string | null
  created_at: string
}

export interface GitHubTokenInput {
  label?: string
  token: string
}

export const githubTokensApi = {
  list: (): Promise<ApiResponse<{ items: GitHubToken[]; total: number }>> =>
    api.get('/github/tokens'),

  add: (body: GitHubTokenInput): Promise<ApiResponse<GitHubToken>> =>
    api.post('/github/tokens', body),

  remove: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/github/tokens/${id}`),
}

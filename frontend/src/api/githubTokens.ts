import api, { ApiResponse } from '@/lib/api'

/**
 * GitHub Token 池：仓库采集认证与 API 限流提升，多条轮询使用。
 * token 明文只在添加时提交，服务端存储后 GET 只回脱敏串。
 */

export interface GitHubToken {
  id: number
  name: string
  /** 脱敏串（如 ghp_05Q…n5W），明文永不回传 */
  masked: string
  enabled: boolean
  created_at: string
}

export interface GitHubTokenInput {
  name?: string
  token: string
}

export const githubTokensApi = {
  list: (): Promise<ApiResponse<{ items: GitHubToken[]; total: number }>> =>
    api.get('/github/tokens'),

  add: (body: GitHubTokenInput): Promise<ApiResponse<GitHubToken>> =>
    api.post('/github/tokens', body),

  remove: (id: number): Promise<ApiResponse<null>> =>
    api.delete(`/github/tokens/${id}`),
}

import api, { ApiResponse } from '@/lib/api'

/** GitHub 泄露监控（迁移自 4zreco/internal/githubleak） */

export interface GitHubMonitorRule {
  id: number
  project_id: number
  name: string
  keywords: string[]
  enabled: boolean
  created_at: string
}

export interface GitHubFinding {
  id: string
  status: string
  rule_name: string
  keyword: string
  repository: string
  path: string
  line: number
  secret_type: string
  confidence: string
  severity: string
  /** H4 加固：API 不返回明文，只有脱敏摘录与首末锚点 */
  masked_excerpt: string
  html_url: string
  fingerprint?: string
  secret_key?: string
  verify_status?: string
  verify_evidence?: string
  source_updated_at?: string
  first_seen_at: string
  last_seen_at: string
  /** 兼容旧字段（历史响应） */
  first_seen?: string
  last_seen?: string
}

export interface GitHubFindingListParams {
  status?: string
  keyword?: string
  q?: string
  page?: number
  page_size?: number
}

export interface GitHubFindingsPage {
  items: GitHubFinding[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface GitHubMonitorSettings {
  project_id: number
  enabled: boolean
  token_configured: boolean
  interval_seconds?: number
  /** 高级误报治理与动态规则（迁移自 4zreco 设置面） */
  repo_max_age_days?: number
  lookback_days?: number
  boilerplate_repos?: number
  blob_rescan?: boolean
  max_blob_rescans_per_rule?: number
  extra_rules_path?: string
  notify_enabled?: boolean
  updated?: string
}

export interface GitHubMonitorOverview {
  settings: GitHubMonitorSettings
  rules: GitHubMonitorRule[]
  stats: Record<string, number>
  latest_run: Record<string, unknown>
  monitor_ready: boolean
  monitor_error: string
}

/** 误报抑制规则（迁移自 4zreco suppressions） */
export interface GitHubSuppression {
  id: string
  pattern_type: string
  pattern: string
  note: string
  created_by: string
  created_at: string
}

/** Token 池账号（token 不回显，只有 masked；配额字段供面板展示） */
export interface GitHubPoolToken {
  id: string
  label: string
  masked: string
  enabled: boolean
  rate_limit: number
  rate_remaining: number
  rate_used: number
  rate_reset_at: string | null
  last_checked_at: string | null
  created_at: string
}

/** 规则精度统计（确认/误报/忽略与精确率） */
export interface GitHubRulePrecision {
  rule_name: string
  total: number
  confirmed: number
  false_positive: number
  ignored: number
  precision: number
  last_seen_at?: string
}

/** 历史噪音清理报告（preview/apply 同构） */
export interface GitHubCleanupReport {
  total: number
  matched: number
  deleted: number
  by_status: Record<string, number>
  by_type: Record<string, number>
  samples?: Array<Record<string, unknown>>
}

/** 命中分状态统计（全局页概览卡） */
export interface GitHubLeakStats {
  total: number
  new: number
  triaged: number
  false_positive: number
  resolved: number
  likely: number
  suspected: number
}

/** 监控运行态（/github-monitor/runtime） */
export interface GitHubRuntimeStatus {
  enabled: boolean
  configured: boolean
  running: boolean
  last_run_at?: string
  next_run_at?: string
  last_status: string
  last_error: string
  last_warning: string
  rate_remaining: number
  rate_reset_at?: string
  interval_seconds: number
  request_interval_seconds: number
  request_timeout_seconds: number
  keywords: string[]
  query: string
  repo_max_age_days: number
  lookback_days: number
  rules?: Array<Record<string, unknown>>
  last_requests: number
  last_processed: number
  last_detected: number
  notify_enabled: boolean
}

export const githubMonitorApi = {
  overview: (projectId: number) =>
    api.get<unknown, ApiResponse<GitHubMonitorOverview>>(`/projects/${projectId}/github-monitor`),
  saveSettings: (
    projectId: number,
    body: {
      enabled: boolean
      token?: string
      interval_seconds?: number
      repo_max_age_days?: number
      lookback_days?: number
      boilerplate_repos?: number
      blob_rescan?: boolean
      max_blob_rescans_per_rule?: number
      extra_rules_path?: string
      notify_enabled?: boolean
    },
  ) =>
    api.put<unknown, ApiResponse<{ saved: boolean }>>(`/projects/${projectId}/github-monitor/settings`, body),
  createRule: (projectId: number, body: { name?: string; keywords: string[] }) =>
    api.post<unknown, ApiResponse<GitHubMonitorRule>>(`/projects/${projectId}/github-monitor/rules`, body),
  deleteRule: (projectId: number, ruleId: number) =>
    api.delete<unknown, ApiResponse<null>>(`/projects/${projectId}/github-monitor/rules/${ruleId}`),
  findings: (projectId: number, params: GitHubFindingListParams = {}) =>
    api.get<unknown, ApiResponse<GitHubFindingsPage>>(`/projects/${projectId}/github-monitor/findings`, { params }),
  updateFindingStatus: (projectId: number, findingId: string, status: string) =>
    api.put<unknown, ApiResponse<GitHubFinding>>(
      `/projects/${projectId}/github-monitor/findings/${findingId}/status`,
      { status },
    ),

  // ---- 全局运维（Run/Backfill/抑制/水线/规则精度/自动建规则/清理）----

  runtime: () => api.get<unknown, ApiResponse<GitHubRuntimeStatus>>('/github-monitor/runtime'),
  stats: () => api.get<unknown, ApiResponse<GitHubLeakStats>>('/github-monitor/stats'),

  // 全局命中（不带项目过滤）
  globalFindings: (params: GitHubFindingListParams = {}) =>
    api.get<unknown, ApiResponse<GitHubFindingsPage>>('/github-monitor/findings', { params }),
  globalUpdateFindingStatus: (findingId: string, status: string) =>
    api.put<unknown, ApiResponse<GitHubFinding>>(`/github-monitor/findings/${findingId}/status`, { status }),
  globalRecordVerifyResult: (findingId: string, body: { verify_status: string; verify_evidence?: string }) =>
    api.post<unknown, ApiResponse<{ verify_status: string }>>(
      `/github-monitor/findings/${findingId}/verify-result`,
      body,
    ),

  runNow: () => api.post<unknown, ApiResponse<{ accepted: boolean; busy?: boolean }>>('/github-monitor/run'),
  backfill: () => api.post<unknown, ApiResponse<{ filled: number }>>('/github-monitor/backfill'),
  listSuppressions: () =>
    api.get<unknown, ApiResponse<{ suppressions: GitHubSuppression[] }>>('/github-monitor/suppressions'),
  addSuppression: (body: { pattern_type: string; pattern: string; note?: string }) =>
    api.post<unknown, ApiResponse<{ created: boolean }>>('/github-monitor/suppressions', body),
  deleteSuppression: (id: string) =>
    api.delete<unknown, ApiResponse<{ deleted: boolean }>>(`/github-monitor/suppressions/${id}`),
  resetWaterline: (query?: string) =>
    api.post<unknown, ApiResponse<{ reset: number }>>('/github-monitor/waterline/reset', { query: query ?? '' }),
  rulePrecisionStats: () =>
    api.get<unknown, ApiResponse<{ rules: GitHubRulePrecision[] }>>('/github-monitor/rules/stats'),
  addAutoRules: (body: { domain?: string; org?: string }) =>
    api.post<unknown, ApiResponse<{ added: number }>>('/github-monitor/rules/auto', body),
  cleanupPreview: () => api.post<unknown, ApiResponse<GitHubCleanupReport>>('/github-monitor/cleanup/preview'),
  cleanupApply: () => api.post<unknown, ApiResponse<GitHubCleanupReport>>('/github-monitor/cleanup/apply'),

  // ---- Token 池 ----

  tokens: () => api.get<unknown, ApiResponse<GitHubPoolToken[]>>('/github-tokens'),
  addToken: (body: { label?: string; token: string }) =>
    api.post<unknown, ApiResponse<GitHubPoolToken>>('/github-tokens', body),
  deleteToken: (id: string) => api.delete<unknown, ApiResponse<null>>(`/github-tokens/${id}`),
  setTokenEnabled: (id: string, enabled: boolean) =>
    api.patch<unknown, ApiResponse<null>>(`/github-tokens/${id}/enabled`, { enabled }),
  refreshToken: (id: string) =>
    api.post<unknown, ApiResponse<GitHubPoolToken>>(`/github-tokens/${id}/refresh`),
  refreshAllTokens: () => api.post<unknown, ApiResponse<GitHubPoolToken[]>>('/github-tokens/refresh'),
}

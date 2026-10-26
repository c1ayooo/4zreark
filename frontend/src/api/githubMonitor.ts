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

export interface GitHubMonitorSettings {
  project_id: number
  enabled: boolean
  token_configured: boolean
  interval_seconds?: number
  updated?: string
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
  masked_excerpt: string
  html_url: string
  verify_status?: string
  first_seen?: string
  last_seen?: string
}

export interface GitHubFindingsPage {
  items: GitHubFinding[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface GitHubMonitorOverview {
  settings: GitHubMonitorSettings
  rules: GitHubMonitorRule[]
  stats: Record<string, number>
  latest_run: Record<string, unknown>
  monitor_ready: boolean
  monitor_error: string
}

export const githubMonitorApi = {
  overview: (projectId: number) =>
    api.get<unknown, ApiResponse<GitHubMonitorOverview>>(`/projects/${projectId}/github-monitor`),
  saveSettings: (projectId: number, body: { enabled: boolean; token?: string; interval_seconds?: number }) =>
    api.put<unknown, ApiResponse<{ saved: boolean }>>(`/projects/${projectId}/github-monitor/settings`, body),
  createRule: (projectId: number, body: { name?: string; keywords: string[] }) =>
    api.post<unknown, ApiResponse<GitHubMonitorRule>>(`/projects/${projectId}/github-monitor/rules`, body),
  deleteRule: (projectId: number, ruleId: number) =>
    api.delete<unknown, ApiResponse<null>>(`/projects/${projectId}/github-monitor/rules/${ruleId}`),
  findings: (projectId: number, params: { status?: string; q?: string; page?: number; page_size?: number } = {}) =>
    api.get<unknown, ApiResponse<GitHubFindingsPage>>(`/projects/${projectId}/github-monitor/findings`, { params }),
  updateFindingStatus: (projectId: number, findingId: string, status: string) =>
    api.put<unknown, ApiResponse<GitHubFinding>>(
      `/projects/${projectId}/github-monitor/findings/${findingId}/status`,
      { status },
    ),
}

import api, { ApiResponse } from '@/lib/api'

/**
 * CommitSentinel（提交哨兵）：采集公开仓库提交 → 判定是否为安全修复 → 落地发现。
 * 后端：api/sentinel_handler.go，路由前缀 /api/sentinel。
 *
 * 约定：这里统一把 ApiResponse 解包成业务对象，页面不再写 `.data.data`。
 * 分页接口（commits/findings）后端用 SuccessWithPagination，total/page/size 在响应顶层。
 */

export interface SentinelOverview {
  repo_count: number
  today_commits: number
  security_fixes: number
  pending_commits: number
  queue_backlog: number
}

export interface SentinelRepo {
  id: string
  full_name: string
  clone_url: string
  default_branch: string
  branch: string
  interval_minutes: number
  enabled: boolean
  last_checked_at: string | null
  last_commit_sha: string
  /** 上次采集失败原因；空串表示正常 */
  last_error: string
  created_at: string
  updated_at: string
}

export interface SentinelCommit {
  id: number
  repo_id: string
  repo_full_name: string
  sha: string
  subject: string
  author_name: string
  committed_at: string
  files_changed: number
  additions: number
  deletions: number
  /** pending / judged / skipped / failed */
  status: string
  skip_reason: string
  judged: boolean
  is_security_fix: boolean
  vuln_class: string
  severity: string
  confidence: number
}

export interface SentinelCommitDetail {
  id: number
  repo_id: string
  repo_full_name: string
  sha: string
  author_name: string
  author_email: string
  committed_at: string
  subject: string
  message: string
  files_changed: number
  additions: number
  deletions: number
  diff: string
  status: string
  skip_reason: string
  created_at: string
}

export interface SentinelJudgment {
  id: number
  commit_id: number
  model: string
  is_security_fix: boolean
  vuln_class: string
  severity: string
  confidence: number
  title: string
  reasoning: string
  /** 结构化证据：后端是 []string（真实 hunk 头），可能为 null */
  evidence: string[] | null
  partial: boolean
  prompt_tokens: number
  completion_tokens: number
  created_at: string
}

export interface SentinelFinding {
  id: number
  commit_id: number
  judgment_id: number | null
  vuln_class: string
  severity: string
  status: string
  title: string
  detail: string
  created_at: string
  updated_at: string
  repo_id: string
  repo_full_name: string
  sha: string
  subject: string
  committed_at: string
  model: string
}

export interface SentinelRun {
  id: number
  run_type: string
  repo_id: string | null
  status: string
  total: number
  processed: number
  failed: number
  last_seq: number
  error: string
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface SentinelRunEvent {
  id: number
  run_id: number
  seq: number
  level: string
  kind: string
  message: string
  payload: unknown
  created_at: string
}

export interface SentinelCommitDetailBundle {
  commit: SentinelCommitDetail
  judgment: SentinelJudgment | null
  findings: SentinelFinding[]
}

/** 分页结果（已解包） */
export interface SentinelPaged<T> {
  list: T[]
  total: number
  page: number
  size: number
}

/** SuccessWithPagination 的原始响应 */
interface SentinelPagedRaw<T> {
  code: number
  message: string
  data: T[]
  total: number
  page: number
  size: number
}

export interface CommitQuery {
  repo_id?: string
  status?: string
  sha?: string
  /** 只看判定命中的安全修复 */
  security_fix?: boolean
  since?: string
  until?: string
  page?: number
  size?: number
}

export interface FindingQuery {
  status?: string
  severity?: string
  repo_id?: string
  page?: number
  size?: number
}

/** 审计技能：只注入检查项与检索顺序，不改变工具权限 */
export interface SentinelSkill {
  id: string
  name: string
  version: string
  desc: string
  checks: number
  vuln_classes: string[]
}

export interface SentinelChatEvent {
  seq: number
  type: string
  payload: Record<string, unknown>
}

export interface SentinelChatReply {
  answer: string
  model: string
  skill: SentinelSkill | null
  usage: { in: number; out: number }
  events: SentinelChatEvent[]
}

export interface SentinelSkillCatalog {
  items: SentinelSkill[]
  default_id: string
}

export interface SentinelRepoPayload {
  full_name?: string
  clone_url: string
  branch?: string
  interval_minutes?: number
  enabled?: boolean
}

const unwrap = <T>(p: Promise<ApiResponse<T>>) => p.then((r) => r.data)

const paged = <T>(p: Promise<SentinelPagedRaw<T>>): Promise<SentinelPaged<T>> =>
  p.then((r) => ({ list: r.data ?? [], total: r.total, page: r.page, size: r.size }))

export const sentinelApi = {
  overview: () => unwrap(api.get<unknown, ApiResponse<SentinelOverview>>('/sentinel/overview')),

  repos: (keyword?: string) =>
    unwrap(
      api.get<unknown, ApiResponse<{ items: SentinelRepo[]; clone_hosts: string[] }>>('/sentinel/repos', {
        params: keyword ? { keyword } : undefined,
      }),
    ),
  listRepos: (keyword?: string) => sentinelApi.repos(keyword),

  createRepo: (body: SentinelRepoPayload) =>
    api.post<unknown, ApiResponse<SentinelRepo>>('/sentinel/repos', body),

  updateRepo: (
    id: string,
    body: {
      clone_url?: string
      branch?: string
      default_branch?: string
      interval_minutes?: number
      enabled?: boolean
    },
  ) => api.put<unknown, ApiResponse<null>>(`/sentinel/repos/${id}`, body),

  deleteRepo: (id: string) => api.delete<unknown, ApiResponse<null>>(`/sentinel/repos/${id}`),

  collectRepo: (id: string) => api.post<unknown, ApiResponse<null>>(`/sentinel/repos/${id}/collect`),

  commits: (params: CommitQuery = {}) =>
    paged(api.get<unknown, SentinelPagedRaw<SentinelCommit>>('/sentinel/commits', { params })),
  listCommits: (params: CommitQuery = {}) => sentinelApi.commits(params),

  commit: (id: number) =>
    unwrap(
      api.get<unknown, ApiResponse<SentinelCommitDetailBundle>>(`/sentinel/commits/${id}`),
    ),
  commitDetail: (id: number) => sentinelApi.commit(id),

  judge: (id: number) => api.post<unknown, ApiResponse<unknown>>(`/sentinel/commits/${id}/judge`),
  judgeCommit: (id: number) => sentinelApi.judge(id),

  findings: (params: FindingQuery = {}) =>
    paged(api.get<unknown, SentinelPagedRaw<SentinelFinding>>('/sentinel/findings', { params })),

  runs: (params: { run_type?: string; limit?: number } = {}) =>
    unwrap(api.get<unknown, ApiResponse<SentinelRun[]>>('/sentinel/runs', { params })),

  runEvents: (id: number, afterSeq = 0, limit = 100) =>
    unwrap(
      api.get<unknown, ApiResponse<SentinelRunEvent[]>>(`/sentinel/runs/${id}/events`, {
        params: { after_seq: afterSeq, limit },
      }),
    ),

  skills: () =>
    unwrap(api.get<unknown, ApiResponse<SentinelSkillCatalog>>('/sentinel/skills')),

  setDefaultSkill: (skillId: string) =>
    api.post<unknown, ApiResponse<{ skill: SentinelSkill | null }>>('/sentinel/skills/default', {
      skill_id: skillId,
    }),

  /** 一次模型对话：返回回答 + 与前端渲染层一致的事件序列 */
  chat: (body: { messages: { role: string; content: string }[]; skill_id?: string }) =>
    unwrap(api.post<unknown, ApiResponse<SentinelChatReply>>('/sentinel/chat', body, {
      // 模型推理可能几十秒，别被全局超时打断
      timeout: 180000,
    })),
}

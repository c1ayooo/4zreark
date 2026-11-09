import api, { ApiResponse } from '@/lib/api'
import { getErrorMessage } from '@/lib/errors'

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
  /** 命中安全修复时展开的三段式说明（旧判定为空串） */
  attack_path: string
  impact: string
  fix_evidence: string
  /** 模型摘录的 diff 关键代码行，可能为 null */
  evidence_snippets: string[] | null
  partial: boolean
  prompt_tokens: number
  completion_tokens: number
  created_at: string
}

export type SentinelFindingStatus = 'open' | 'confirmed' | 'ignored' | 'resolved'

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

/** 产物链（v0.3 §11.8）：draft → pending_review → verified / rejected → deprecated */
export type SentinelArtifactStatus = 'draft' | 'pending_review' | 'verified' | 'rejected' | 'deprecated'

export type SentinelArtifactKind = 'poc' | 'nuclei' | 'report' | 'patch' | 'repro_log'

export interface SentinelArtifact {
  id: number
  finding_id: number
  kind: SentinelArtifactKind
  title: string
  status: SentinelArtifactStatus
  path: string
  content: string
  created_at: string
  updated_at: string
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
  /** 漏洞类型多选，逗号分隔（SQLI 自动连带历史 INJECTION） */
  vuln_class?: string
  /** 严重度下限：medium/high/critical */
  min_severity?: string
  since?: string
  until?: string
  page?: number
  size?: number
}

export interface FindingQuery {
  status?: string
  severity?: string
  vuln_class?: string
  min_severity?: string
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

/** 去掉空串/undefined 的查询参数，避免后端把空串当成有效筛选 */
function compactSentinelQuery(q: FindingQuery): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(q)) {
    if (typeof v === 'string' ? v !== '' : v != null) out[k] = String(v)
  }
  return out
}

/** responseType:'blob' 时 4xx/5xx 的 JSON 错误体也是 Blob，转回文本提取 message */
async function blobErrorMessage(e: unknown, fallback: string): Promise<string> {
  const data = (e as { response?: { data?: unknown } } | null | undefined)?.response?.data
  if (typeof Blob !== 'undefined' && data instanceof Blob) {
    try {
      const body = JSON.parse(await data.text()) as { message?: string }
      if (body.message) return body.message
    } catch {
      // 非 JSON 错误体，走默认文案
    }
  }
  return getErrorMessage(e, fallback)
}

/** 与后端 DownloadArtifact 的 filename 清洗一致：仅保留可打印 ASCII，兜底 artifact-{id} */
function artifactFilename(title: string, id: number): string {
  const clean = title
    .split('')
    .filter((c) => {
      const code = c.charCodeAt(0)
      return code > 32 && code < 127 && c !== '/' && c !== '\\'
    })
    .join('')
  return `${clean || `artifact-${id}`}.txt`
}

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

  /**
   * 发现报告导出（md / pdf）：走 api 实例带 Authorization 拿 blob 再触发下载，
   * 同 downloadArtifact 套路。PDF 后端用 chrome 无头转换，耗时较长。
   */
  exportFindings: async (format: 'md' | 'pdf', query: FindingQuery = {}): Promise<void> => {
    let blob: Blob
    try {
      blob = await api.get<unknown, Blob>('/sentinel/findings/export', {
        params: { format, ...compactSentinelQuery(query) },
        responseType: 'blob',
        timeout: 180000,
      })
    } catch (e) {
      throw new Error(await blobErrorMessage(e, '导出失败'))
    }
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `sentinel-findings-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, '')}.${format}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(url)
  },

  /** 流转发现状态（open/confirmed/ignored/resolved）；open→confirmed 时后端自动固化 patch 证据产物 */
  patchFinding: (id: number, status: SentinelFindingStatus) =>
    unwrap(api.patch<unknown, ApiResponse<SentinelFinding>>(`/sentinel/findings/${id}`, { status })),

  findingArtifacts: (findingId: number) =>
    unwrap(api.get<unknown, ApiResponse<SentinelArtifact[]>>(`/sentinel/findings/${findingId}/artifacts`)),

  /** 人工新增产物（粘贴 PoC/模板/报告），后端落 draft 待审 */
  createFindingArtifact: (findingId: number, body: { kind: SentinelArtifactKind; title: string; content: string }) =>
    unwrap(api.post<unknown, ApiResponse<SentinelArtifact>>(`/sentinel/findings/${findingId}/artifacts`, body)),

  /** 模型依据修复 diff 草拟 nuclei 模板：同步调用 30-60s，落 draft，别被全局 30s 超时打断 */
  generateFindingNuclei: (findingId: number) =>
    unwrap(
      api.post<unknown, ApiResponse<SentinelArtifact>>(`/sentinel/findings/${findingId}/generate-nuclei`, null, {
        timeout: 180000,
      }),
    ),

  setArtifactStatus: (id: number, status: SentinelArtifactStatus) =>
    unwrap(api.put<unknown, ApiResponse<SentinelArtifact>>(`/sentinel/artifacts/${id}/status`, { status })),

  /** 产物下载地址（仅 verified 可下载，后端对非 verified 返回 403） */
  artifactDownloadURL: (id: number) => `/api/sentinel/artifacts/${id}/download`,

  /** 文本下载：走 api 实例带 Authorization 拿 blob 再触发浏览器下载（同 reports.download 套路），403 时抛 message */
  downloadArtifact: async (artifact: Pick<SentinelArtifact, 'id' | 'title'>): Promise<void> => {
    let blob: Blob
    try {
      blob = await api.get<unknown, Blob>(`/sentinel/artifacts/${artifact.id}/download`, {
        responseType: 'blob',
      })
    } catch (e) {
      throw new Error(await blobErrorMessage(e, '仅 verified 产物可下载'))
    }
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = artifactFilename(artifact.title, artifact.id)
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(url)
  },

  /** 发布 verified 的 nuclei 模板到 PoC 库，返回模板 id；重复发布后端 400 */
  publishArtifact: (id: number) =>
    unwrap(api.post<unknown, ApiResponse<{ template_id: number }>>(`/sentinel/artifacts/${id}/publish`)),

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

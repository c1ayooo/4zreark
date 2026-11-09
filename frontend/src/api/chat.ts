import api, { ApiResponse } from '@/lib/api'

/**
 * 对话工作台接口。
 *
 * 与 api/sentinel.ts 的分工：
 *   - sentinel.ts：提交哨兵域（仓库/提交/判定/产物）；
 *   - 本文件：对话会话、消息流、附件、技能库。
 *
 * 流式回答走原生 fetch（axios 在浏览器里读不到增量 body），
 * 其余 CRUD 复用 axios 实例以便统一处理 401 与业务错误码。
 */

export interface Conversation {
  id: string
  user_id: string
  title: string
  commit_id?: number | null
  skill_id: string
  model: string
  message_count: number
  created_at: string
  updated_at: string
}

export interface ChatAttachmentMeta {
  id?: string
  name: string
  size: number
  kind?: string
  summary?: string
  files?: { path: string; size: number; note?: string }[]
}

export interface ChatMsg {
  id: number
  role: 'user' | 'assistant'
  content: string
  attachments?: ChatAttachmentMeta[]
  events?: StreamEvent[]
  usage?: { in: number; out: number }
  model?: string
  created_at: string
}

export interface StreamEvent {
  seq: number
  type: string
  payload: Record<string, unknown>
}

export interface UploadResult {
  id: string
  name: string
  size: number
  kind: string
  summary: string
}

export interface SkillItem {
  id: string
  name: string
  version: string
  desc: string
  checks: number
  vuln_classes: string[]
  prompt?: string
  builtin: boolean
  enabled: boolean
  sort: number
}

export interface SkillInput {
  id?: string
  name: string
  version?: string
  desc?: string
  prompt: string
  checks?: number
  vuln_classes?: string[]
  enabled?: boolean
  sort?: number
}

/** 一次技能调用的记录（后端 skill_usage 表）。 */
export interface SkillUsageItem {
  id: string
  skill_id: string
  skill_name: string
  skill_version: string
  conversation_id: string
  user_id: string
  source: string
  model: string
  status: 'running' | 'finished' | 'error'
  tokens_in: number
  tokens_out: number
  duration_ms: number
  error: string
  created_at: string
}

export interface SkillUsageSummary {
  total: number
  finished: number
  failed: number
  avg_duration_ms: number
  tokens_in: number
  tokens_out: number
  by_skill: { skill_id: string; skill_name: string; calls: number; failed: number }[]
}

export interface SkillUsageResult {
  items: SkillUsageItem[]
  total: number
  page: number
  page_size: number
  summary: SkillUsageSummary
}

export interface ImportSkillResult {
  items: SkillItem[]
  failed: string[]
}

export const chatApi = {
  listConversations: () =>
    api.get<unknown, ApiResponse<{ items: Conversation[] }>>('/sentinel/conversations')
      .then((r) => r.data.items),

  createConversation: (body: { title?: string; skill_id?: string } = {}) =>
    api.post<unknown, ApiResponse<Conversation>>('/sentinel/conversations', body).then((r) => r.data),

  getConversation: (id: string) =>
    api.get<unknown, ApiResponse<{ conversation: Conversation; messages: ChatMsg[] }>>(
      `/sentinel/conversations/${id}`,
    ).then((r) => r.data),

  rename: (id: string, title: string) =>
    api.patch<unknown, ApiResponse<Conversation>>(`/sentinel/conversations/${id}`, { title })
      .then((r) => r.data),

  setSkill: (id: string, skillId: string) =>
    api.patch<unknown, ApiResponse<Conversation>>(`/sentinel/conversations/${id}`, { skill_id: skillId })
      .then((r) => r.data),

  remove: (id: string) => api.delete(`/sentinel/conversations/${id}`),

  upload: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api
      .post<unknown, ApiResponse<UploadResult>>('/sentinel/uploads', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      })
      .then((r) => r.data)
  },

  listSkillsManage: () =>
    api.get<unknown, ApiResponse<{ items: SkillItem[] }>>('/sentinel/skills/manage')
      .then((r) => r.data.items),

  saveSkill: (body: SkillInput) =>
    api.post<unknown, ApiResponse<SkillItem>>('/sentinel/skills', body).then((r) => r.data),

  deleteSkill: (id: string) => api.delete(`/sentinel/skills/${encodeURIComponent(id)}`),

  setDefaultSkill: (skillId: string) =>
    api.post('/sentinel/skills/default', { skill_id: skillId }),

  skillUsage: (
    params: { page?: number; page_size?: number; skill_id?: string; status?: string } = {},
  ) =>
    api.get<unknown, ApiResponse<SkillUsageResult>>('/sentinel/skills/usage', { params })
      .then((r) => r.data),

  importSkill: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api
      .post<unknown, ApiResponse<ImportSkillResult>>('/sentinel/skills/import', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 60000,
      })
      .then((r) => r.data)
  },
}

/**
 * 流式发送一条消息。
 *
 * 返回的 Promise 在流结束（正常或出错）后 resolve；错误通过 onEvent 的 error 事件
 * 或 reject 抛出，调用方只需关心「什么时候结束」。
 */
export async function streamMessage(
  sessionId: string,
  body: { content: string; skill_id?: string; upload_ids?: string[] },
  onEvent: (ev: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const token = localStorage.getItem('token')
  const base = import.meta.env.VITE_API_BASE_URL || '/api'

  const res = await fetch(`${base}/sentinel/conversations/${sessionId}/messages`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
    signal,
  })

  if (!res.ok) {
    let msg = `请求失败（HTTP ${res.status}）`
    try {
      const j = await res.json()
      msg = j.message || msg
    } catch {
      /* 非 JSON 响应，用状态码兜底 */
    }
    throw new Error(msg)
  }
  if (!res.body) {
    throw new Error('当前浏览器不支持流式响应')
  }

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buf = ''

  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buf += decoder.decode(value, { stream: true })

    // SSE 帧以空行分隔；一帧可能被拆到多次 read，必须缓冲到完整帧再解析。
    let idx = buf.indexOf('\n\n')
    while (idx >= 0) {
      const frame = buf.slice(0, idx)
      buf = buf.slice(idx + 2)
      idx = buf.indexOf('\n\n')

      for (const line of frame.split('\n')) {
        if (!line.startsWith('data:')) continue
        const raw = line.slice(5).trim()
        if (!raw) continue
        try {
          onEvent(JSON.parse(raw) as StreamEvent)
        } catch {
          /* 半帧或非 JSON，忽略 */
        }
      }
    }
  }
}

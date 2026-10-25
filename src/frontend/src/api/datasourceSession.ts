import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// 数据源会话托管：企业数据源的会话状态/维护 + 平台内扫码登录（无头浏览器托管）。

export interface DatasourceSessionView {
  name: string
  label: string
  auth: string // cookie / account
  available: boolean
  hint: string
  status: 'unconfigured' | 'active' | 'expired' | string
  has_cookie: boolean
  has_account: boolean
  qr_supported: boolean
  updated_at?: string
}

export const datasourceSessionStatusLabel: Record<string, string> = {
  unconfigured: '未配置',
  active: '有效',
  expired: '已失效',
}

export interface QrBeginResult {
  session_id: string
  qr_image: string // data:image/png;base64,…
  expires_at: string
  scan_hint?: string
}

export type QrPollStatus = 'waiting' | 'confirmed' | 'expired' | 'error'

export const datasourceSessionApi = {
  list: () =>
    api.get<unknown, ApiResponse<{ items: DatasourceSessionView[] }>>('/datasource-sessions'),

  save: (
    provider: string,
    body: { cookie?: string; username?: string; password?: string }
  ) => api.put<unknown, ApiResponse<null>>(`/datasource-sessions/${provider}`, body),

  remove: (provider: string) =>
    api.delete<unknown, ApiResponse<null>>(`/datasource-sessions/${provider}`),

  qrBegin: (provider: string) =>
    api.post<unknown, ApiResponse<QrBeginResult>>(`/datasource-sessions/${provider}/qr/begin`, {}),

  qrPoll: (provider: string, sessionId: string) =>
    api.get<unknown, ApiResponse<{ status: QrPollStatus; message?: string }>>(
      `/datasource-sessions/${provider}/qr/poll`,
      { params: { session_id: sessionId } }
    ),

  qrCancel: (provider: string, sessionId: string) =>
    api.post<unknown, ApiResponse<{ cancelled: boolean }>>(
      `/datasource-sessions/${provider}/qr/cancel`,
      { session_id: sessionId }
    ),
}

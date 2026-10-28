import api, { ApiResponse } from '@/lib/api'

// 平台版本与自更新
export interface VersionInfo {
  current: string
  latest?: string
  has_update: boolean
  published_at?: string
  release_url?: string
  notes?: string
  asset_size?: number
  error?: string
}

export interface UpdateState {
  stage: 'idle' | 'checking' | 'downloading' | 'verifying' | 'replacing' | 'restarting' | 'done' | 'error' | string
  percent: number
  downloaded: number
  total: number
  target_version: string
  error: string
  started_at: string
}

export const systemApi = {
  // 当前版本 + GitHub 最新版（后端缓存 10 分钟）
  version: () => api.get<unknown, ApiResponse<VersionInfo>>('/system/version'),

  // 更新进度（前端 1s 轮询渲染进度条）
  updateStatus: () => api.get<unknown, ApiResponse<UpdateState>>('/system/update/status'),

  // 启动自更新（下载 → 校验 → 替换 → 重启）
  startUpdate: (version?: string) =>
    api.post<unknown, ApiResponse<UpdateState>>('/system/update', { version }),
}

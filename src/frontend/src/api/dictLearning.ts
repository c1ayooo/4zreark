import api, { ApiResponse } from '@/lib/api'

// 字典自学习：子域首标签 / 接口路径按任务出现频次自动晋升进词表。

export type DictLearningKind = 'subdomain' | 'path'

export interface DictLearningEntry {
  id: number
  kind: DictLearningKind
  value: string
  /** 观察到该词的任务数（每任务每值 +1） */
  hits: number
  denied: boolean
  promoted_at?: string | null
  first_seen: string
  last_seen: string
  last_project_id: number
}

export interface DictLearningConfig {
  enabled: boolean
  subdomain_min_hits: number
  path_min_hits: number
}

export interface DictLearningPage {
  items: DictLearningEntry[]
  total: number
  page: number
  page_size: number
}

export const dictLearningApi = {
  list: (params: { kind?: string; page?: number; page_size?: number }) =>
    api.get<unknown, { code: number; data: DictLearningPage }>('/dict-learning', { params }),
  config: () => api.get<unknown, ApiResponse<DictLearningConfig>>('/dict-learning/config'),
  saveConfig: (cfg: DictLearningConfig) =>
    api.put<unknown, ApiResponse<null>>('/dict-learning/config', cfg),
  setDenied: (id: number, denied: boolean) =>
    api.post<unknown, ApiResponse<null>>(`/dict-learning/${id}/deny`, { denied }),
  stats: () =>
    api.get<unknown, ApiResponse<Record<string, number>>>('/dict-learning/stats'),
}

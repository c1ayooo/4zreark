import api from '@/lib/api'

interface BackendPaginatedResponse<T> {
  code: number
  message: string
  data: T[]
  total: number
  page: number
  size: number
}

export interface OperationLog {
  id: number
  user_id: string
  username: string
  action: string
  module: string
  target: string
  detail: string
  ip: string
  user_agent: string
  status: number
  created_at: string
}

export const auditApi = {
  list: (params: {
    username?: string
    action?: string
    module?: string
    status?: '0' | '1'
    page?: number
    page_size?: number
  }) => api.get<unknown, BackendPaginatedResponse<OperationLog>>('/audit', { params }),
}

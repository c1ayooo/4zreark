import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => {
    const body = response.data
    // 后端业务错误统一返回 HTTP 200 + code≠0（utils.Error），只看 HTTP 状态码
    // 会把这类错误当成功吞掉（失败弹「成功」、预览失败静默无提示）。
    // 统一在这里转 reject，让调用方的 catch / onError 真正生效。
    if (body && typeof body === 'object' && !Array.isArray(body) && 'code' in body && body.code !== 0) {
      // 1013 = 强制改密：默认口令未改，除改密闭环外全部拒绝。
      if (body.code === 1013 && !window.location.pathname.startsWith('/settings')) {
        window.location.href = '/settings?must_change_password=1'
      }
      return Promise.reject(body)
    }
    return body
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
      return Promise.reject(error.response?.data || error)
    }
    // 1013 = 强制改密：默认口令未改，除改密闭环外全部拒绝。
    // 统一重定向到设置页的改密表单，避免每个调用点各自处理。
    if (error.response?.data?.code === 1013) {
      if (!window.location.pathname.startsWith('/settings')) {
        window.location.href = '/settings?must_change_password=1'
      }
    }
    return Promise.reject(error.response?.data || error)
  }
)

export default api

// Types
export interface ApiResponse<T> {
  code: number
  message: string
  data: T
}

export interface PaginatedResponse<T> {
  code: number
  message: string
  data: {
    list: T[]
    total: number
    page: number
    pageSize: number
    /** keyset 分页：空字符串表示已经到底 */
    nextCursor?: string
    hasMore?: boolean
  }
}

export interface PaginationParams {
  page?: number
  pageSize?: number
  search?: string
  sort?: string
  order?: 'asc' | 'desc'
}

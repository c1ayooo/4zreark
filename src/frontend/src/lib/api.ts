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
    return response.data
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

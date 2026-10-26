import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

export interface RegistrationCode {
  code: string
  role: string
  max_uses: number
  used_count: number
  expires_at: string | null
  created_by: string
  created_at: string
}

export const registrationApi = {
  list: (limit = 100) =>
    api.get<unknown, ApiResponse<{ items: RegistrationCode[]; total: number }>>(
      '/registration-codes',
      { params: { limit } }
    ),

  generate: (body: {
    count: number
    role: string
    max_uses: number
    expires_at?: string | null
  }) =>
    api.post<unknown, ApiResponse<{ codes: string[]; count: number }>>(
      '/registration-codes',
      body
    ),

  remove: (code: string) =>
    api.delete<unknown, ApiResponse<null>>(
      `/registration-codes/${encodeURIComponent(code)}`
    ),

  batchDelete: (codes: string[]) =>
    api.post<unknown, ApiResponse<{ deleted: number }>>(
      '/registration-codes/batch-delete',
      { codes }
    ),
}

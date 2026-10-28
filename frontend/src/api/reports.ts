import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

export type ReportKind = 'vuln' | 'asset'

export interface ReportProfile {
  id: string
  type: ReportKind
  name: string
  description: string
  formats: string[]
  min_severity?: string
  max_rows?: number
}

export interface ReportDelivery {
  client_name?: string
  report_no?: string
  classification?: string
  tester?: string
  contact?: string
}

export interface GeneratedReport {
  id: string
  name: string
  type: 'html' | 'pdf' | 'markdown' | 'docx' | 'xlsx' | string
  report_kind: ReportKind
  template: string
  file_path: string
  summary: {
    total_assets?: number
    total_vulns: number
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
    info_count: number
  }
}

export const reportApi = {
  // 内置模板目录；按 kind 过滤只取一类（vuln / asset）。
  templates: async (kind?: ReportKind): Promise<ReportProfile[]> => {
    const raw = (await api.get('/reports/templates', {
      params: kind ? { kind } : undefined,
    })) as unknown as ApiResponse<{ items: ReportProfile[] }>
    return raw.data?.items ?? []
  },

  generate: async (input: {
    workspace_id?: string
    project_id?: number
    name?: string
    title?: string
    format?: 'html' | 'pdf' | 'markdown' | 'docx' | 'xlsx'
    kind?: ReportKind
    template?: string
    delivery?: ReportDelivery
  }): Promise<GeneratedReport> => {
    const raw = (await api.post('/reports/generate', input, {
      timeout: 180000,
    })) as unknown as ApiResponse<GeneratedReport>
    return raw.data
  },

  // 下载走 axios 拿 blob，避免浏览器直接打开 JSON 错误页。
  download: async (report: GeneratedReport): Promise<void> => {
    const res = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
    const ext =
      report.type === 'pdf'
        ? '.pdf'
        : report.type === 'markdown'
          ? '.md'
          : report.type === 'docx'
            ? '.docx'
            : report.type === 'xlsx'
              ? '.xlsx'
              : '.html'
    const url = window.URL.createObjectURL(new Blob([res.data]))
    const a = document.createElement('a')
    a.href = url
    a.download = (report.name || 'report') + ext
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.URL.revokeObjectURL(url)
  },
}

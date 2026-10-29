import api, { ApiResponse } from '@/lib/api'

// 任务日志（统一动作日志）：task_logs + ICP 查询 + 企业采集 跨源聚合
export interface ActionLogRow {
  created_at: string
  category: string
  title: string
  level: string
  status: string
  detail: string
  ref: string
}

export const taskLogApi = {
  list: (params: {
    project_id?: number
    category?: string
    level?: string
    q?: string
    page?: number
    page_size?: number
  }) => api.get<unknown, { total: number }>('/task-logs', { params }),

  settings: () =>
    api.get<unknown, ApiResponse<{ retention_days: number }>>('/task-logs/settings'),

  saveSettings: (retention_days: number) =>
    api.put<unknown, ApiResponse<{ retention_days: number; purged: number }>>(
      '/task-logs/settings',
      { retention_days }
    ),

  purge: () =>
    api.post<unknown, ApiResponse<{ purged: number }>>('/task-logs/purge'),
}

// 功能分类（后端 category 枚举）
export const taskLogCategories: { value: string; label: string }[] = [
  { value: 'subdomain', label: '子域名收集' },
  { value: 'port_scan', label: '端口扫描' },
  { value: 'fingerprint', label: '指纹识别' },
  { value: 'crawler', label: 'Web 爬虫' },
  { value: 'dir_scan', label: '目录扫描' },
  { value: 'sensitive', label: '敏感信息' },
  { value: 'vuln_scan', label: '漏洞扫描' },
  { value: 'takeover', label: '子域名接管' },
  { value: 'service_identify', label: '服务识别' },
  { value: 'exposure_scan', label: '暴露面探测' },
  { value: 'clue_hunt', label: '存量线索' },
  { value: 'icp', label: 'ICP 查询' },
  { value: 'enterprise', label: '企业采集' },
  { value: 'custom', label: '组合扫描' },
  { value: 'task', label: '扫描任务' },
  { value: 'system', label: '系统' },
]

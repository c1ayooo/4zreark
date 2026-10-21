import api, { ApiResponse } from '@/lib/api'

// 外部平台 / MCP 访问凭证。完整 key 只在创建响应里出现一次。
export interface APIKey {
  id: number
  name: string
  key_prefix: string
  project_id: number | null
  project_code: string
  project_name: string
  scopes: string[]
  enabled: boolean
  expires_at: string | null
  last_used_at: string | null
  request_count: number
  created_by: string
  created_at: string
}

export interface CreatedAPIKey extends APIKey {
  key: string
}

// 与后端 service.ScopeCatalog 保持一致；新增权限点时两边一起改。
export interface MCPScopeInfo {
  name: string
  label: string
  group: string
  description: string
  dangerous: boolean
}

export const MCP_SCOPES: MCPScopeInfo[] = [
  { name: 'assets:read', label: '读资产', group: '资产', description: '查询项目、资产列表、资产详情、站点路由与变更事件', dangerous: false },
  { name: 'assets:write', label: '改资产', group: '资产', description: '导入资产、人工验证、探测、保护与失联归档', dangerous: true },
  { name: 'projects:read', label: '读项目', group: '项目', description: '读取项目采集状态等扩展信息', dangerous: false },
  { name: 'projects:write', label: '改项目', group: '项目', description: '新建/编辑/暂停/恢复/删除项目', dangerous: true },
  { name: 'governance:read', label: '读治理', group: '治理', description: '查看种子、计划、批次与执行单元', dangerous: false },
  { name: 'governance:write', label: '改治理', group: '治理', description: '维护种子/计划、触发批次、重建关系与回放结果', dangerous: true },
  { name: 'tasks:read', label: '读任务', group: '任务', description: '查看任务、日志、结果与统计', dangerous: false },
  { name: 'tasks:write', label: '改任务', group: '任务', description: '创建/编辑/删除/启停/重试/续扫任务', dangerous: true },
  { name: 'scans:run', label: '执行扫描', group: '扫描', description: '直接执行端口、子域名、指纹、漏洞、目录、爬虫、弱口令、接管与 nuclei 扫描', dangerous: true },
  { name: 'vulns:read', label: '读漏洞', group: '漏洞', description: '查看漏洞列表、详情与统计（仅全项目 key）', dangerous: false },
  { name: 'vulns:write', label: '改漏洞', group: '漏洞', description: '创建/编辑/删除漏洞、改状态与复核（仅全项目 key）', dangerous: true },
  { name: 'pocs:read', label: '读 POC', group: 'POC', description: '查看 POC 模板与统计（仅全项目 key）', dangerous: false },
  { name: 'pocs:write', label: '改 POC', group: 'POC', description: '创建/编辑/删除/启停 POC（仅全项目 key）', dangerous: true },
]

export const MCP_SCOPE_GROUPS = Array.from(new Set(MCP_SCOPES.map((s) => s.group)))

export const scopeLabel = (name: string) =>
  MCP_SCOPES.find((s) => s.name === name)?.label ?? name

export const scopeGroup = (name: string) =>
  MCP_SCOPES.find((s) => s.name === name)?.group ?? name

export interface CreateAPIKeyInput {
  name: string
  // 0 / 不传 = 所有项目
  project_id?: number | null
  // 不传 = assets:read
  scopes?: string[]
  // RFC3339；不传 = 永不过期
  expires_at?: string | null
}

export const apiKeyApi = {
  list: () =>
    api.get<unknown, ApiResponse<{ items: APIKey[]; total: number }>>('/api-keys'),
  create: (body: CreateAPIKeyInput) =>
    api.post<unknown, ApiResponse<CreatedAPIKey>>('/api-keys', body),
  setEnabled: (id: number, enabled: boolean) =>
    api.put<unknown, ApiResponse<{ id: number; enabled: boolean }>>(`/api-keys/${id}`, { enabled }),
  remove: (id: number) =>
    api.delete<unknown, ApiResponse<{ id: number }>>(`/api-keys/${id}`),
}

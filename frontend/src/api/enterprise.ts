import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// v4 功能域 15：企业身份线索（企业名 / 备案 / 与 APP 名单归属对齐）。

export interface EnterpriseDomain {
  domain: string
  site?: string
  icp?: string
  evidence?: string
}

export interface EnterpriseEntity {
  id: number
  project_id: number
  name: string
  credit_code: string
  legal_person: string
  open_status: string
  industry: string
  address: string
  registered_capital: string
  registered_capital_wan: number
  icp_numbers: string[]
  domains: EnterpriseDomain[]
  source: string
  status: 'unverified' | 'verified' | 'ignored' | string
  notes: string
  digital_count: number
  created_at: string
  updated_at: string
  // 深度采集（BFS）落库的层级信息；手工行 entity_type=root、depth=0、parent 为空
  job_id?: string
  ext_id: string
  entity_type: 'root' | 'branch' | 'invest' | 'group' | string
  parent_ext_id: string
  depth: number
}

export const entityTypeLabel: Record<string, string> = {
  root: '根企业',
  branch: '分支机构',
  invest: '对外投资',
  group: '集团成员',
}

export interface EnterpriseListResponse {
  code: number
  message: string
  data: EnterpriseEntity[]
  total: number
  page: number
  size: number
}

export interface EnterpriseInput {
  name: string
  credit_code?: string
  legal_person?: string
  open_status?: string
  industry?: string
  address?: string
  icp_numbers?: string[]
  domains?: EnterpriseDomain[]
  source?: string
  status?: string
  notes?: string
}

export interface EnterpriseProvider {
  Name: string
  Label: string
  Auth: string
  Available: boolean
  Hint: string
}

export interface EnterpriseCollectResult {
  provider: string
  keyword: string
  found: number
  entities: EnterpriseEntity[]
  domains: EnterpriseDomain[]
  warnings?: string[]
}

export interface AlignedDigitalAsset {
  id: number
  kind: string
  name: string
  company: string
  platform: string
  source: string
  status: string
}

export interface CompanyRef {
  ext_id: string
  name: string
}

export interface EnterpriseJob {
  id: string
  project_id: string
  owner: string
  provider: string
  keyword: string
  status: 'running' | 'done' | 'error' | 'canceled' | string
  depth: number
  max_nodes: number
  nodes: number
  entities: number
  domains: number
  digital: number
  imported: number
  error: string
  created_at: string
  finished_at: string | null
}

export interface EnterpriseCandidate {
  id: string
  job_id: string
  project_id: string
  kind: string
  value: string
  entity_name: string
  evidence: string
  status: string
  created_at: string
}

/** 深度采集硬上限：所有任务的层级/节点都在此范围内钳制，保存后即时生效 */
export interface EnterpriseCollectorSettings {
  max_depth: number
  max_nodes: number
}

export const enterpriseStatusLabel: Record<string, string> = {
  unverified: '待核对',
  verified: '已核对',
  ignored: '已忽略',
}

export const enterpriseApi = {
  list: (params: {
    project_id?: number
    q?: string
    status?: string
    page?: number
    page_size?: number
  }) => api.get<unknown, EnterpriseListResponse>('/enterprise-entities', { params }),

  upsert: (body: EnterpriseInput & { project_id: number }) =>
    api.post<unknown, ApiResponse<EnterpriseEntity>>('/enterprise-entities', body),

  remove: (id: number) =>
    api.delete<unknown, ApiResponse<null>>(`/enterprise-entities/${id}`),

  importRows: (projectId: number, items: EnterpriseInput[], source = 'import') =>
    api.post<unknown, ApiResponse<{ inserted: number; updated: number; total: number }>>(
      '/enterprise-entities/import',
      { project_id: projectId, source, items }
    ),

  alignedAssets: (id: number) =>
    api.get<unknown, ApiResponse<{ entity: EnterpriseEntity; items: AlignedDigitalAsset[]; total: number }>>(
      `/enterprise-entities/${id}/assets`
    ),

  providers: () =>
    api.get<unknown, ApiResponse<{ items: EnterpriseProvider[] }>>(
      '/enterprise-entities/providers'
    ),

  collect: (body: {
    project_id: number
    provider: string
    keyword: string
    limit?: number
    cookie?: string
    username?: string
    password?: string
    proxy_url?: string
  }) =>
    api.post<unknown, ApiResponse<EnterpriseCollectResult>>('/enterprise-entities/collect', body),

  searchProvider: (body: {
    project_id: number
    provider: string
    keyword: string
    limit?: number
    cookie?: string
    username?: string
    password?: string
    proxy_url?: string
  }) =>
    api.post<unknown, ApiResponse<{ items: CompanyRef[]; total: number }>>(
      '/enterprise-entities/search',
      body
    ),

  discover: (body: {
    project_id: number
    provider: string
    ext_id: string
    name: string
    depth?: number
    max_nodes?: number
    cookie?: string
    username?: string
    password?: string
    proxy_url?: string
    collect_digital?: boolean
    collect_group?: boolean
  }) =>
    api.post<unknown, ApiResponse<EnterpriseJob>>('/enterprise-entities/discover', body),

  jobs: (projectId?: number, limit = 50) =>
    api.get<unknown, ApiResponse<{ items: EnterpriseJob[]; total: number }>>(
      '/enterprise-entities/jobs',
      { params: { project_id: projectId || undefined, limit } }
    ),

  job: (id: string) =>
    api.get<unknown, ApiResponse<EnterpriseJob>>(
      `/enterprise-entities/jobs/${encodeURIComponent(id)}`
    ),

  cancelJob: (id: string) =>
    api.post<unknown, ApiResponse<{ id: string }>>(
      `/enterprise-entities/jobs/${encodeURIComponent(id)}/cancel`
    ),

  candidates: (projectId?: number, status = '', limit = 200) =>
    api.get<unknown, ApiResponse<{ items: EnterpriseCandidate[]; total: number }>>(
      '/enterprise-entities/candidates',
      { params: { project_id: projectId || undefined, status: status || undefined, limit } }
    ),

  /** 深度采集硬上限（层级/节点）；深度采集弹窗的表单上限与配置入口共用 */
  settings: () =>
    api.get<unknown, ApiResponse<EnterpriseCollectorSettings>>('/enterprise-entities/settings'),

  /** 保存硬上限：热更新，保存即对后续采集任务生效，无需重启 */
  saveSettings: (body: { max_depth?: number; max_nodes?: number }) =>
    api.put<unknown, ApiResponse<EnterpriseCollectorSettings>>(
      '/enterprise-entities/settings',
      body
    ),

  // 候选域名批量转 domain 种子（集团成员/无备案域名的人工确认通道）
  confirmCandidates: (projectId: number, ids: string[]) =>
    api.post<unknown, ApiResponse<{ seeded: number; confirmed: number }>>(
      '/enterprise-entities/candidates/confirm',
      { project_id: projectId, ids: ids.map(Number) }
    ),

  rejectCandidates: (ids: string[]) =>
    api.post<unknown, ApiResponse<{ rejected: number }>>(
      '/enterprise-entities/candidates/reject',
      { ids: ids.map(Number) }
    ),
}

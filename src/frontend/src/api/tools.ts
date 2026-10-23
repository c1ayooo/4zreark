import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

export interface CloudVerifyResult {
  valid: boolean
  status: string
  account_id?: string
  arn?: string
  code?: string
  message?: string
}

export interface DBVerifyResult {
  alive: boolean
  authed: boolean
  user?: string
  version?: string
  database?: string
  detail?: string
}

export interface SSHVerifyResult {
  alive: boolean
  authed: boolean
  user?: string
  groups?: string
  sudo_nopw?: boolean
  banner?: string
  detail?: string
}

export interface WebReconResult {
  recon: {
    Host: string
    Bundles: string[]
    EndpointGroups: string[]
    Endpoints: string[]
    Routes: string[]
    Leaks: { Key: string; Val: string; Src: string }[]
  }
  unauth_hits?: { Path: string; Status: number; Length: number; Note?: string }[]
}

export interface GithubDork {
  id: string
  category: string
  title: string
  query: string
  note?: string
}

export interface GithubLeakCandidate {
  RuleName: string
  Keyword: string
  Repository: string
  Path: string
  SecretType: string
  Confidence: string
  Severity: string
  MaskedExcerpt: string
  HTMLURL: string
}

export interface GithubLeakResult {
  query: string
  items: number
  candidates: GithubLeakCandidate[]
  truncated: boolean
  errors?: string[]
}

export interface EnterpriseProvider {
  Name: string
  Label: string
  Auth: string
  Available: boolean
  Hint: string
}

export interface EnterpriseRef {
  ExtID: string
  Name: string
  [key: string]: unknown
}

export interface EnterpriseSearchResult {
  provider: string
  items: EnterpriseRef[]
  detail?: Record<string, unknown>
}

export interface NucleiRuntimeStatus {
  Root: string
  BinaryPath: string
  BinaryExists: boolean
  BinaryVersion?: string
  TemplatesDir: string
  TemplatesExists: boolean
  TemplateCount: number
  CustomTemplatesExists: boolean
  CustomTemplateCount: number
  AutoUpdate: boolean
  UpdateIntervalHours: number
  VersionSetting: string
  LastUpdate?: string
  Warnings?: string[]
}

export interface VerifyStats {
  window_days: number
  finished: number
  hits: number
  misses: number
  failures: number
  skipped: number
  by_status: Record<string, number>
}

export interface PlaybookInfo {
  id: string
  name?: string
  vars_required?: string[]
  steps: number
  note?: string
}

export interface ComponentCVE {
  product: string
  cve: string
  evidence: string
}

export const toolsApi = {
  oobDomain: async (base = ''): Promise<string> => {
    const raw = (await api.post('/tools/oob/domain', { base })) as unknown as ApiResponse<{ domain: string }>
    return raw.data.domain
  },
  oobRecords: async (domain: string, base = '', waitSeconds = 0): Promise<string[]> => {
    const raw = (await api.post('/tools/oob/records', { base, domain, wait_seconds: waitSeconds })) as unknown as ApiResponse<{ records: string[] }>
    return raw.data.records || []
  },
  verifyCloud: async (input: { provider: string; access_key_id: string; secret_key: string }): Promise<CloudVerifyResult> => {
    const raw = (await api.post('/tools/creds/cloud', input)) as unknown as ApiResponse<CloudVerifyResult>
    return raw.data
  },
  verifyDB: async (input: Record<string, unknown>): Promise<DBVerifyResult> => {
    const raw = (await api.post('/tools/creds/db', input)) as unknown as ApiResponse<DBVerifyResult>
    return raw.data
  },
  verifySSH: async (input: Record<string, unknown>): Promise<SSHVerifyResult> => {
    const raw = (await api.post('/tools/creds/ssh', input)) as unknown as ApiResponse<SSHVerifyResult>
    return raw.data
  },
  diffprobe: async (input: Record<string, unknown>): Promise<unknown> => {
    const raw = (await api.post('/tools/diffprobe', input, { timeout: 120000 })) as unknown as ApiResponse<unknown>
    return raw.data
  },
  webrecon: async (input: { project_id: number; base_url: string; unauth_sweep?: boolean; bypass?: boolean }): Promise<WebReconResult> => {
    const raw = (await api.post('/tools/webrecon', input, { timeout: 180000 })) as unknown as ApiResponse<WebReconResult>
    return raw.data
  },
  quoteCheck: async (quote: string, text: string): Promise<boolean> => {
    const raw = (await api.post('/tools/quote-check', { quote, text })) as unknown as ApiResponse<{ found: boolean }>
    return raw.data.found
  },
  playbooks: async (): Promise<{ items: PlaybookInfo[]; errors: string[] }> => {
    const raw = (await api.get('/tools/playbooks')) as unknown as ApiResponse<{ items: PlaybookInfo[]; errors: string[] }>
    return raw.data
  },
  runPlaybook: async (input: { project_id: number; playbook: string; base_url: string; vars?: Record<string, string> }): Promise<unknown> => {
    const raw = (await api.post('/tools/playbooks/run', input, { timeout: 120000 })) as unknown as ApiResponse<unknown>
    return raw.data
  },
  githubDorks: async (): Promise<GithubDork[]> => {
    const raw = (await api.get('/tools/github-leak/dorks')) as unknown as ApiResponse<GithubDork[]>
    return raw.data || []
  },
  githubLeakScan: async (input: { query?: string; dork_id?: string; org?: string; domain?: string; max_results?: number }): Promise<GithubLeakResult> => {
    const raw = (await api.post('/tools/github-leak/scan', input, { timeout: 180000 })) as unknown as ApiResponse<GithubLeakResult>
    return raw.data
  },
  enterpriseProviders: async (): Promise<EnterpriseProvider[]> => {
    const raw = (await api.get('/tools/enterprise/providers')) as unknown as ApiResponse<EnterpriseProvider[]>
    return raw.data || []
  },
  enterpriseSearch: async (input: { provider: string; config: Record<string, string>; keyword: string; limit?: number; detail?: boolean }): Promise<EnterpriseSearchResult> => {
    const raw = (await api.post('/tools/enterprise/search', input, { timeout: 120000 })) as unknown as ApiResponse<EnterpriseSearchResult>
    return raw.data
  },
  extract: async (input: { template_id: string; target?: string; match_url?: string; request?: string; response?: string }): Promise<unknown> => {
    const raw = (await api.post('/tools/extract', input)) as unknown as ApiResponse<unknown>
    return raw.data
  },
  nucleiRuntimeStatus: async (): Promise<NucleiRuntimeStatus> => {
    const raw = (await api.get('/nuclei/runtime/status')) as unknown as ApiResponse<NucleiRuntimeStatus>
    return raw.data
  },
  nucleiRuntimeEnsure: async (auto: boolean): Promise<unknown> => {
    const raw = (await api.post(`/nuclei/runtime/ensure?auto=${auto ? '1' : '0'}`)) as unknown as ApiResponse<unknown>
    return raw.data
  },
  nucleiRuntimeUpdate: async (input: { force?: boolean; binary_only?: boolean; templates_only?: boolean }): Promise<unknown> => {
    const raw = (await api.post('/nuclei/runtime/update', input, { timeout: 600000 })) as unknown as ApiResponse<unknown>
    return raw.data
  },
  verifyStats: async (days = 30): Promise<VerifyStats> => {
    const raw = (await api.get('/vuln-verify/stats', { params: { days } })) as unknown as ApiResponse<VerifyStats>
    return raw.data
  },
  componentCVEs: async (product: string): Promise<ComponentCVE[]> => {
    const raw = (await api.get('/components/cves', { params: { product } })) as unknown as ApiResponse<{ items: ComponentCVE[] }>
    return raw.data.items || []
  },
}

// ---------------------------------------------------------------------------
// 扫描工具运行时（gogo/spray/katana/rem 的版本与更新管理）
// ---------------------------------------------------------------------------

export interface ToolRuntimeStatus {
  name: string
  repo: string
  description: string
  pinned_version: string
  installed_version: string
  latest_version: string
  auto_update: boolean
  check_interval_hours: number
  status: 'ok' | 'stale' | 'missing' | 'needs_review'
  status_note: string
  path: string
  managed: boolean
  disk_version: string
  update_available: boolean
}

export interface ToolsRuntimeOverview {
  tools: ToolRuntimeStatus[]
  nuclei?: NucleiRuntimeStatus | null
}

export interface EngineUsageStatus {
  available: boolean
  limits?: Record<string, number>
  today?: Record<string, number>
  history?: { day: string; engine: string; queries: number }[]
}

export const toolRuntimeApi = {
  async list(): Promise<ToolsRuntimeOverview> {
    const raw = (await api.get('/tools')) as unknown as ApiResponse<ToolsRuntimeOverview>
    return raw.data
  },
  async check(name: string): Promise<ToolRuntimeStatus> {
    const raw = (await api.post(`/tools/${name}/check`, {}, { timeout: 60000 })) as unknown as ApiResponse<ToolRuntimeStatus>
    return raw.data
  },
  async update(name: string, force = false): Promise<ToolRuntimeStatus> {
    const raw = (await api.post(`/tools/${name}/update`, { force }, { timeout: 600000 })) as unknown as ApiResponse<ToolRuntimeStatus>
    return raw.data
  },
  async rollback(name: string): Promise<ToolRuntimeStatus> {
    const raw = (await api.post(`/tools/${name}/rollback`, {}, { timeout: 60000 })) as unknown as ApiResponse<ToolRuntimeStatus>
    return raw.data
  },
  async setSettings(name: string, body: { pinned_version?: string; auto_update?: boolean; check_interval_hours?: number }): Promise<ToolRuntimeStatus> {
    const raw = (await api.put(`/tools/${name}/settings`, body)) as unknown as ApiResponse<ToolRuntimeStatus>
    return raw.data
  },
  async history(name: string): Promise<unknown[]> {
    const raw = (await api.get(`/tools/${name}/history`)) as unknown as ApiResponse<unknown[]>
    return raw.data ?? []
  },
  async engineUsage(): Promise<EngineUsageStatus> {
    const raw = (await api.get('/governance/engine-usage')) as unknown as ApiResponse<EngineUsageStatus>
    return raw.data
  },
  async setEngineLimits(limits: Record<string, number>): Promise<EngineUsageStatus> {
    const raw = (await api.put('/governance/engine-usage/limits', limits)) as unknown as ApiResponse<EngineUsageStatus>
    return raw.data
  },
}

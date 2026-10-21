import api, { ApiResponse, PaginationParams, PaginatedResponse } from '@/lib/api'

// Backend paginated response format
interface BackendPaginatedResponse<T> {
  code: number
  message: string
  data: T[]
  total: number
  page: number
  size: number
}

// Transform backend node to frontend format
const transformNode = (n: Record<string, unknown>): ScannerNode => {
  const systemInfo = (n.system_info as Record<string, unknown>) || {}
  return {
    id: n.id as string,
    nodeId: (n.node_id as string) || '',
    name: n.name as string,
    hostname: (n.name as string) || '',
    description: (n.description as string) || '',
    ipAddress: (n.ip as string) || '',
    port: (n.port as number) || 0,
    status: n.status as ScannerNode['status'],
    type: (n.type as ScannerNode['type']) || 'worker',
    capabilities: (n.capabilities as string[]) || [],
    tags: (n.tags as string[]) || [],
    maxConcurrency: (n.max_tasks as number) || 0,
    currentTasks: (n.current_tasks as number) || 0,
    cpuUsage: Number(systemInfo.cpu_usage) || 0,
    memoryUsage: Number(systemInfo.memory_usage) || 0,
    version: (n.version as string) || 'dev',
    lastHeartbeat: (n.last_heartbeat as string) || '',
    registeredAt: (n.created_at as string) || '',
  }
}

// Transform backend plugin to frontend format
const transformPlugin = (p: Record<string, unknown>): Plugin => ({
  id: p.id as string,
  name: p.name as string,
  type: p.type as string,
  version: p.version as string,
  description: p.description as string,
  author: p.author as string,
  enabled: p.enabled as boolean,
  config: p.config as Record<string, unknown>,
  capabilities: (p.capabilities as string[]) || [],
  createdAt: p.created_at as string,
  updatedAt: p.updated_at as string,
})

export interface ScannerNode {
  id: string
  nodeId: string
  name: string
  hostname: string
  description: string
  ipAddress: string
  port: number
  status: 'online' | 'offline' | 'busy' | 'disabled' | 'error'
  type: 'master' | 'worker' | 'general' | 'special' | 'internal' | 'local'
  capabilities: string[]
  tags: string[]
  maxConcurrency: number
  currentTasks: number
  cpuUsage: number
  memoryUsage: number
  version: string
  lastHeartbeat: string
  registeredAt: string
}

export interface NodeUpdateInput {
  name?: string
  description?: string
  max_tasks?: number
  tags?: string[]
  status?: ScannerNode['status']
}

export interface EnrollNodeInput {
  name: string
  description?: string
  max_tasks: number
  capabilities?: string[]
  tags?: string[]
}

export interface EnrollNodeResult {
  node_id: string
  id: string
  token: string
}

export interface DeployNodeInput {
  host: string
  port: number
  os: 'linux' | 'windows'
  username: string
  password?: string
  private_key?: string
  key_passphrase?: string
  name: string
  max_tasks: number
  capabilities: string[]
  tags: string[]
  platform_url: string
  proxy?: string
  dir: string
  gost_reverse?: boolean
  gost_relay_port?: number
  gost_tunnel_port?: number
  gost_user?: string
  gost_pass?: string
  platform_port?: number
}

export interface DeployNodeResult {
  node_id: string
  name: string
  host: string
  os: string
  install_dir: string
  output: string
}

export interface DefaultNodeResult {
  node_id: string
  node: ScannerNode | null
}

export interface Plugin {
  id: string
  name: string
  type: string
  version: string
  description?: string
  author?: string
  enabled: boolean
  config?: Record<string, unknown>
  capabilities: string[]
  createdAt: string
  updatedAt: string
}

export interface NodeStats {
  total: number
  online: number
  offline: number
  busy: number
  disabled: number
  averageCpu: number
  averageMemory: number
}

export const nodeApi = {
  // Nodes
  getNodes: async (params?: PaginationParams & {
    status?: string
    type?: string
  }): Promise<PaginatedResponse<ScannerNode>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      status: params?.status,
      type: params?.type,
    }
    const response: BackendPaginatedResponse<Record<string, unknown>> = await api.get('/nodes', { params: backendParams })
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformNode),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      }
    }
  },

  getNode: async (id: string): Promise<ApiResponse<ScannerNode>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(`/nodes/${id}`)
    return {
      code: response.code,
      message: response.message,
      data: transformNode(response.data),
    }
  },

  updateNode: (id: string, data: NodeUpdateInput): Promise<ApiResponse<ScannerNode>> =>
    api.put(`/nodes/${id}`, data),

  enrollNode: (data: EnrollNodeInput): Promise<ApiResponse<EnrollNodeResult>> =>
    api.post('/nodes/enroll', data),

  deployNode: (data: DeployNodeInput): Promise<ApiResponse<DeployNodeResult>> =>
    api.post('/nodes/deploy', data, { timeout: 180000 }),

  rotateNodeToken: (id: string): Promise<ApiResponse<{ token: string }>> =>
    api.post(`/nodes/${id}/token`),

  revokeNodeToken: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/nodes/${id}/token`),

  deleteNode: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/nodes/${id}`),

  getNodeStats: async (): Promise<ApiResponse<NodeStats>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get('/nodes/stats')
    const d = response.data || {}
    return {
      ...response,
      data: {
        total: Number(d.total) || 0,
        online: Number(d.online) || 0,
        offline: Number(d.offline) || 0,
        busy: Number(d.busy) || 0,
        disabled: Number(d.disabled) || 0,
        averageCpu: Number(d.average_cpu) || 0,
        averageMemory: Number(d.average_memory) || 0,
      },
    }
  },

  // 默认扫描节点：任务没显式指定节点时走它
  getDefaultNode: async (): Promise<ApiResponse<DefaultNodeResult>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get('/nodes/default')
    const d = response.data || {}
    return {
      ...response,
      data: {
        node_id: (d.node_id as string) || '',
        node: d.node ? transformNode(d.node as Record<string, unknown>) : null,
      },
    }
  },

  setDefaultNode: (nodeId: string): Promise<ApiResponse<{ node_id: string }>> =>
    api.put('/nodes/default', { node_id: nodeId }),

  // Plugins
  getPlugins: async (params?: PaginationParams & {
    type?: string
    enabled?: boolean
  }): Promise<PaginatedResponse<Plugin>> => {
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      type: params?.type,
      enabled: params?.enabled,
    }
    const response: BackendPaginatedResponse<Record<string, unknown>> = await api.get('/plugins', { params: backendParams })
    return {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map(transformPlugin),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      }
    }
  },

  getPlugin: async (id: string): Promise<ApiResponse<Plugin>> => {
    const response: ApiResponse<Record<string, unknown>> = await api.get(`/plugins/${id}`)
    return {
      code: response.code,
      message: response.message,
      data: transformPlugin(response.data),
    }
  },

  createPlugin: (data: Partial<Plugin>): Promise<ApiResponse<Plugin>> =>
    api.post('/plugins', data),

  updatePlugin: (id: string, data: Partial<Plugin>): Promise<ApiResponse<Plugin>> =>
    api.put(`/plugins/${id}`, data),

  deletePlugin: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/plugins/${id}`),

  togglePlugin: (id: string, enabled: boolean): Promise<ApiResponse<Plugin>> =>
    api.put(`/plugins/${id}/toggle`, { enabled }),

  uploadPlugin: (file: File): Promise<ApiResponse<Plugin>> => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/plugins/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  },
}

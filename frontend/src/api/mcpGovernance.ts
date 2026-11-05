import api, { ApiResponse } from '@/lib/api'

// MCP 治理面 - 对齐 service.MCPToolState（api/mcp_governance_handler.go）
export interface MCPGovernanceTool {
  name: string
  title?: string
  description: string
  scopes: string[]
  any_scopes?: string[]
  write: boolean
  enabled: boolean
}

export interface MCPGovernanceOverview {
  tools: MCPGovernanceTool[]
  rate_limit_per_min: number
}

export const mcpGovernanceApi = {
  // 全部工具元数据 + 总闸状态 + 当前配额
  overview: (): Promise<ApiResponse<MCPGovernanceOverview>> => api.get('/mcp-governance'),

  // 启停单个工具
  setToolEnabled: (
    name: string,
    enabled: boolean,
  ): Promise<ApiResponse<{ tool: string; enabled: boolean }>> =>
    api.put(`/mcp-governance/tools/${encodeURIComponent(name)}`, { enabled }),

  // 调整速率配额（次/分钟，后端校验 1-600），立即生效
  updateRateLimit: (perMinute: number): Promise<ApiResponse<{ rate_limit_per_min: number }>> =>
    api.put('/mcp-governance/rate-limit', { per_minute: perMinute }),
}

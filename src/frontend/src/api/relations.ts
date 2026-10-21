import api from '@/lib/api'
import type { ApiResponse } from '@/lib/api'

// G5：变更事件时间线（/api/events）与关系图谱（/api/relations）。

export type AssetEventType = 'first_seen' | 'attribute_change' | 'reappear' | 'archived'

export interface AssetEvent {
  id: number
  project_id: number
  site_id: number
  record_id: number | null
  event_type: AssetEventType | string
  title: string
  before: Record<string, unknown>
  after: Record<string, unknown>
  created_at: string
}

export const relationTypeLabel: Record<string, string> = {
  domain_parent: '父子域',
  same_ip: '同 IP',
  same_cert: '同证书',
  same_icon: '同图标',
  same_fp: '同技术栈',
  same_c_segment: '同 C 段',
  redirect: '跳转关系',
  cname: 'CNAME',
}

export const eventTypeLabel: Record<string, string> = {
  first_seen: '首次发现',
  attribute_change: '属性变化',
  reappear: '重新出现',
  takeover: '接管风险',
  archived: '已归档',
}

export const eventTypeVariant = (
  type: string
): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (type === 'first_seen') return 'default'
  if (type === 'reappear') return 'default'
  if (type === 'archived') return 'outline'
  return 'secondary'
}

export const assetEventApi = {
  list: (limit = 50) =>
    api.get<unknown, ApiResponse<{ items: AssetEvent[]; limit: number }>>('/events', {
      params: { limit },
    }),
}

export interface RelationNode {
  id: number
  project_id: number
  host: string
  value: string
  title: string
  ip: string
}

export interface RelationEdge {
  id: number
  type: string
  key: string
  confidence: number
  left: RelationNode
  right: RelationNode
}

export interface RelationGraphData {
  nodes: RelationNode[]
  edges: RelationEdge[]
  total_edges: number
  truncated: boolean
}

export interface RelationIndexStatus {
  by_type: Record<string, number>
  edges: number
  evidence: number
  sites: number
}

export const relationApi = {
  /** 图谱。type 可选：domain_parent / same_ip / same_cert / same_icon / same_fp / same_c_segment / redirect 之一 */
  list: (params: { project_id?: number; type?: string; limit?: number } = {}) =>
    api.get<unknown, ApiResponse<RelationGraphData>>('/relations', { params }),

  indexStatus: (projectId?: number) =>
    api.get<unknown, ApiResponse<RelationIndexStatus>>('/relations/index-status', {
      params: { project_id: projectId || undefined },
    }),

  rebuild: (projectId?: number) =>
    api.post<unknown, ApiResponse<{ by_type: Record<string, number> }>>(
      '/governance/relations/rebuild',
      {},
      { params: { project_id: projectId || undefined } }
    ),
}

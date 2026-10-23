import api, { ApiResponse } from '@/lib/api'

/** 种子收集队列作业：单 worker 串行执行，状态机 queued→running→done/error */
export type SeedCollectionJobStatus = 'queued' | 'running' | 'done' | 'error'

export interface SeedCollectionJob {
  id: string
  project_id: number
  seed_id: number
  kind: string
  value: string
  status: SeedCollectionJobStatus
  /** 完成时新增的候选数 */
  found: number
  error: string
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface SeedCollectResult {
  enqueued: number
  /** 未能入队的种子值 */
  skipped: string[]
}

export interface SeedCollectionJobsResult {
  items: SeedCollectionJob[]
  /** queued/running 的作业数，>0 时前端开启轮询 */
  active: number
}

/** 最近一次发现轮结果 */
export interface DiscoveryRunInfo {
  id: number
  project_id: number
  ran_at: string
  from_ctlog: number
  from_engines: number
  new_count: number
  error: string
}

/** 巡航状态：发现轮历史 + 站点巡检汇总 */
export interface CruiseStatus {
  discovery: DiscoveryRunInfo | null
  watch: {
    /** 巡检判定可达的站点数 */
    reachable: number
    /** 24 小时内巡检过的站点数 */
    checked_24h: number
    /** 历史上发生过内容变更的站点数 */
    changed_total: number
    /** 待处理发现候选数 */
    candidates_pending: number
    /** 收集队列进行中的作业数 */
    collect_active: number
  }
}

/** 资产巡航 v2 总览行：被动发现 + 站点内容巡检，按项目汇总 */
export interface CruiseOverviewRow {
  project_id: number
  name: string
  code: string
  paused: boolean
  /** 最近一次发现轮时间，尚未运行时为 null */
  last_run_at: string | null
  /** 发现累计新增候选数 */
  discover_new: number
  /** 待确认候选数 */
  pending: number
  /** 巡检判定可达的站点数 */
  reachable: number
  /** 24 小时内巡检过的站点数 */
  checked_24h: number
  /** 历史上发生过内容变更的站点数 */
  changed_total: number
  /** 收集队列进行中的作业数 */
  collecting: number
}

export const seedCollectionApi = {
  // seed_ids 缺省且 all=false 时后端拒绝；all=true 忽略 seed_ids 全量入队
  collect: (projectId: number, seedIds?: number[], all = false) =>
    api.post<unknown, ApiResponse<SeedCollectResult>>(`/projects/${projectId}/seeds/collect`, {
      seed_ids: seedIds,
      all,
    }),
  jobs: (projectId: number, limit = 20) =>
    api.get<unknown, ApiResponse<SeedCollectionJobsResult>>(
      `/projects/${projectId}/seeds/collect/jobs`,
      { params: { limit } }
    ),
  cruiseStatus: (projectId: number) =>
    api.get<unknown, ApiResponse<CruiseStatus>>(`/projects/${projectId}/cruise/status`),
  // 资产巡航 v2：全部项目的「发现 + 巡检」汇总（自动巡航页顶部卡片）
  overview: () => api.get<unknown, ApiResponse<CruiseOverviewRow[]>>('/cruise/v2/overview'),
}

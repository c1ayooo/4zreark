import api from '@/lib/api'

export type FpScoreLevel = 'high' | 'medium' | 'low' | 'none'
export type FpScoreSort = 'score' | 'host' | 'assets'

/** 一条指纹命中：分数怎么来的，前端直接展示。 */
export interface FpScoreMatch {
  name: string
  category: string
  /** 分类中文名，未映射时等于 category */
  category_label: string
  source: 'rule' | 'tech'
  points: number
  reason: string
}

export interface FpScoreItem {
  id: number
  host: string
  value: string
  ip: string
  title: string
  http_status: number
  state: string
  project_id: number
  project_name: string
  technology_stack: string[]
  categories: string[]
  score: number
  level: FpScoreLevel
  /** 档位中文名，后端下发 */
  level_label: string
  matches: FpScoreMatch[]
  last_seen: string
}

export interface FpScoreFacet {
  name: string
  label: string
  asset_count: number
}

export interface FpScoreBand {
  level: FpScoreLevel
  label: string
  count: number
  min: number
  max: number
}

export interface FpScoreFacets {
  bands: FpScoreBand[]
  categories: FpScoreFacet[]
  fingerprints: FpScoreFacet[]
  total: number
  scored: number
  avg_score: number
}

export interface FpScorePage {
  items: FpScoreItem[]
  total: number
  page: number
  page_size: number
  facets: FpScoreFacets
  project_id: number
  category: string
  fingerprint: string
  level: string
  /** true 表示候选资产超过后端计算上限，只统计了最近发现的一批 */
  truncated: boolean
  /** 实际参与评分的候选数；truncated 为 true 时即计算上限 */
  scored_count: number
}

export interface FpScoreParams {
  project_id?: number
  category?: string
  fingerprint?: string
  level?: FpScoreLevel
  /** 0 / 不传 = 不限 */
  min_score?: number
  max_score?: number
  q?: string
  sort?: FpScoreSort
  page?: number
  page_size?: number
}

export const fingerprintScoreApi = {
  list: (params: FpScoreParams) =>
    api.get<unknown, { code: number; message: string; data: FpScorePage }>(
      '/assets/fingerprint-scores',
      { params }
    ),
}

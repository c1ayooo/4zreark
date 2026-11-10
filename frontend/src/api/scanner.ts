import api, { ApiResponse } from '@/lib/api'

// 全局禁扫黑名单（config 只读展示：master/worker 必须读同一份配置才能保证两端判定一致）
export interface ScannerDenylist {
  deny_domain_suffixes: string[]
  deny_cidrs: string[]
  editable: boolean
}

// nuclei 误报黑名单（KV 层可写；生效值 = KV ∪ config 兜底）
export interface NucleiDenylist {
  ids: string[]
  kv_ids: string[]
  config_ids: string[]
}

export const scannerApi = {
  getDenylist: (): Promise<ApiResponse<ScannerDenylist>> =>
    api.get('/scanner/denylist'),

  getNucleiDenylist: (): Promise<ApiResponse<NucleiDenylist>> =>
    api.get('/nuclei/denylist'),

  saveNucleiDenylist: (ids: string[]): Promise<ApiResponse<{ ids: string[] }>> =>
    api.put('/nuclei/denylist', { ids }),
}

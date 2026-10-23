import api, { ApiResponse } from '@/lib/api'

// 出网代理覆盖模式：跟随全局 / 强制直连 / 自定义代理
export type ProxyOverrideMode = 'global' | 'direct' | 'custom'

// 全局代理配置
export interface ProxyEntry {
  enabled: boolean
  url: string
}

// 单模块覆盖
export interface ProxyOverride {
  mode: ProxyOverrideMode
  url: string
}

// 平台出网代理配置（后端 app_settings network.proxy）：
// 指纹同步 / nuclei / 工具下载 / 情报 / 被动收集 / 通知可分别指定代理；
// 对扫描目标的流量不走全局代理（扫描任务有自己的按任务代理参数）。
export interface ProxyConfig {
  global: ProxyEntry
  modules: Record<string, ProxyOverride>
}

// 连通性测试结果
export interface ProxyTestResult {
  ok: boolean
  status?: number
  latency_ms: number
  target: string
  error?: string
}

export const proxyApi = {
  getConfig: (): Promise<ApiResponse<{ config: ProxyConfig; modules: string[] }>> =>
    api.get('/network/proxy'),
  updateConfig: (
    config: ProxyConfig
  ): Promise<ApiResponse<{ config: ProxyConfig; modules: string[] }>> =>
    api.put('/network/proxy', config),
  // url 为空 = 测直连
  test: (url: string): Promise<ApiResponse<ProxyTestResult>> =>
    api.post('/network/proxy/test', { url }),
}

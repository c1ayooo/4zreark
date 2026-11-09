import api, { ApiResponse } from '@/lib/api'

/**
 * 模型接入（LLM）：判定与对话共用。
 * 密钥只在服务端加密存储，GET 只回 api_key_configured + 掩码。
 */

export interface LLMSettingsView {
  base_url: string
  model: string
  api_key_configured: boolean
  api_key_masked: string
  temperature: number
  max_tokens: number
  timeout_seconds: number
  /** db：界面配置；env：环境变量；none：都没配（判定走桩模型） */
  source: 'db' | 'env' | 'none'
  updated_at?: string
  updated_by?: string
}

export interface LLMSettingsInput {
  base_url: string
  model: string
  /** 留空表示沿用已保存的密钥 */
  api_key?: string
  clear_key?: boolean
  temperature?: number
  max_tokens?: number
  timeout_seconds?: number
}

export interface LLMTestResult {
  ok: boolean
  message: string
  reply: string
}

export const llmApi = {
  get: () =>
    api.get<unknown, ApiResponse<LLMSettingsView>>('/llm/settings').then((r) => r.data),

  save: (body: LLMSettingsInput) =>
    api.put<unknown, ApiResponse<LLMSettingsView>>('/llm/settings', body).then((r) => r.data),

  test: (body: LLMSettingsInput) =>
    api.post<unknown, ApiResponse<LLMTestResult>>('/llm/settings/test', body).then((r) => r.data),
}

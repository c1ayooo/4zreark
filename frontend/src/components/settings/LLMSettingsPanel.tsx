import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Input, InputNumber, Tag } from 'antd'
import { CheckCircle2, Loader2, PlugZap, Save, XCircle } from 'lucide-react'
import { useToast } from '@/components/ui/use-toast'
import { llmApi, type LLMSettingsInput, type LLMSettingsView } from '@/api/llm'

/**
 * 设置 → 模型接入。
 *
 * 判定（CommitSentinel）与对话工作台共用这一份配置：
 *   保存 → app_settings(llm.config, 密钥 secretbox 加密) → 下一次调用立即生效，不用重启。
 * 环境变量（ZRE_LLM_*）仍然有效，作为「界面没配」时的兜底。
 */

const PRESETS: { label: string; base_url: string; model: string }[] = [
  { label: 'OpenAI', base_url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
  { label: 'DeepSeek', base_url: 'https://api.deepseek.com/v1', model: 'deepseek-chat' },
  { label: '阿里云百炼', base_url: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-plus' },
  { label: '本地 vLLM / Ollama', base_url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:14b' },
]

const sourceMeta = (source: LLMSettingsView['source']) => {
  switch (source) {
    case 'db':
      return { label: '界面配置', tag: <Tag className="border-transparent bg-emerald-600 text-white">界面配置</Tag> }
    case 'env':
      return { label: '环境变量', tag: <Tag className="border-transparent bg-sky-600 text-white">环境变量</Tag> }
    default:
      return { label: '未配置', tag: <Tag className="border-transparent bg-zinc-500 text-white">未配置</Tag> }
  }
}

export function LLMSettingsPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const query = useQuery({ queryKey: ['llm-settings'], queryFn: llmApi.get })

  const [form, setForm] = useState<LLMSettingsInput>({
    base_url: '',
    model: '',
    api_key: '',
    temperature: 0,
    max_tokens: 2048,
    timeout_seconds: 90,
  })
  const [tested, setTested] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    const v = query.data
    if (!v) return
    setForm({
      base_url: v.base_url,
      model: v.model,
      api_key: '',
      temperature: v.temperature,
      max_tokens: v.max_tokens,
      timeout_seconds: v.timeout_seconds,
    })
  }, [query.data])

  const save = useMutation({
    mutationFn: () => llmApi.save(form),
    onSuccess: (v) => {
      toast({ title: '已保存', description: '判定与对话立即使用新配置' })
      setForm((f) => ({ ...f, api_key: '' }))
      queryClient.setQueryData(['llm-settings'], v)
      setTested(null)
    },
    onError: (e: Error) => toast({ title: '保存失败', description: e.message, variant: 'destructive' }),
  })

  const test = useMutation({
    mutationFn: () => llmApi.test(form),
    onSuccess: (r) => {
      setTested({ ok: true, text: r.reply || r.message })
      toast({ title: '连通成功', description: `模型回复：${r.reply}` })
    },
    onError: (e: Error) => {
      setTested({ ok: false, text: e.message })
      toast({ title: '连通失败', description: e.message, variant: 'destructive' })
    },
  })

  const view = query.data
  const meta = sourceMeta(view?.source ?? 'none')
  const busy = save.isPending || test.isPending

  return (
    <div className="space-y-4">
      <Card
        title={
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-2">
              模型接入（LLM）
              {meta.tag}
              {view?.api_key_configured ? (
                <Tag className="inline-flex items-center gap-1 border-transparent bg-emerald-600 text-white">
                  <CheckCircle2 className="h-3 w-3" /> 密钥已配置
                </Tag>
              ) : (
                <Tag className="inline-flex items-center gap-1 border-transparent bg-rose-600 text-white">
                  <XCircle className="h-3 w-3" /> 未配置密钥
                </Tag>
              )}
            </span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              判定（提交哨兵）与对话工作台共用这一份配置：OpenAI 兼容端点即可，Base URL 可指向
              DeepSeek / 百炼 / vLLM。密钥加密存库，保存后立即生效，不需要重启；环境变量
              <span className="mx-1 font-mono">ZRE_LLM_API_KEY</span>
              仍作为未配置时的兜底。
            </span>
          </div>
        }
      >
        {query.isLoading ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" /> 读取配置…
          </p>
        ) : (
          <div className="grid gap-3">
            {view && !view.api_key_configured && (
              <Alert
                type="warning"
                showIcon
                message={view.source === 'db' ? '配置已保存，但缺少 API Key' : '当前没有任何模型配置'}
                description="判定会用桩模型（结论标记 partial、一律判为「不是安全修复」），对话工作台会直接报「尚未配置模型接入」。填完 Base URL / 模型 / API Key 并保存即可。"
              />
            )}
            {view && view.source === 'env' && (
              <Alert
                type="info"
                showIcon
                message="当前生效的是环境变量配置"
                description={`密钥来自环境变量（${view.api_key_masked || '已设置'}）。在这里保存会覆盖环境变量，改回环境变量需要清空界面配置。`}
              />
            )}

            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-muted-foreground">快捷填充：</span>
              {PRESETS.map((p) => (
                <Button
                  key={p.label}
                  size="small"
                  onClick={() => setForm((f) => ({ ...f, base_url: p.base_url, model: p.model }))}
                >
                  {p.label}
                </Button>
              ))}
            </div>

            <label className="grid gap-1">
              <span className="text-xs text-muted-foreground">Base URL（OpenAI 兼容，需带 /v1）</span>
              <Input
                value={form.base_url}
                placeholder="https://api.openai.com/v1"
                onChange={(e) => setForm((f) => ({ ...f, base_url: e.target.value }))}
              />
            </label>

            <label className="grid gap-1">
              <span className="text-xs text-muted-foreground">模型</span>
              <Input
                value={form.model}
                placeholder="gpt-4o-mini"
                onChange={(e) => setForm((f) => ({ ...f, model: e.target.value }))}
              />
            </label>

            <label className="grid gap-1">
              <span className="text-xs text-muted-foreground">
                API Key
                {view?.api_key_configured && (
                  <span className="ml-2 font-mono text-[10.5px]">当前：{view.api_key_masked}</span>
                )}
              </span>
              <Input.Password
                value={form.api_key}
                placeholder={view?.api_key_configured ? '留空表示沿用已保存的密钥' : 'sk-...'}
                onChange={(e) => setForm((f) => ({ ...f, api_key: e.target.value }))}
              />
            </label>

            <div className="flex flex-wrap items-end gap-3">
              <label className="grid gap-1">
                <span className="text-xs text-muted-foreground">温度</span>
                <InputNumber
                  className="w-28"
                  min={0}
                  max={2}
                  step={0.1}
                  value={form.temperature}
                  onChange={(v) => setForm((f) => ({ ...f, temperature: Number(v ?? 0) }))}
                />
              </label>
              <label className="grid gap-1">
                <span className="text-xs text-muted-foreground">max tokens</span>
                <InputNumber
                  className="w-32"
                  min={64}
                  max={32768}
                  value={form.max_tokens}
                  onChange={(v) => setForm((f) => ({ ...f, max_tokens: Number(v ?? 2048) }))}
                />
              </label>
              <label className="grid gap-1">
                <span className="text-xs text-muted-foreground">超时（秒）</span>
                <InputNumber
                  className="w-28"
                  min={5}
                  max={600}
                  value={form.timeout_seconds}
                  onChange={(v) => setForm((f) => ({ ...f, timeout_seconds: Number(v ?? 90) }))}
                />
              </label>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Button type="primary" icon={<Save className="h-3.5 w-3.5" />} loading={save.isPending} disabled={busy && !save.isPending} onClick={() => save.mutate()}>
                保存
              </Button>
              <Button icon={<PlugZap className="h-3.5 w-3.5" />} loading={test.isPending} disabled={busy && !test.isPending} onClick={() => test.mutate()}>
                测试连通
              </Button>
              {view?.api_key_configured && (
                <Button
                  danger
                  size="small"
                  onClick={() => llmApi.save({ ...form, clear_key: true }).then(() => {
                    toast({ title: '已清空密钥' })
                    queryClient.invalidateQueries({ queryKey: ['llm-settings'] })
                  })}
                >
                  清空密钥
                </Button>
              )}
              {view?.updated_at && (
                <span className="ml-auto text-[10.5px] text-muted-foreground">
                  最后修改 {new Date(view.updated_at).toLocaleString()}
                  {view.updated_by ? ` · ${view.updated_by}` : ''}
                </span>
              )}
            </div>

            {tested && (
              <Alert
                type={tested.ok ? 'success' : 'error'}
                showIcon
                message={tested.ok ? '连通成功' : '连通失败'}
                description={<span className="break-all font-mono text-[11px]">{tested.text}</span>}
              />
            )}
          </div>
        )}
      </Card>

      <Card size="small" title="判定链路怎么用它">
        <ul className="m-0 list-disc space-y-1 pl-5 text-xs leading-relaxed text-muted-foreground">
          <li>保存后下一次判定自动换模型（判定服务按配置指纹热更，不重启）；</li>
          <li>未配置密钥时判定降级为桩模型，结论标 <span className="font-mono">partial=true</span>，不会污染真实数据；</li>
          <li>对话工作台没有密钥时直接返回明确提示，不再回放假事件流；</li>
          <li>模型名会写进每条 judgment，方便对比不同模型对同一提交的结论。</li>
        </ul>
      </Card>
    </div>
  )
}

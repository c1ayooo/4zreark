import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Input, Select, Switch, Tag } from 'antd'
import { FlaskConical, Globe, Save } from 'lucide-react'
import { getErrorMessage } from '@/lib/errors'
import { useToast } from '@/components/ui/use-toast'
import {
  proxyApi,
  ProxyConfig,
  ProxyOverride,
  ProxyOverrideMode,
  ProxyTestResult,
} from '@/api/proxy'

// 模块清单与后端 outbound.Modules() 对齐；说明文案给用户解释各模块覆盖哪些出网。
const MODULE_META: { key: string; label: string; desc: string }[] = [
  {
    key: 'fingerprint_sync',
    label: '指纹规则库同步',
    desc: 'wappalyzergo / webanalyze / dddd 上游规则拉取（24h 一轮）',
  },
  {
    key: 'nuclei',
    label: 'Nuclei 引擎与模板',
    desc: 'nuclei 二进制下载与模板快照同步（含子进程）',
  },
  {
    key: 'tool_download',
    label: '工具下载',
    desc: 'gogo / spray / katana / rem 的 GitHub release 下载',
  },
  {
    key: 'intel',
    label: '漏洞情报',
    desc: '公开漏洞源轮询与 GitHub PoC 富化',
  },
  {
    key: 'recon',
    label: '被动信息收集',
    desc: '空间测绘、被动 DNS/子域源、CT 日志、Wayback、GitHub 检索',
  },
  {
    key: 'notify',
    label: '通知推送',
    desc: '钉钉 / 飞书 / 企微 / 自定义 Webhook',
  },
]

const MODE_OPTIONS: { value: ProxyOverrideMode; label: string }[] = [
  { value: 'global', label: '跟随全局' },
  { value: 'direct', label: '强制直连' },
  { value: 'custom', label: '自定义代理' },
]

const PROXY_PLACEHOLDER = 'http://127.0.0.1:7890 或 socks5://user:pass@host:1080'

// 卡片标题：主标题 + 说明小字，与设置页其他 tab 一致。
function cardTitle(title: string, desc: string) {
  return (
    <div className="flex flex-col gap-1">
      <span>{title}</span>
      <span className="text-xs font-normal leading-relaxed text-muted-foreground">{desc}</span>
    </div>
  )
}

export function ProxyPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [cfg, setCfg] = useState<ProxyConfig | null>(null)
  // 连通性测试结果按位置存（global 或模块 key），同一时间只有一处展示自己的结果。
  const [testResults, setTestResults] = useState<Record<string, ProxyTestResult>>({})
  const [testingKey, setTestingKey] = useState<string | null>(null)

  const configQuery = useQuery({
    queryKey: ['network-proxy'],
    queryFn: async () => {
      const res = await proxyApi.getConfig()
      return res.data?.config ?? null
    },
  })
  useEffect(() => {
    if (configQuery.data) setCfg(configQuery.data)
  }, [configQuery.data])

  const save = useMutation({
    mutationFn: (c: ProxyConfig) => proxyApi.updateConfig(c),
    onSuccess: (res) => {
      toast({ title: '代理设置已保存，出网立即生效（无需重启）' })
      queryClient.invalidateQueries({ queryKey: ['network-proxy'] })
      if (res.data?.config) setCfg(res.data.config)
    },
    onError: (e: unknown) =>
      toast({ title: '保存失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const test = useMutation({
    mutationFn: ({ url }: { key: string; url: string }) => proxyApi.test(url),
    onMutate: ({ key }) => {
      setTestingKey(key)
      setTestResults((prev) => {
        const next = { ...prev }
        delete next[key]
        return next
      })
    },
    onSuccess: (res, { key }) => {
      if (res.data) setTestResults((prev) => ({ ...prev, [key]: res.data! }))
    },
    onError: (e: unknown, { key }) => {
      setTestResults((prev) => ({
        ...prev,
        [key]: { ok: false, latency_ms: 0, target: '', error: getErrorMessage(e, '请求失败') },
      }))
    },
    onSettled: () => setTestingKey(null),
  })

  if (!cfg) {
    return (
      <Card loading={configQuery.isLoading}>
        {configQuery.isError ? (
          <span className="text-sm text-destructive">
            代理配置读取失败：{getErrorMessage(configQuery.error)}
          </span>
        ) : null}
      </Card>
    )
  }

  const updateGlobal = (patch: Partial<ProxyConfig['global']>) =>
    setCfg({ ...cfg, global: { ...cfg.global, ...patch } })
  const updateModule = (key: string, patch: Partial<ProxyOverride>) => {
    const base: ProxyOverride = cfg.modules[key] ?? { mode: 'global', url: '' }
    setCfg({
      ...cfg,
      modules: { ...cfg.modules, [key]: { ...base, ...patch } },
    })
  }

  const renderTestResult = (key: string) => {
    const r = testResults[key]
    if (!r) return null
    return r.ok ? (
      <Tag className="border-transparent bg-emerald-600 text-white">
        连通正常 · {r.latency_ms}ms
      </Tag>
    ) : (
      <Tag color="error">失败{r.error ? ` · ${r.error}` : ''}</Tag>
    )
  }

  const runTest = (key: string, url: string) => test.mutate({ key, url })

  return (
    <div className="space-y-4">
      <Card
        title={cardTitle(
          '全局出网代理',
          '开启后，未单独配置的平台出网（规则同步、工具下载、情报、被动收集、通知等）默认经此代理；关闭时跟随系统环境变量。对扫描目标的流量不受影响，保持直连。'
        )}
      >
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-3">
            <Switch
              checked={cfg.global.enabled}
              onChange={(v) => updateGlobal({ enabled: v })}
            />
            <Input
              className="min-w-72 flex-1"
              placeholder={PROXY_PLACEHOLDER}
              value={cfg.global.url}
              onChange={(e) => updateGlobal({ url: e.target.value })}
            />
            <Button
              icon={<FlaskConical className="h-4 w-4" />}
              loading={testingKey === 'global'}
              onClick={() => runTest('global', cfg.global.url.trim())}
            >
              测试{cfg.global.url.trim() ? '代理' : '直连'}
            </Button>
            {renderTestResult('global')}
          </div>
          <div className="text-xs text-muted-foreground">
            协议支持 http / https / socks5 / socks5h，凭据可直接写进 URL。测试默认探测
            api.github.com，与规则同步、工具下载实际访问的域一致。
          </div>
        </div>
      </Card>

      <Card
        title={cardTitle(
          '模块级代理',
          '为单个功能指定独立代理：跟随全局（默认）、强制直连（不走任何代理）或自定义代理地址。'
        )}
      >
        <div className="grid gap-2">
          {MODULE_META.map((m) => {
            const ov = cfg.modules[m.key] ?? { mode: 'global' as ProxyOverrideMode, url: '' }
            return (
              <div key={m.key} className="grid gap-2 rounded-md border p-3">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-medium">{m.label}</span>
                  <span className="text-xs text-muted-foreground">{m.desc}</span>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Select
                    className="w-36"
                    value={ov.mode}
                    options={MODE_OPTIONS}
                    onChange={(v) => updateModule(m.key, { mode: v })}
                  />
                  {ov.mode === 'custom' && (
                    <>
                      <Input
                        className="min-w-64 flex-1"
                        placeholder={PROXY_PLACEHOLDER}
                        value={ov.url}
                        onChange={(e) => updateModule(m.key, { url: e.target.value })}
                      />
                      <Button
                        icon={<FlaskConical className="h-4 w-4" />}
                        loading={testingKey === m.key}
                        onClick={() => runTest(m.key, ov.url.trim())}
                      >
                        测试
                      </Button>
                    </>
                  )}
                  {renderTestResult(m.key)}
                </div>
              </div>
            )
          })}
        </div>
      </Card>

      <div className="flex items-center gap-3">
        <Button
          type="primary"
          icon={<Save className="h-4 w-4" />}
          loading={save.isPending}
          onClick={() => save.mutate(cfg)}
        >
          保存设置
        </Button>
        <span className="flex items-center gap-1 text-xs text-muted-foreground">
          <Globe className="h-3 w-3" />
          保存后立即生效，无需重启；模块留空表示跟随全局。
        </span>
      </div>
    </div>
  )
}

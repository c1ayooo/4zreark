import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Input, Tag } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolRuntimeApi, type ToolRuntimeStatus } from '@/api/tools'
import { Loader2, RefreshCw, RotateCcw, Download, Gauge } from 'lucide-react'

const statusBadge = (st: ToolRuntimeStatus['status']) => {
  switch (st) {
    case 'ok':
      return <Tag className="border-transparent bg-emerald-600 text-white">正常</Tag>
    case 'stale':
      return <Tag className="border-transparent bg-amber-600 text-white">有新版本</Tag>
    case 'needs_review':
      return <Tag color="error">需人工确认</Tag>
    default:
      return <Tag>未安装</Tag>
  }
}

function ToolRow({ tool }: { tool: ToolRuntimeStatus }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [pin, setPin] = useState(tool.pinned_version || '')
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['tool-runtime'] })

  const check = useMutation({
    mutationFn: () => toolRuntimeApi.check(tool.name),
    onSuccess: (st) => {
      toast({ title: `${tool.name} 最新版本 ${st.latest_version || '未知'}` })
      refresh()
    },
    onError: (e: Error) => toast({ title: '检查失败', description: e.message, variant: 'destructive' }),
  })
  const update = useMutation({
    mutationFn: () => toolRuntimeApi.update(tool.name),
    onSuccess: (st) => {
      toast({ title: `${tool.name} 已更新到 ${st.installed_version}` })
      refresh()
    },
    onError: (e: Error) => toast({ title: '更新失败', description: e.message, variant: 'destructive' }),
  })
  const rollback = useMutation({
    mutationFn: () => toolRuntimeApi.rollback(tool.name),
    onSuccess: (st) => {
      toast({ title: `${tool.name} 已回滚到 ${st.installed_version}` })
      refresh()
    },
    onError: (e: Error) => toast({ title: '回滚失败', description: e.message, variant: 'destructive' }),
  })
  const savePin = useMutation({
    mutationFn: () => toolRuntimeApi.setSettings(tool.name, { pinned_version: pin }),
    onSuccess: () => {
      toast({ title: '版本钉住已保存' })
      refresh()
    },
    onError: (e: Error) => toast({ title: '保存失败', description: e.message, variant: 'destructive' }),
  })

  const busy = check.isPending || update.isPending || rollback.isPending || savePin.isPending

  return (
    <div className="grid gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{tool.name}</span>
        {statusBadge(tool.status)}
        <span className="text-xs text-muted-foreground">{tool.description}</span>
        {tool.status_note && (
          <span className="text-xs text-destructive">{tool.status_note}</span>
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>已装 <span className="text-foreground">{tool.installed_version || tool.disk_version || '—'}</span></span>
        <span>上游 <span className="text-foreground">{tool.latest_version || '—'}</span></span>
        <span>{tool.managed ? '托管' : 'vendored/PATH'}{tool.path ? ` · ${tool.path}` : ''}</span>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="small"
          icon={<RefreshCw className="h-3 w-3" />}
          loading={check.isPending}
          disabled={busy}
          onClick={() => check.mutate()}
        >
          检查
        </Button>
        <Button
          size="small"
          icon={<Download className="h-3 w-3" />}
          loading={update.isPending}
          disabled={busy}
          onClick={() => update.mutate()}
        >
          安装/更新
        </Button>
        <Button
          size="small"
          icon={<RotateCcw className="h-3 w-3" />}
          loading={rollback.isPending}
          disabled={busy}
          onClick={() => rollback.mutate()}
        >
          回滚
        </Button>
        <div className="flex items-center gap-1">
          <Input
            className="h-7 w-28 text-xs"
            placeholder="钉住版本"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
          />
          <Button size="small" type="text" disabled={busy} onClick={() => savePin.mutate()}>钉住</Button>
        </div>
      </div>
    </div>
  )
}

function EngineUsageCard() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [limits, setLimits] = useState<Record<string, number>>({})
  const usage = useQuery({ queryKey: ['engine-usage'], queryFn: () => toolRuntimeApi.engineUsage() })

  const save = useMutation({
    mutationFn: () => toolRuntimeApi.setEngineLimits(limits),
    onSuccess: () => {
      toast({ title: '限额已保存' })
      queryClient.invalidateQueries({ queryKey: ['engine-usage'] })
    },
    onError: (e: Error) => toast({ title: '保存失败', description: e.message, variant: 'destructive' }),
  })

  if (usage.isLoading) {
    return <p className="text-sm text-muted-foreground flex items-center gap-2"><Loader2 className="h-3 w-3 animate-spin" /> 加载引擎额度…</p>
  }
  if (!usage.data?.available) {
    return <p className="text-sm text-muted-foreground">引擎额度记账需要在控制面（master）上查询。</p>
  }

  const engines = Object.keys(usage.data.limits ?? {})
  const today = usage.data.today ?? {}

  return (
    <div className="grid gap-3">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {engines.map((e) => {
          const limit = usage.data?.limits?.[e] ?? 0
          const used = today[e] ?? 0
          const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0
          return (
            <div key={e} className="rounded-md border p-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{e}</span>
                <span className="text-xs text-muted-foreground">{used}/{limit > 0 ? limit : '∞'}</span>
              </div>
              {limit > 0 && (
                <div className="mt-2 h-1.5 rounded-full bg-muted">
                  <div
                    className={`h-1.5 rounded-full ${pct >= 90 ? 'bg-destructive' : pct >= 60 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              )}
            </div>
          )
        })}
      </div>
      <div className="flex flex-wrap items-end gap-2">
        {engines.map((e) => (
          <label key={e} className="flex items-center gap-1 text-xs">
            {e}
            <Input
              className="h-7 w-20 text-xs"
              type="number"
              value={limits[e] ?? usage.data?.limits?.[e] ?? 60}
              onChange={(ev) => setLimits((prev) => ({ ...prev, [e]: Number(ev.target.value) }))}
            />
          </label>
        ))}
        <Button size="small" loading={save.isPending} onClick={() => save.mutate()}>
          保存限额
        </Button>
      </div>
    </div>
  )
}

export function ToolRuntimePanel() {
  const overview = useQuery({
    queryKey: ['tool-runtime'],
    queryFn: () => toolRuntimeApi.list(),
  })

  return (
    <div className="space-y-6">
      <Card
        title={
          <div className="flex flex-col gap-1">
            <span>扫描工具运行时</span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              gogo / spray / katana / rem 的版本与更新管理：下载校验 checksums、换版前跑
              flag 探针（上游改名会被拦下）、旧版本保留一键回滚。nuclei 由独立运行时自更新，状态一并列出。
              更新永不阻断扫描：解析不到托管二进制时回退 vendored tools/ 与 PATH。
            </span>
          </div>
        }
      >
        <div className="grid gap-3">
          {overview.isLoading && (
            <p className="text-sm text-muted-foreground flex items-center gap-2">
              <Loader2 className="h-3 w-3 animate-spin" /> 加载工具状态…
            </p>
          )}
          {overview.data?.tools?.map((t) => <ToolRow key={t.name} tool={t} />)}
          {overview.data?.nuclei ? (
            <p className="text-xs text-muted-foreground">
              nuclei：{overview.data.nuclei.BinaryVersion || '未安装'} · 自动更新 {overview.data.nuclei.AutoUpdate ? '开' : '关'}（详见漏洞模板页）
            </p>
          ) : null}
        </div>
      </Card>

      <Card
        title={
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-2">
              <Gauge className="h-4 w-4" /> 测绘引擎每日额度
            </span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              按天记账：任务创建时按余额收紧单任务上限，master 侧种子反查查询前查余额，worker 实际消耗随任务完成上报。
              worker 崩溃会少记——这是防超烧的保护性记账，不是审计。0 或负数表示不限。
            </span>
          </div>
        }
      >
        <EngineUsageCard />
      </Card>
    </div>
  )
}

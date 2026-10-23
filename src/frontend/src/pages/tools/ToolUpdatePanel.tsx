import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Input, InputNumber, Modal, Space, Switch, Table, Tag, Tooltip } from 'antd'
import { History, RefreshCw, Save } from 'lucide-react'
import { useToast } from '@/components/ui/use-toast'
import {
  toolRuntimeApi,
  toolsApi,
  type NucleiRuntimeStatus,
  type ToolRuntimeStatus,
  type ToolUpdateRecord,
  type ToolsRuntimeOverview,
} from '@/api/tools'

// 更新策略面板：gogo/spray/katana/rem 托管工具 + nuclei 运行时的
// 自动更新开关 / 检查间隔 / 版本锁定，以及检查/更新/回滚/历史操作。
// 后端语义：auto_update 默认开、间隔默认 24h；pin 非空时 Update 固定装该版本。

interface StrategyDraft {
  auto: boolean
  hours: number
  pin: string
}

const STATUS_META: Record<ToolRuntimeStatus['status'], { color: string; label: string }> = {
  ok: { color: 'success', label: '正常' },
  stale: { color: 'warning', label: '有更新' },
  missing: { color: 'error', label: '未安装' },
  needs_review: { color: 'warning', label: '需复核' },
}

// rem 的反向转发依赖 fork 补丁（官方 release 数据面不通），自动升到官方版会断隧道
const TOOL_HINTS: Record<string, string> = {
  rem: 'rem 当前为 fork 构建（官方版本反向转发不通）。建议关闭自动更新，或把版本锁定在 0.3.0，待官方修复后再放开。',
}

export default function ToolUpdatePanel() {
  const { toast } = useToast()
  const [overview, setOverview] = useState<ToolsRuntimeOverview | null>(null)
  const [nuclei, setNuclei] = useState<NucleiRuntimeStatus | null>(null)
  const [loading, setLoading] = useState(false)

  // 每个工具一份未保存的策略草稿，行内直接改、点保存才提交
  const [drafts, setDrafts] = useState<Record<string, StrategyDraft>>({})
  const [saving, setSaving] = useState('')
  const [rowBusy, setRowBusy] = useState('')

  const [historyTool, setHistoryTool] = useState('')
  const [history, setHistory] = useState<ToolUpdateRecord[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)
  const [historyBusy, setHistoryBusy] = useState(false)

  const applyOverview = useCallback((data: ToolsRuntimeOverview) => {
    setOverview(data)
    setDrafts((prev) => {
      const next = { ...prev }
      for (const t of data.tools) {
        if (!next[t.name]) {
          next[t.name] = { auto: t.auto_update, hours: t.check_interval_hours || 24, pin: t.pinned_version || '' }
        }
      }
      return next
    })
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [data, nuc] = await Promise.all([toolRuntimeApi.list(), toolsApi.nucleiRuntimeStatus().catch(() => null)])
      applyOverview(data)
      setNuclei(nuc)
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取工具运行时失败', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [applyOverview, toast])

  useEffect(() => {
    load()
  }, [load])

  const patchDraft = (name: string, patch: Partial<StrategyDraft>) => {
    setDrafts((prev) => ({ ...prev, [name]: { ...prev[name], ...patch } }))
  }

  const saveStrategy = async (name: string) => {
    const d = drafts[name]
    if (!d) return
    setSaving(name)
    try {
      const st = await toolRuntimeApi.setSettings(name, {
        auto_update: d.auto,
        check_interval_hours: Math.max(1, Math.min(720, d.hours || 24)),
        pinned_version: d.pin.trim(),
      })
      setOverview((prev) => prev ? { ...prev, tools: prev.tools.map((t) => t.name === name ? st : t) } : prev)
      toast({ title: `${name} 更新策略已保存` })
    } catch (e) {
      toast({ title: (e as Error)?.message || '保存失败', variant: 'destructive' })
    } finally {
      setSaving('')
    }
  }

  const runAction = async (name: string, action: 'check' | 'update' | 'rollback') => {
    setRowBusy(name + action)
    try {
      const st = action === 'check'
        ? await toolRuntimeApi.check(name)
        : action === 'update'
          ? await toolRuntimeApi.update(name)
          : await toolRuntimeApi.rollback(name)
      setOverview((prev) => prev ? { ...prev, tools: prev.tools.map((t) => t.name === name ? st : t) } : prev)
      setDrafts((prev) => ({
        ...prev,
        [name]: { auto: st.auto_update, hours: st.check_interval_hours || 24, pin: st.pinned_version || '' },
      }))
      toast({
        title: action === 'check'
          ? `${name} 已检查：最新 ${st.latest_version || '未知'}`
          : action === 'update'
            ? `${name} 已更新到 ${st.installed_version || '最新'}`
            : `${name} 已回滚到 ${st.installed_version || '上一版'}`,
      })
    } catch (e) {
      toast({ title: (e as Error)?.message || `${name} ${action} 失败`, variant: 'destructive' })
    } finally {
      setRowBusy('')
    }
  }

  const openHistory = async (name: string) => {
    setHistoryTool(name)
    setHistoryOpen(true)
    setHistoryBusy(true)
    try {
      setHistory(await toolRuntimeApi.history(name))
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取历史失败', variant: 'destructive' })
    } finally {
      setHistoryBusy(false)
    }
  }

  const saveNuclei = async (patch: { auto_update?: boolean; interval_hours?: number }) => {
    try {
      const st = await toolsApi.nucleiRuntimeSettings(patch)
      setNuclei(st)
      toast({ title: 'nuclei 更新策略已保存' })
    } catch (e) {
      toast({ title: (e as Error)?.message || '保存失败', variant: 'destructive' })
    }
  }

  const columns = useMemo(() => [
    {
      title: '工具',
      width: 180,
      render: (_: unknown, t: ToolRuntimeStatus) => (
        <div>
          <div className="font-medium">{t.name}</div>
          <div className="text-xs text-muted-foreground">{t.description}</div>
        </div>
      ),
    },
    {
      title: '已装版本',
      width: 130,
      render: (_: unknown, t: ToolRuntimeStatus) => (
        <Space size={4}>
          <span className="font-mono text-xs">{t.installed_version || t.disk_version || '未安装'}</span>
          {t.pinned_version && <Tooltip title={`版本已锁定在 ${t.pinned_version}`}><Tag color="geekblue">锁</Tag></Tooltip>}
        </Space>
      ),
    },
    {
      title: '上游最新',
      width: 130,
      render: (_: unknown, t: ToolRuntimeStatus) => (
        <Space size={4}>
          <span className="font-mono text-xs">{t.latest_version || '未检查'}</span>
          {t.update_available && <Tag color="orange">可更新</Tag>}
        </Space>
      ),
    },
    {
      title: '状态',
      width: 100,
      render: (_: unknown, t: ToolRuntimeStatus) => {
        const meta = STATUS_META[t.status] || { color: 'default', label: t.status }
        return <Tooltip title={t.status_note}><Tag color={meta.color}>{meta.label}</Tag></Tooltip>
      },
    },
    {
      title: '更新策略',
      render: (_: unknown, t: ToolRuntimeStatus) => {
        const d = drafts[t.name]
        if (!d) return null
        return (
          <div className="space-y-1">
            <Space size={8} wrap>
              <Tooltip title="开启后按检查间隔自动升级（只升不降，换版前过 flag 探针，失败保持旧版）">
                <Space size={6}><Switch size="small" checked={d.auto} onChange={(v) => patchDraft(t.name, { auto: v })} /><span className="text-xs">自动更新</span></Space>
              </Tooltip>
              <Space size={4}>
                <span className="text-xs text-muted-foreground">间隔</span>
                <InputNumber
                  size="small"
                  min={1}
                  max={720}
                  value={d.hours}
                  disabled={!d.auto}
                  onChange={(v) => patchDraft(t.name, { hours: Number(v) || 24 })}
                  addonAfter="h"
                  style={{ width: 96 }}
                />
              </Space>
              <Tooltip title="锁定版本后不再自动升级，更新操作也固定安装该版本；留空跟随最新">
                <Input
                  size="small"
                  placeholder="锁定版本（空=跟随最新）"
                  value={d.pin}
                  onChange={(e) => patchDraft(t.name, { pin: e.target.value })}
                  style={{ width: 176 }}
                />
              </Tooltip>
              <Button
                size="small"
                icon={<Save className="h-3.5 w-3.5" />}
                loading={saving === t.name}
                onClick={() => saveStrategy(t.name)}
              >
                保存
              </Button>
            </Space>
            {TOOL_HINTS[t.name] && (
              <div className="text-xs text-amber-600">{TOOL_HINTS[t.name]}</div>
            )}
          </div>
        )
      },
    },
    {
      title: '操作',
      width: 250,
      render: (_: unknown, t: ToolRuntimeStatus) => (
        <Space size={4} wrap>
          <Button size="small" loading={rowBusy === t.name + 'check'} onClick={() => runAction(t.name, 'check')}>检查</Button>
          <Button size="small" type="primary" loading={rowBusy === t.name + 'update'} onClick={() => runAction(t.name, 'update')}>更新</Button>
          <Button size="small" loading={rowBusy === t.name + 'rollback'} onClick={() => runAction(t.name, 'rollback')}>回滚</Button>
          <Button size="small" icon={<History className="h-3.5 w-3.5" />} onClick={() => openHistory(t.name)}>历史</Button>
        </Space>
      ),
    },
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [drafts, saving, rowBusy])

  const tools = overview?.tools || []
  const updateCount = tools.filter((t) => t.update_available).length

  return (
    <div className="space-y-4">
      <Card
        title="托管工具更新策略"
        extra={
          <Space>
            {updateCount > 0 && <Tag color="orange">{updateCount} 个工具可更新</Tag>}
            <Button icon={<RefreshCw className="h-4 w-4" />} onClick={load} loading={loading}>刷新</Button>
          </Space>
        }
      >
        {tools.length === 0 && !loading && (
          <Alert type="info" showIcon message="尚未读到托管工具状态：worker/无库模式下只展示本地磁盘工具。" />
        )}
        <Table
          rowKey="name"
          size="middle"
          loading={loading}
          pagination={false}
          dataSource={tools}
          columns={columns as never}
        />
        <p className="mt-3 text-xs text-muted-foreground">
          自动更新为全局默认开启，按各工具间隔到期检查 GitHub releases（直连失败自动走镜像）。换版前会校验 sha256
          并探测我们使用的命令行 flag 是否仍在，上游改版会被拦下保持旧版；每次变更可在「历史」中回滚。
          worker 节点按 master 的清单（sha256）自动跟进，无需逐台更新。
        </p>
      </Card>

      <Card title="nuclei 更新策略">
        {nuclei ? (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-6 text-sm">
              <Space size={6}>
                <Switch
                  size="small"
                  checked={nuclei.AutoUpdate}
                  onChange={(v) => saveNuclei({ auto_update: v })}
                />
                <span>自动更新（二进制 + 官方模板，失败不阻断扫描）</span>
              </Space>
              <Space size={4}>
                <span className="text-xs text-muted-foreground">间隔</span>
                <InputNumber
                  size="small"
                  min={1}
                  max={720}
                  value={nuclei.UpdateIntervalHours}
                  onChange={(v) => saveNuclei({ interval_hours: Number(v) || 24 })}
                  addonAfter="h"
                  style={{ width: 96 }}
                />
              </Space>
            </div>
            <div className="text-xs text-muted-foreground">
              二进制 {nuclei.BinaryExists ? nuclei.BinaryVersion || '已安装' : '缺失'} · 官方模板{' '}
              {nuclei.TemplateCount} 个 · 自定义模板 {nuclei.CustomTemplateCount} 个 · 引导版本 {nuclei.VersionSetting}
            </div>
            {nuclei.Warnings?.map((w, i) => <div key={i} className="text-xs text-amber-600">{w}</div>)}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">nuclei 运行时状态不可用。</p>
        )}
      </Card>

      <Modal
        title={`${historyTool} 更新历史`}
        open={historyOpen}
        onCancel={() => setHistoryOpen(false)}
        footer={null}
        width={680}
      >
        <Table
          rowKey={(_, i) => String(i)}
          size="small"
          loading={historyBusy}
          pagination={false}
          dataSource={history}
          columns={[
            { title: '时间', width: 160, render: (_: unknown, r: ToolUpdateRecord) => new Date(r.created_at).toLocaleString() },
            { title: '变更', width: 160, render: (_: unknown, r: ToolUpdateRecord) => (
              <span className="font-mono text-xs">{r.from_version || '—'} → {r.to_version}</span>
            ) },
            { title: '结果', width: 80, render: (_: unknown, r: ToolUpdateRecord) => (
              <Tag color={r.ok ? 'success' : 'error'}>{r.ok ? '成功' : '失败'}</Tag>
            ) },
            { title: '备注', render: (_: unknown, r: ToolUpdateRecord) => (
              <span className="text-xs text-muted-foreground break-all">{r.note}{r.sha256 ? ` · sha256:${r.sha256.slice(0, 12)}…` : ''}</span>
            ) },
          ] as never}
        />
      </Modal>
    </div>
  )
}

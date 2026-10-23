import { useEffect, useState, type FormEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Input, Modal, Select, Switch, Tag } from 'antd'
import {
  type SeedKind,
  type SeedPreviewResult,
  seedKindLabel,
  type PlanTriggerMode,
} from '@/api/projects'
import { dictionaryApi } from '@/api/sources'
import { statusTagClass } from '@/components/ui/StatusTag'

const PLAN_TRIGGER_MODES: { value: PlanTriggerMode; label: string }[] = [
  { value: 'interval', label: '固定周期' },
  { value: 'on_change', label: '资产变化' },
  { value: 'both', label: '周期 + 变化' },
]

interface AddSeedDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  defaultIntervalHours: number
  onPreview: (
    kind: SeedKind,
    value: string,
    capability: Record<string, unknown>,
    live: boolean,
  ) => Promise<SeedPreviewResult>
  onSubmit: (
    kind: SeedKind,
    value: string,
    intervalHours: number,
    capability: Record<string, unknown>,
    triggerMode: PlanTriggerMode,
    cooldownMinutes: number,
  ) => Promise<unknown>
}

// app（商店）暂无展开数据源，先不暴露创建入口，避免建出永远空跑的计划。
const SEED_KINDS: SeedKind[] = ['domain', 'cidr', 'company', 'cert', 'repo', 'dict']

export default function AddSeedDialog({
  open,
  onOpenChange,
  defaultIntervalHours,
  onPreview,
  onSubmit,
}: AddSeedDialogProps) {
  const [kind, setKind] = useState<SeedKind>('domain')
  const [value, setValue] = useState('')
  const [interval, setInterval] = useState(defaultIntervalHours)
  const [triggerMode, setTriggerMode] = useState<PlanTriggerMode>('interval')
  const [cooldown, setCooldown] = useState(10)
  const [dictionaryId, setDictionaryId] = useState('')
  const [live, setLive] = useState(false)
  const [preview, setPreview] = useState<SeedPreviewResult | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState('')

  const dictionaries = useQuery({
    queryKey: ['dictionaries', 'subdomain', 'seed-picker'],
    queryFn: () => dictionaryApi.list({ type: 'subdomain', page: 1, page_size: 100 }),
    enabled: open && kind === 'dict',
  })
  const dictionaryList = dictionaries.data?.data ?? []

  useEffect(() => {
    if (!open) return
    setKind('domain')
    setValue('')
    setInterval(defaultIntervalHours)
    setTriggerMode('interval')
    setCooldown(10)
    setDictionaryId('')
    setLive(false)
    setPreview(null)
  }, [open, defaultIntervalHours])

  // 输入变化后旧的预览结果不再可信，强制重新预览才能保存。
  const resetPreview = () => setPreview(null)

  const capability = (): Record<string, unknown> => {
    const base: Record<string, unknown> = {}
    if (kind === 'dict') {
      if (dictionaryId) base.dictionary_ids = [dictionaryId]
    }
    if (live) base.live = true
    return base
  }

  const runPreview = async () => {
    if (!value.trim()) return
    setPreviewing(true)
    try {
      const res = await onPreview(kind, value.trim(), capability(), live)
      setPreview(res)
    } catch {
      /* 错误提示由调用方负责 */
    } finally {
      setPreviewing(false)
    }
  }

  const submit = async (e?: FormEvent) => {
    e?.preventDefault()
    if (!value.trim() || !preview || preview.total === 0) return
    // 间隔必填：清空静默建「无计划种子」+ 成功提示谎称已启用，是既定修复项
    const intervalNum = Number(interval) || 0
    if (intervalNum < 1 || intervalNum > 720) {
      setSubmitError('检查间隔需为 1-720 小时')
      return
    }
    setSubmitError('')
    setSubmitting(true)
    try {
      await onSubmit(
        kind,
        value.trim(),
        intervalNum,
        capability(),
        triggerMode,
        Number(cooldown) || 10
      )
      onOpenChange(false)
    } catch {
      /* 错误提示由调用方负责 */
    } finally {
      setSubmitting(false)
    }
  }

  const previewBlocked = !value.trim() || (kind === 'dict' && !dictionaryId)

  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      title="添加监控种子"
      width={512}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>取消</Button>
          <Button onClick={runPreview} disabled={previewing || previewBlocked}>
            {previewing ? '预览中…' : '预览目标'}
          </Button>
          <Button
            type="primary"
            onClick={() => submit()}
            disabled={submitting || previewBlocked || !preview || preview.total === 0}
          >
            {submitting ? '添加中…' : '添加并启用监控'}
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        种子是持续监控的起点（域名 / 网段 / 公司等）。保存后会按间隔自动生成采集批次。
      </p>
      <form onSubmit={(e) => submit(e)} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="text-sm font-medium">种子类型</label>
            <Select
              className="w-full"
              value={kind}
              onChange={(v) => {
                setKind(v as SeedKind)
                setDictionaryId('')
                setLive(false)
                resetPreview()
              }}
              options={SEED_KINDS.map((k) => ({ value: k, label: seedKindLabel[k] }))}
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="seed-interval" className="text-sm font-medium">
              监控间隔（小时）
            </label>
            <Input
              id="seed-interval"
              type="number"
              min={1}
              max={720}
              value={interval}
              onChange={(e) => { setInterval(Number(e.target.value)); setSubmitError('') }}
            />
            {submitError && (
              <p className="text-xs text-destructive">{submitError}</p>
            )}
          </div>
        </div>
        <div className="space-y-1.5">
          <label htmlFor="seed-trigger" className="text-sm font-medium">
            触发方式
          </label>
          <Select
            className="w-full"
            id="seed-trigger"
            value={triggerMode}
            onChange={(v) => setTriggerMode(v as PlanTriggerMode)}
            options={PLAN_TRIGGER_MODES.map((m) => ({ value: m.value, label: m.label }))}
          />
          <p className="text-muted-foreground text-xs">
            {triggerMode === 'interval'
              ? '按监控间隔到期跑。'
              : triggerMode === 'on_change'
                ? '项目内出现新增/重现资产时才跑。'
                : '到期照跑；有资产变化也提前跑一次。'}
          </p>
        </div>
        {triggerMode !== 'interval' && (
          <div className="space-y-1.5">
            <label htmlFor="seed-cooldown" className="text-sm font-medium">
              变化触发冷却（分钟）
            </label>
            <Input
              id="seed-cooldown"
              type="number"
              min={1}
              max={1440}
              value={cooldown}
              onChange={(e) => setCooldown(Number(e.target.value))}
            />
            <p className="text-muted-foreground text-xs">
              两次变化触发之间至少间隔这么久，避免一次采集风暴刷出一串批次。
            </p>
          </div>
        )}
        <div className="space-y-1.5">
          <label htmlFor="seed-value" className="text-sm font-medium">
            种子值
          </label>
          <Input
            id="seed-value"
            value={value}
            placeholder={
              kind === 'cidr'
                ? '203.0.113.0/24'
                : kind === 'dict'
                  ? 'example.com（基础域名）'
                  : kind === 'company'
                    ? '公司名称'
                    : kind === 'cert'
                      ? '证书组织名，如 Meituan Software System'
                      : kind === 'repo'
                        ? 'https://github.com/org/repo'
                        : 'example.com'
            }
            onChange={(e) => {
              setValue(e.target.value)
              resetPreview()
            }}
            className="font-mono"
          />
          {kind === 'dict' && (
            <p className="text-muted-foreground text-xs">
              dict 种子的值是基础域名，具体子域词表从下面的字典展开。
            </p>
          )}
        </div>

        {kind === 'dict' && (
          <div className="space-y-1.5">
            <label className="text-sm font-medium">子域字典</label>
            <Select
              className="w-full"
              value={dictionaryId || undefined}
              onChange={(v) => {
                setDictionaryId(v)
                resetPreview()
              }}
              placeholder={dictionaries.isLoading ? '加载中…' : '选择字典'}
              options={dictionaryList.map((d) => ({
                value: String(d.id),
                label: `${d.name}（${d.line_count} 行）`,
              }))}
            />
            {!dictionaries.isLoading && dictionaryList.length === 0 && (
              <p className="text-muted-foreground text-xs">
                还没有子域字典，先去「字典」页导入。
              </p>
            )}
          </div>
        )}

        {(kind === 'company' || kind === 'cert' || kind === 'repo' || kind === 'app') && (
          <div className="flex items-start justify-between gap-3 rounded-md border p-3">
            <div>
              <label className="text-sm font-medium">使用 live 数据源</label>
              <p className="text-muted-foreground mt-1 text-xs">
                会向已配置的测绘 / 代码托管 API 发起查询，但不会探测展开出的目标。
              </p>
            </div>
            <Switch
              checked={live}
              onChange={(checked) => {
                setLive(checked)
                resetPreview()
              }}
            />
          </div>
        )}

        {preview && (
          <div className="bg-muted/30 space-y-2 rounded-md border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Tag className={statusTagClass(preview.total > 0 ? 'success' : 'warning')}>
                {preview.total} 个目标
              </Tag>
              <span className="text-muted-foreground text-xs">
                模式 {preview.mode} · 来源 {preview.source}
              </span>
              {preview.truncated && (
                <span className="text-muted-foreground text-xs">
                  仅展示前 {preview.shown} 条
                </span>
              )}
            </div>
            {preview.targets.length > 0 && (
              <div className="max-h-28 overflow-auto rounded border bg-background p-2 font-mono text-xs">
                {preview.targets.slice(0, 10).map((t) => (
                  <div key={`${t.host}:${t.port}`}>
                    {t.host}:{t.port}
                  </div>
                ))}
              </div>
            )}
            {preview.warnings.map((w) => (
              <p key={w} className="text-amber-600 text-xs">
                {w}
              </p>
            ))}
            {preview.total === 0 && (
              <p className="text-destructive text-xs">
                预览没有产生目标，不能保存；请调整种子或等待对应数据源接入。
              </p>
            )}
          </div>
        )}
      </form>
    </Modal>
  )
}

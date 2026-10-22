import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  Database,
  ExternalLink,
  FileText,
  ImageOff,
  ImagePlus,
  Layers,
  ListTodo,
  Pause,
  Pencil,
  Play,
  Plus,
  Radio,
  RefreshCw,
  ShieldCheck,
  Trash2,
  Zap,
} from 'lucide-react'

import {
  projectApi,
  seedKindLabel,
  type Plan,
  type ProjectInput,
  type Run,
  type Seed,
  type SeedKind,
  type SeedPreviewResult,
  planTriggerModeLabel,
  type PlanTriggerMode,
} from '@/api/projects'
import { dictionaryApi } from '@/api/sources'
import { taskApi } from '@/api/tasks'
import { ProjectFormDialog } from '@/components/projects/ProjectFormDialog'
import { ReportGenerateDialog } from '@/components/reports/ReportGenerateDialog'
import { reportApi, type ReportProfile } from '@/api/reports'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, formatNumber } from '@/lib/utils'

// app（商店）暂无展开数据源，先不暴露创建入口，避免建出永远空跑的计划。
const SEED_KINDS: SeedKind[] = ['domain', 'cidr', 'company', 'cert', 'repo', 'dict']

const regionLabel = (region: string) => {
  if (!region) return '—'
  if (region === 'domestic') return '国内'
  if (region === 'intl' || region === 'overseas') return '国际'
  return region
}

const fmtDate = (v?: string | null) => (v ? formatDate(v) : '—')

const runStatusMeta: Record<
  Run['status'],
  {
    label: string
    variant: 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'
  }
> = {
  queued: { label: '排队中', variant: 'secondary' },
  running: { label: '执行中', variant: 'info' },
  partial: { label: '部分完成', variant: 'warning' },
  done: { label: '已完成', variant: 'success' },
  failed: { label: '失败', variant: 'destructive' },
}

const taskStatusMeta: Record<
  string,
  {
    label: string
    variant: 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'
  }
> = {
  pending: { label: '待开始', variant: 'secondary' },
  running: { label: '运行中', variant: 'info' },
  paused: { label: '已暂停', variant: 'warning' },
  completed: { label: '已完成', variant: 'success' },
  failed: { label: '失败', variant: 'destructive' },
  cancelled: { label: '已取消', variant: 'outline' },
}

const taskTypeLabel: Record<string, string> = {
  asset_discovery: '资产发现',
  port_scan: '端口扫描',
  fingerprint: '指纹识别',
  vuln_scan: '漏洞扫描',
  subdomain: '子域名枚举',
  takeover: '子域名接管',
  dir_scan: '目录扫描',
  crawler: 'Web 爬虫',
  bruteforce: '弱口令',
  monitor: '页面监控',
  full: '全量扫描',
  custom: '组合扫描',
  service_identify: '服务识别',
  service_detect: '服务识别',
  exposure_scan: '暴露面探测',
  clue_hunt: '存量线索',
}

function InfoRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 text-sm">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className="min-w-0 break-words text-right font-medium">{children}</span>
    </div>
  )
}

function StatCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Database
  label: string
  value: ReactNode
  tone?: 'danger'
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <span
          className={cn(
            'flex size-9 shrink-0 items-center justify-center rounded-lg',
            tone === 'danger' ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary',
          )}
        >
          <Icon className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="text-muted-foreground text-xs">{label}</div>
          <div className="truncate text-lg font-semibold tabular-nums">{value}</div>
        </div>
      </CardContent>
    </Card>
  )
}

function SectionHeader({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <CardTitle className="text-base">{title}</CardTitle>
        {description && <p className="text-muted-foreground mt-1 text-xs">{description}</p>}
      </div>
      {action}
    </div>
  )
}

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

function AddSeedDialog({
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

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!value.trim() || !preview || preview.total === 0) return
    setSubmitting(true)
    try {
      await onSubmit(
        kind,
        value.trim(),
        Number(interval) || 0,
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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>添加监控种子</DialogTitle>
          <DialogDescription>
            种子是持续监控的起点（域名 / 网段 / 公司等）。保存后会按间隔自动生成采集批次。
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label>种子类型</Label>
              <Select
                value={kind}
                onValueChange={(v) => {
                  setKind(v as SeedKind)
                  setDictionaryId('')
                  setLive(false)
                  resetPreview()
                }}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SEED_KINDS.map((k) => (
                    <SelectItem key={k} value={k}>
                      {seedKindLabel[k]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="seed-interval">监控间隔（小时）</Label>
              <Input
                id="seed-interval"
                type="number"
                min={1}
                max={720}
                value={interval}
                onChange={(e) => setInterval(Number(e.target.value))}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="seed-trigger">触发方式</Label>
            <Select
              value={triggerMode}
              onValueChange={(v) => setTriggerMode(v as PlanTriggerMode)}
            >
              <SelectTrigger id="seed-trigger">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PLAN_TRIGGER_MODES.map((m) => (
                  <SelectItem key={m.value} value={m.value}>
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
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
              <Label htmlFor="seed-cooldown">变化触发冷却（分钟）</Label>
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
            <Label htmlFor="seed-value">种子值</Label>
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
              <Label>子域字典</Label>
              <Select
                value={dictionaryId}
                onValueChange={(v) => {
                  setDictionaryId(v)
                  resetPreview()
                }}
              >
                <SelectTrigger>
                  <SelectValue
                    placeholder={dictionaries.isLoading ? '加载中…' : '选择字典'}
                  />
                </SelectTrigger>
                <SelectContent>
                  {dictionaryList.map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.name}（{d.line_count} 行）
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
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
                <Label>使用 live 数据源</Label>
                <p className="text-muted-foreground mt-1 text-xs">
                  会向已配置的测绘 / 代码托管 API 发起查询，但不会探测展开出的目标。
                </p>
              </div>
              <Switch
                checked={live}
                onCheckedChange={(v) => {
                  setLive(v)
                  resetPreview()
                }}
              />
            </div>
          )}

          {preview && (
            <div className="bg-muted/30 space-y-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={preview.total > 0 ? 'success' : 'warning'}>
                  {preview.total} 个目标
                </Badge>
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

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={runPreview}
              disabled={previewing || previewBlocked}
            >
              {previewing ? '预览中…' : '预览目标'}
            </Button>
            <Button
              type="submit"
              disabled={submitting || previewBlocked || !preview || preview.total === 0}
            >
              {submitting ? '添加中…' : '添加并启用监控'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function ProjectDetailPage() {
  const { id } = useParams<{ id: string }>()
  const idNum = Number(id)
  const validId = Number.isFinite(idNum) && idNum > 0
  const queryClient = useQueryClient()
  const { toast } = useToast()

  const [editOpen, setEditOpen] = useState(false)
  const [seedOpen, setSeedOpen] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)

  const reportTemplatesQuery = useQuery({
    queryKey: ['report-templates'],
    queryFn: () => reportApi.templates(),
    staleTime: 10 * 60 * 1000,
  })
  const reportTemplates: ReportProfile[] = reportTemplatesQuery.data ?? []

  const projectQuery = useQuery({
    queryKey: ['project', idNum],
    queryFn: () => projectApi.get(idNum),
    enabled: validId,
  })
  const seedsQuery = useQuery({
    queryKey: ['project-seeds', idNum],
    queryFn: () => projectApi.seeds(idNum),
    enabled: validId,
  })
  const domainCountsQuery = useQuery({
    queryKey: ['project-seed-domain-counts', idNum],
    queryFn: () => projectApi.domainCounts(idNum),
    enabled: validId,
  })
  const plansQuery = useQuery({
    queryKey: ['project-plans', idNum],
    queryFn: () => projectApi.plans(idNum),
    enabled: validId,
  })
  const runsQuery = useQuery({
    queryKey: ['project-runs', idNum],
    queryFn: () => projectApi.runs(idNum),
    enabled: validId,
    refetchInterval: 30000,
  })
  const tasksQuery = useQuery({
    queryKey: ['project-tasks', idNum],
    queryFn: () => taskApi.getTasks({ page: 1, pageSize: 20, projectId: idNum }),
    enabled: validId,
    refetchInterval: 10000,
  })

  const project = projectQuery.data?.data
  const seeds = seedsQuery.data?.data ?? []
  const domainCounts = domainCountsQuery.data?.data?.items ?? []
  const domainCountMap = new Map(domainCounts.map((d) => [d.seed_id, d.site_count]))
  const plans = plansQuery.data?.data ?? []
  const runs = runsQuery.data?.data ?? []
  const tasks = tasksQuery.data?.data.list ?? []
  const tasksTotal = tasksQuery.data?.data.total ?? 0

  const invalidateProject = () => {
    queryClient.invalidateQueries({ queryKey: ['projects'] })
    queryClient.invalidateQueries({ queryKey: ['asset-projects'] })
    queryClient.invalidateQueries({ queryKey: ['project', idNum] })
    queryClient.invalidateQueries({ queryKey: ['project-tasks', idNum] })
  }
  const invalidateMonitoring = () => {
    queryClient.invalidateQueries({ queryKey: ['project-seeds', idNum] })
    queryClient.invalidateQueries({ queryKey: ['project-seed-domain-counts', idNum] })
    queryClient.invalidateQueries({ queryKey: ['project-plans', idNum] })
    queryClient.invalidateQueries({ queryKey: ['project-runs', idNum] })
    invalidateProject()
  }

  const fail = (title: string) => (e: any) =>
    toast({
      title,
      description: e?.message || '请稍后重试',
      variant: 'destructive',
    })

  const updateMutation = useMutation({
    mutationFn: (input: ProjectInput) => projectApi.update(idNum, input),
    onSuccess: (res) => {
      toast({ title: res.message || '项目已更新' })
      invalidateProject()
    },
    onError: fail('更新项目失败'),
  })

  const pauseMutation = useMutation({
    mutationFn: (paused: boolean) => (paused ? projectApi.pause(idNum) : projectApi.resume(idNum)),
    onSuccess: (res) => {
      toast({ title: res.message })
      invalidateProject()
      queryClient.invalidateQueries({ queryKey: ['project-plans', idNum] })
    },
    onError: fail('切换采集状态失败'),
  })

  const previewSeedMutation = useMutation({
    mutationFn: async ({
      kind,
      value,
      capability,
      live,
    }: {
      kind: SeedKind
      value: string
      capability: Record<string, unknown>
      live: boolean
    }) => {
      const res = await projectApi.previewSeed({
        project_id: idNum,
        kind,
        value,
        capability,
        live,
      })
      return res.data
    },
    onError: fail('预览种子失败'),
  })

  const addSeedMutation = useMutation({
    mutationFn: async ({
      kind,
      value,
      intervalHours,
      capability,
      triggerMode,
      changeCooldownMinutes,
    }: {
      kind: SeedKind
      value: string
      intervalHours: number
      capability: Record<string, unknown>
      triggerMode: PlanTriggerMode
      changeCooldownMinutes: number
    }) => {
      const seedRes = await projectApi.createSeed({
        project_id: idNum,
        kind,
        value,
        capability,
      })
      if (intervalHours > 0) {
        await projectApi.createPlan({
          seed_id: seedRes.data.id,
          interval_hours: intervalHours,
          trigger_mode: triggerMode,
          change_cooldown_minutes: changeCooldownMinutes,
        })
      }
      return seedRes.data
    },
    onSuccess: () => {
      toast({ title: '种子已添加，监控计划已启用' })
      invalidateMonitoring()
    },
    onError: fail('添加种子失败'),
  })

  const deleteSeedMutation = useMutation({
    mutationFn: (seedId: number) => projectApi.deleteSeed(seedId),
    onSuccess: () => {
      toast({ title: '种子已删除，关联计划一并移除' })
      invalidateMonitoring()
    },
    onError: fail('删除种子失败'),
  })

  const updatePlanMutation = useMutation({
    mutationFn: ({ planId, enabled }: { planId: number; enabled: boolean }) =>
      projectApi.updatePlan(planId, { enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['project-plans', idNum] })
    },
    onError: fail('更新计划失败'),
  })

  const triggerPlanMutation = useMutation({
    mutationFn: (planId: number) => projectApi.triggerPlan(planId),
    onSuccess: (res) => {
      toast({ title: res.message || '已创建批次' })
      queryClient.invalidateQueries({ queryKey: ['project-plans', idNum] })
      queryClient.invalidateQueries({ queryKey: ['project-runs', idNum] })
    },
    onError: fail('触发计划失败'),
  })

  const deletePlanMutation = useMutation({
    mutationFn: (planId: number) => projectApi.deletePlan(planId),
    onSuccess: () => {
      toast({ title: '计划已删除' })
      queryClient.invalidateQueries({ queryKey: ['project-plans', idNum] })
    },
    onError: fail('删除计划失败'),
  })

  const executeRunMutation = useMutation({
    mutationFn: (runId: number) => projectApi.executeRun(runId),
    onSuccess: () => {
      toast({ title: '批次执行完成' })
      queryClient.invalidateQueries({ queryKey: ['project-runs', idNum] })
      invalidateProject()
    },
    onError: fail('执行批次失败'),
  })

  const uploadIconMutation = useMutation({
    mutationFn: (file: File) => projectApi.uploadIcon(idNum, file),
    onSuccess: () => {
      toast({ title: '项目图标已更新' })
      invalidateProject()
    },
    onError: fail('上传图标失败'),
  })

  const clearIconMutation = useMutation({
    mutationFn: () => projectApi.clearIcon(idNum),
    onSuccess: () => {
      toast({ title: '项目图标已移除' })
      invalidateProject()
    },
    onError: fail('移除图标失败'),
  })

  if (!validId) {
    return (
      <Card>
        <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16">
          项目 ID 不合法
          <Button asChild variant="outline" size="sm">
            <Link to="/projects">返回项目列表</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  if (projectQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-16 w-full" />
        <div className="grid gap-4 md:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-72 w-full" />
      </div>
    )
  }

  if (!project) {
    return (
      <Card>
        <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16">
          <AlertTriangle className="text-destructive h-8 w-8" />
          {projectQuery.isError ? '项目加载失败' : '项目不存在'}
          <Button asChild variant="outline" size="sm">
            <Link to="/projects">返回项目列表</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  const projectPath = `/assets?project_id=${project.id}`
  const topologyPath = `/topology?project_id=${project.id}`

  return (
    <div className="space-y-4">
      {/* 顶部：面包屑 + 项目身份 + 操作 */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Button variant="ghost" size="icon" asChild>
            <Link to="/projects" aria-label="返回项目列表">
              <ArrowLeft className="h-5 w-5" />
            </Link>
          </Button>
          <span
            className="flex size-11 shrink-0 items-center justify-center overflow-hidden rounded-xl text-white shadow-sm"
            style={{ backgroundColor: project.color || '#64748b' }}
          >
            {project.icon_sha256 ? (
              <img
                src={`/api/asset-icons/${project.icon_sha256}`}
                alt={project.name}
                className="size-full object-cover"
              />
            ) : (
              <ShieldCheck className="size-5" />
            )}
          </span>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-bold">{project.name}</h1>
              <Badge variant={project.collection_paused ? 'warning' : 'success'}>
                {project.collection_paused ? '已暂停' : '采集中'}
              </Badge>
            </div>
            <p className="text-muted-foreground mt-1 font-mono text-sm">
              {project.code} · {regionLabel(project.region)}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to={projectPath}>
              <Database className="mr-2 h-4 w-4" />
              项目资产
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm">
            <Link to={topologyPath}>
              <Radio className="mr-2 h-4 w-4" />
              资产星图
            </Link>
          </Button>
          <Button variant="outline" size="sm" onClick={() => setReportOpen(true)}>
            <FileText className="mr-2 h-4 w-4" />
            信息收集报告
          </Button>
          <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
            <Pencil className="mr-2 h-4 w-4" />
            编辑资料
          </Button>
          {/* 用 Button asChild 包 label：之前手抄了一套按钮样式，改了 Button 也跟不上 */}
          <Button asChild variant="outline" size="sm">
          <label className="cursor-pointer">
            <ImagePlus className="mr-2 h-4 w-4" />
            图标
            <input
              type="file"
              accept="image/png,image/jpeg,image/webp"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) uploadIconMutation.mutate(file)
                e.currentTarget.value = ''
              }}
            />
          </label>
          </Button>
          {project.icon_sha256 && (
            <Button
              variant="ghost"
              size="sm"
              disabled={clearIconMutation.isPending}
              onClick={() => clearIconMutation.mutate()}
            >
              <ImageOff className="mr-2 h-4 w-4" />
              移除图标
            </Button>
          )}
          <Button
            variant={project.collection_paused ? 'default' : 'outline'}
            size="sm"
            disabled={pauseMutation.isPending}
            onClick={() => pauseMutation.mutate(!project.collection_paused)}
          >
            {project.collection_paused ? (
              <>
                <Play className="mr-2 h-4 w-4" />
                恢复采集
              </>
            ) : (
              <>
                <Pause className="mr-2 h-4 w-4" />
                暂停采集
              </>
            )}
          </Button>
        </div>
      </div>

      {/* 统计 */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <StatCard icon={Database} label="资产" value={formatNumber(project.asset_count)} />
        <StatCard icon={Layers} label="原始记录" value={formatNumber(project.record_count)} />
        <StatCard
          icon={AlertTriangle}
          label="失联资产"
          value={formatNumber(project.lost_count)}
          tone={project.lost_count > 0 ? 'danger' : undefined}
        />
        <StatCard icon={ShieldCheck} label="种子" value={formatNumber(project.seed_count)} />
        <StatCard icon={Calendar} label="采集周期" value={`${project.cycle_interval_days} 天`} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        {/* 左：任务 + 持续监控 */}
        <div className="space-y-4 xl:col-span-2">
          <Card>
            <CardHeader>
              <SectionHeader
                title="关联任务"
                description="归属于本项目的扫描任务；任务结果会自动并入项目资产。"
                action={
                  <div className="flex items-center gap-2">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => tasksQuery.refetch()}
                      disabled={tasksQuery.isFetching}
                    >
                      <RefreshCw
                        className={cn('mr-2 h-4 w-4', tasksQuery.isFetching && 'animate-spin')}
                      />
                      刷新
                    </Button>
                    <Button size="sm" asChild>
                      <Link to={`/tasks/new?project_id=${project.id}`}>
                        <Plus className="mr-2 h-4 w-4" />
                        新建任务
                      </Link>
                    </Button>
                  </div>
                }
              />
            </CardHeader>
            <CardContent>
              {tasksQuery.isLoading ? (
                <Skeleton className="h-24 w-full" />
              ) : tasks.length === 0 ? (
                <div className="text-muted-foreground flex flex-col items-center gap-3 py-6 text-sm">
                  <ListTodo className="h-8 w-8 opacity-40" />
                  <p>本项目还没有任务</p>
                  <Button size="sm" variant="outline" asChild>
                    <Link to={`/tasks/new?project_id=${project.id}`}>
                      <Plus className="mr-2 h-4 w-4" />
                      新建任务
                    </Link>
                  </Button>
                </div>
              ) : (
                <>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>任务</TableHead>
                        <TableHead>类型</TableHead>
                        <TableHead>状态</TableHead>
                        <TableHead>进度</TableHead>
                        <TableHead>目标</TableHead>
                        <TableHead>创建时间</TableHead>
                        <TableHead className="text-right">操作</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {tasks.map((task) => {
                        const meta = taskStatusMeta[task.status] ?? {
                          label: task.status,
                          variant: 'outline' as const,
                        }
                        return (
                          <TableRow key={task.id}>
                            <TableCell className="max-w-[220px] truncate font-medium">
                              {task.name}
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
                              {taskTypeLabel[task.type] || task.type}
                            </TableCell>
                            <TableCell>
                              <Badge variant={meta.variant}>{meta.label}</Badge>
                            </TableCell>
                            <TableCell>
                              <div className="flex min-w-[110px] items-center gap-2">
                                <Progress value={task.progress} className="h-1.5 w-16" />
                                <span className="text-muted-foreground w-9 tabular-nums text-xs">
                                  {task.progress}%
                                </span>
                              </div>
                            </TableCell>
                            <TableCell className="text-muted-foreground text-xs">
                              {task.targets.length} 个
                            </TableCell>
                            <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
                              {fmtDate(task.createdAt)}
                            </TableCell>
                            <TableCell>
                              <div className="flex justify-end">
                                <Button variant="ghost" size="sm" asChild>
                                  <Link to={`/tasks/${task.id}`}>查看</Link>
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        )
                      })}
                    </TableBody>
                  </Table>
                  {tasksTotal > tasks.length && (
                    <p className="text-muted-foreground pt-3 text-xs">
                      共 {tasksTotal} 个任务，显示最近 {tasks.length} 个
                    </p>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <SectionHeader
                title="监控种子"
                description="种子决定持续监控的范围；暂停项目后，种子保留但不会到期执行。"
                action={
                  <Button size="sm" onClick={() => setSeedOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" />
                    添加种子
                  </Button>
                }
              />
            </CardHeader>
            <CardContent>
              {seedsQuery.isLoading ? (
                <Skeleton className="h-24 w-full" />
              ) : seeds.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">
                  还没有种子，先添加一个域名或网段。
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>类型</TableHead>
                      <TableHead>种子值</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>创建时间</TableHead>
                      <TableHead className="w-12" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {seeds.map((seed: Seed) => (
                      <TableRow key={seed.id}>
                        <TableCell>
                          <Badge variant="outline">{seedKindLabel[seed.kind] || seed.kind}</Badge>
                        </TableCell>
                        <TableCell className="max-w-[280px] truncate font-mono text-xs">
                          {seed.value}
                          {seed.kind === 'domain' && (
                            <div className="text-muted-foreground mt-1 font-sans text-[11px]">
                              覆盖 {domainCountMap.get(seed.id) ?? 0} 个站点
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <Badge variant={seed.enabled ? 'success' : 'secondary'}>
                            {seed.enabled ? '启用' : '停用'}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {fmtDate(seed.created_at)}
                        </TableCell>
                        <TableCell>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button variant="ghost" size="icon" title="删除种子">
                                <Trash2 className="text-destructive size-4" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>删除这个种子？</AlertDialogTitle>
                                <AlertDialogDescription>
                                  种子和它关联的监控计划都会删除，已经产生的批次记录保留。
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>取消</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  onClick={() => deleteSeedMutation.mutate(seed.id)}
                                >
                                  删除
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <SectionHeader
                title="监控计划"
                description="每个种子按固定间隔生成治理批次；开关只影响该计划。"
              />
            </CardHeader>
            <CardContent>
              {plansQuery.isLoading ? (
                <Skeleton className="h-24 w-full" />
              ) : plans.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">暂无监控计划</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>种子</TableHead>
                      <TableHead>间隔</TableHead>
                      <TableHead>启用</TableHead>
                      <TableHead>下次执行</TableHead>
                      <TableHead>上次执行</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {plans.map((plan: Plan) => (
                      <TableRow key={plan.id}>
                        <TableCell className="max-w-[220px] truncate font-mono text-xs">
                          {plan.seed_value}
                        </TableCell>
                        <TableCell className="whitespace-nowrap text-sm">
                          {plan.interval_hours} 小时 ·{' '}
                          {planTriggerModeLabel[plan.trigger_mode] ?? plan.trigger_mode ?? '固定周期'}
                        </TableCell>
                        <TableCell>
                          <Switch
                            checked={plan.enabled}
                            disabled={updatePlanMutation.isPending}
                            onCheckedChange={(enabled) =>
                              updatePlanMutation.mutate({ planId: plan.id, enabled })
                            }
                          />
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {fmtDate(plan.next_run_at)}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">
                          {fmtDate(plan.last_run_at)}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-1">
                            <Button
                              variant="ghost"
                              size="icon"
                              title="立即触发"
                              disabled={triggerPlanMutation.isPending}
                              onClick={() => triggerPlanMutation.mutate(plan.id)}
                            >
                              <Zap className="size-4" />
                            </Button>
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="ghost" size="icon" title="删除计划">
                                  <Trash2 className="text-destructive size-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>删除这个监控计划？</AlertDialogTitle>
                                  <AlertDialogDescription>
                                    不会删除种子，只停止按此计划生成批次。
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>取消</AlertDialogCancel>
                                  <AlertDialogAction
                                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                    onClick={() => deletePlanMutation.mutate(plan.id)}
                                  >
                                    删除
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <SectionHeader
                title="执行批次"
                description="每次计划到期或手动触发都会生成一个批次，批次里是待探测的目标。"
                action={
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => runsQuery.refetch()}
                    disabled={runsQuery.isFetching}
                  >
                    <RefreshCw
                      className={cn('mr-2 h-4 w-4', runsQuery.isFetching && 'animate-spin')}
                    />
                    刷新
                  </Button>
                }
              />
            </CardHeader>
            <CardContent>
              {runsQuery.isLoading ? (
                <Skeleton className="h-24 w-full" />
              ) : runs.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">
                  暂无执行批次，触发一个计划即可生成。
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>批次</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead>周期开始</TableHead>
                      <TableHead>统计</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((run) => {
                      const meta = runStatusMeta[run.status] ?? {
                        label: run.status,
                        variant: 'outline' as const,
                      }
                      return (
                        <TableRow key={run.id}>
                          <TableCell className="font-mono text-xs">#{run.id}</TableCell>
                          <TableCell>
                            <Badge variant={meta.variant}>{meta.label}</Badge>
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">
                            {fmtDate(run.cycle_start)}
                          </TableCell>
                          <TableCell className="text-muted-foreground max-w-[240px] truncate text-xs">
                            {Object.keys(run.stats ?? {}).length > 0
                              ? Object.entries(run.stats)
                                  .slice(0, 3)
                                  .map(([k, v]) => `${k}: ${String(v)}`)
                                  .join(' · ')
                              : '—'}
                          </TableCell>
                          <TableCell>
                            <div className="flex justify-end">
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={
                                  executeRunMutation.isPending ||
                                  run.status === 'done' ||
                                  run.status === 'failed'
                                }
                                onClick={() => executeRunMutation.mutate(run.id)}
                              >
                                <Play className="mr-1 h-3.5 w-3.5" />
                                执行
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </div>

        {/* 右：项目资料（表单式字段） */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <SectionHeader title="项目资料" description="项目的基本信息与采集状态。" />
            </CardHeader>
            <CardContent className="divide-y">
              <InfoRow label="项目编码">
                <span className="font-mono">{project.code}</span>
              </InfoRow>
              <InfoRow label="地区">{regionLabel(project.region)}</InfoRow>
              <InfoRow label="采集周期">{project.cycle_interval_days} 天</InfoRow>
              <InfoRow label="采集状态">
                <Badge variant={project.collection_paused ? 'warning' : 'success'}>
                  {project.collection_paused ? '已暂停' : '采集中'}
                </Badge>
              </InfoRow>
              {project.collection_paused && (
                <InfoRow label="暂停原因">{project.collection_pause_reason || '—'}</InfoRow>
              )}
              <InfoRow label="主页">
                {project.homepage_url ? (
                  <a
                    href={project.homepage_url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-primary inline-flex items-center gap-1 hover:underline"
                  >
                    打开
                    <ExternalLink className="size-3" />
                  </a>
                ) : (
                  '—'
                )}
              </InfoRow>
              <InfoRow label="更新时间">{fmtDate(project.updated_at)}</InfoRow>
              <div className="pt-3">
                <div className="text-muted-foreground mb-1 text-xs">项目说明</div>
                <p className="whitespace-pre-wrap text-sm leading-relaxed">
                  {project.description || '暂无说明'}
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <SectionHeader title="数据入口" description="按项目筛选资产或查看星图。" />
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button asChild variant="outline" className="justify-start">
                <Link to={projectPath}>
                  <Database className="mr-2 h-4 w-4" />
                  资产探索 · 按本项目筛选
                </Link>
              </Button>
              <Button asChild variant="outline" className="justify-start">
                <Link to={topologyPath}>
                  <Radio className="mr-2 h-4 w-4" />
                  资产星图 · 按本项目筛选
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      <ProjectFormDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        project={project}
        onSubmit={(input) => updateMutation.mutateAsync(input)}
      />

      <AddSeedDialog
        open={seedOpen}
        onOpenChange={setSeedOpen}
        defaultIntervalHours={Math.max(1, Math.min(720, project.cycle_interval_days * 24))}
        onPreview={(kind, value, capability, live) =>
          previewSeedMutation.mutateAsync({ kind, value, capability, live })
        }
        onSubmit={(kind, value, intervalHours, capability, triggerMode, cooldownMinutes) =>
          addSeedMutation.mutateAsync({
            kind,
            value,
            intervalHours,
            capability,
            triggerMode,
            changeCooldownMinutes: cooldownMinutes,
          })
        }
      />

      <ReportGenerateDialog
        open={reportOpen}
        onOpenChange={setReportOpen}
        projectId={project.id}
        projectName={project.name}
        defaultKind="asset"
        templates={reportTemplates}
      />
    </div>
  )
}

import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import ProjectAssessmentCard from '@/components/projects/ProjectAssessmentCard'
import CollectOverviewCard from '@/components/projects/CollectOverviewCard'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  ChevronDown,
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
} from 'lucide-react'
import { Badge, Button, Card, Dropdown, Input, Modal, Select, Skeleton, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import {
  projectApi,
  seedKindLabel,
  type Plan,
  type ProjectInput,
  type Run,
  type Seed,
  type SeedKind,
  type PlanTriggerMode,
} from '@/api/projects'
import { seedsApi, type SeedBatchResult, type SeedRestartPreview } from '@/api/seeds'
import {
  buildPlanColumns,
  buildRunColumns,
  buildSeedColumns,
  fmtDate,
  jobColumns,
  taskColumns,
} from './components/columns'
import AddSeedDialog from './components/AddSeedDialog'
import ProjectDeleteModal from '@/pages/projects/ProjectDeleteModal'
import {
  seedCollectionApi,
  type SeedCollectionJob,
} from '@/api/seedCollection'
import { taskApi, type Task } from '@/api/tasks'
import { ProjectFormDialog } from '@/components/projects/ProjectFormDialog'
import { DiscoveryCandidatesPanel } from '@/components/projects/DiscoveryCandidatesPanel'
import { GitHubMonitorPanel } from '@/components/projects/GitHubMonitorPanel'
import { ReportGenerateDialog } from '@/components/reports/ReportGenerateDialog'
import { reportApi, type ReportProfile } from '@/api/reports'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatNumber } from '@/lib/utils'
import { statusTagClass } from '@/components/ui/StatusTag'

import { safeExternalURL } from '@/lib/safeUrl'
const regionLabel = (region: string) => {
  if (!region) return '—'
  if (region === 'domestic') return '国内'
  if (region === 'intl' || region === 'overseas') return '国际'
  return region
}

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass

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
    <Card styles={{ body: { padding: '10px 12px' } }}>
      <div className="flex items-center gap-2.5">
        <span
          className={cn(
            'flex size-8 shrink-0 items-center justify-center rounded-lg',
            tone === 'danger' ? 'bg-destructive/10 text-destructive' : 'bg-primary/10 text-primary',
          )}
        >
          <Icon className="size-3.5" />
        </span>
        <div className="min-w-0">
          <div className="text-muted-foreground text-xs">{label}</div>
          <div className="truncate text-base font-semibold tabular-nums">{value}</div>
        </div>
      </div>
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
        <div className="text-base font-semibold">{title}</div>
        {description && <p className="text-muted-foreground mt-1 text-xs">{description}</p>}
      </div>
      {action}
    </div>
  )
}

// 右栏迷你统计块：label + 数值，双列网格铺开巡航/种子概览
function MiniStat({
  label,
  value,
  tone,
  className,
}: {
  label: string
  value: ReactNode
  tone?: 'primary'
  className?: string
}) {
  return (
    <div className={cn('bg-muted/30 rounded-lg border px-3 py-2', className)}>
      <div className="text-muted-foreground text-xs">{label}</div>
      <div
        className={cn(
          'mt-0.5 text-sm font-semibold tabular-nums',
          tone === 'primary' && 'text-primary',
        )}
      >
        {value}
      </div>
    </div>
  )
}


export default function ProjectDetailPage() {
  const navigate = useNavigate()
  const { id } = useParams<{ id: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const idNum = Number(id)
  const validId = Number.isFinite(idNum) && idNum > 0
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const confirm = useConfirm()
  const iconInputRef = useRef<HTMLInputElement>(null)
  const [deleteOpen, setDeleteOpen] = useState(false)

  const [editOpen, setEditOpen] = useState(false)
  const [seedOpen, setSeedOpen] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
  // 种子重建计划：预览拿一次性 token（15 分钟）→ 确认执行（POST /seeds/:id/restart）
  const [restartSeed, setRestartSeed] = useState<Seed | null>(null)
  const [restartPreview, setRestartPreview] = useState<SeedRestartPreview | null>(null)
  const [restartInterval, setRestartInterval] = useState('24')
  const [restartLoading, setRestartLoading] = useState(false)
  // 批量添加种子（POST /seeds/batch，逐条返回状态，不因一条失败中断整批）
  const [batchOpen, setBatchOpen] = useState(false)
  const [batchKind, setBatchKind] = useState<SeedKind>('domain')
  const [batchText, setBatchText] = useState('')
  const [batchSubmitting, setBatchSubmitting] = useState(false)
  const [batchResult, setBatchResult] = useState<SeedBatchResult | null>(null)
  // 种子表勾选（收集入口）
  const [selectedSeedIds, setSelectedSeedIds] = useState<number[]>([])

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
  // 种子收集队列：有进行中作业时 10s 轮询
  const collectJobsQuery = useQuery({
    queryKey: ['project-seed-collect-jobs', idNum],
    queryFn: () => seedCollectionApi.jobs(idNum),
    enabled: validId,
    refetchInterval: (query) => ((query.state.data?.data?.active ?? 0) > 0 ? 10000 : false),
  })
  // 巡航状态：发现轮 + 站点巡检汇总，供右栏「巡航概览」卡
  const cruiseStatusQuery = useQuery({
    queryKey: ['project-cruise-status', idNum],
    queryFn: () => seedCollectionApi.cruiseStatus(idNum),
    enabled: validId,
  })

  const project = projectQuery.data?.data
  const seeds = seedsQuery.data?.data ?? []
  const collectJobs = collectJobsQuery.data?.data?.items ?? []
  const collectActive = collectJobsQuery.data?.data?.active ?? 0
  const domainCounts = domainCountsQuery.data?.data?.items ?? []
  const domainCountMap = new Map(domainCounts.map((d) => [d.seed_id, d.site_count]))
  const plans = plansQuery.data?.data ?? []
  const runs = runsQuery.data?.data ?? []
  const tasks = tasksQuery.data?.data.list ?? []
  const tasksTotal = tasksQuery.data?.data.total ?? 0
  const cruise = cruiseStatusQuery.data?.data

  // 种子构成：按类型分组计数 + 覆盖站点数（domainCountMap 由页面统一下发）
  const seedBreakdown = (() => {
    const byKind = new Map<SeedKind, { count: number; sites: number }>()
    let totalSites = 0
    for (const s of seeds) {
      const sites = domainCountMap.get(s.id) ?? 0
      const e = byKind.get(s.kind) ?? { count: 0, sites: 0 }
      e.count += 1
      e.sites += sites
      byKind.set(s.kind, e)
      totalSites += sites
    }
    return {
      entries: [...byKind.entries()].sort((a, b) => b[1].count - a[1].count),
      totalSites,
    }
  })()

  // 列表页「删除」深链：?delete=1 且项目已加载时自动弹确认框
  useEffect(() => {
    if (searchParams.get('delete') === '1' && project && !deleteOpen) {
      setDeleteOpen(true)
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, project, deleteOpen, setSearchParams])

  const handleDeleteProject = () => {
    if (!project) return
    setDeleteOpen(true)
  }

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
      // 种子与计划分离记账：计划失败不算整体失败（种子已落库，重试会撞唯一键），
      // 由 onSuccess 如实播报，稍后可在计划列表手动补启
      let planEnabled = false
      let planError = ''
      if (intervalHours > 0) {
        try {
          await projectApi.createPlan({
            seed_id: seedRes.data.id,
            interval_hours: intervalHours,
            trigger_mode: triggerMode,
            change_cooldown_minutes: changeCooldownMinutes,
          })
          planEnabled = true
        } catch (e) {
          planError = (e as { message?: string })?.message || '未知原因'
        }
      }
      return { seed: seedRes.data, planEnabled, planError, planRequested: intervalHours > 0 }
    },
    onSuccess: ({ planEnabled, planError, planRequested }) => {
      if (planEnabled) {
        toast({ title: '种子已添加，监控计划已启用' })
      } else if (planRequested) {
        toast({
          title: '种子已添加，但监控计划启用失败',
          description: `${planError}。可稍后在「监控计划」列表手动补启。`,
          variant: 'destructive',
        })
      } else {
        toast({ title: '种子已添加（未启用监控计划）' })
      }
      invalidateMonitoring()
    },
    onError: fail('添加种子失败'),
  })

  const deleteSeedMutation = useMutation({
    mutationFn: (seedId: number) => projectApi.deleteSeed(seedId),
    onSuccess: () => {
      toast({ title: '种子已删除，关联计划一并移除' })
      setSelectedSeedIds((ids) => ids.filter((id) => id !== deleteSeedMutation.variables))
      invalidateMonitoring()
    },
    onError: fail('删除种子失败'),
  })

  // 种子收集：把选中/全部 live-capable 种子排入队列，后台 worker 串行慢速执行
  const collectMutation = useMutation({
    mutationFn: ({ ids, all }: { ids?: number[]; all?: boolean }) =>
      seedCollectionApi.collect(idNum, ids, all),
    onSuccess: (res) => {
      const d = res.data
      const skipped = d?.skipped ?? []
      toast({
        title: `已入队 ${d?.enqueued ?? 0} 个收集任务`,
        description: skipped.length
          ? `跳过 ${skipped.length} 个：${skipped.slice(0, 5).join('、')}${skipped.length > 5 ? ' …' : ''}`
          : undefined,
      })
      setSelectedSeedIds([])
      queryClient.invalidateQueries({ queryKey: ['project-seed-collect-jobs', idNum] })
      queryClient.invalidateQueries({ queryKey: ['project-cruise-status', idNum] })
    },
    onError: fail('发起收集失败'),
  })

  const handleCollectAll = async () => {
    const ok = await confirm({
      title: '收集全部种子？',
      description: '将对全部 域名/公司(ICP)/证书组织 种子排队收集，串行慢速执行。',
      confirmText: '全部收集',
      cancelText: '取消',
    })
    if (!ok) return
    collectMutation.mutate({ all: true })
  }

  // 种子重建计划：预览拿一次性 token → 确认执行。重建会删除该种子关联的计划与
  // 批次后按新参数重建，所以先预览影响面（后端 15 分钟 token 防误触）。
  const openRestartDialog = async (seed: Seed) => {
    setRestartSeed(seed)
    setRestartPreview(null)
    setRestartInterval('24')
    setRestartLoading(true)
    try {
      const res = await seedsApi.restartPreview(seed.id, {})
      setRestartPreview(res.data ?? null)
      if (res.data?.interval_hours) setRestartInterval(String(res.data.interval_hours))
    } catch (e) {
      toast({ title: '预览重建失败', description: (e as Error).message, variant: 'destructive' })
      setRestartSeed(null)
    } finally {
      setRestartLoading(false)
    }
  }

  const refreshRestartPreview = async () => {
    if (!restartSeed) return
    setRestartLoading(true)
    try {
      const res = await seedsApi.restartPreview(restartSeed.id, {
        interval_hours: Math.max(1, Number(restartInterval) || 24),
      })
      setRestartPreview(res.data ?? null)
    } catch (e) {
      toast({ title: '预览重建失败', description: (e as Error).message, variant: 'destructive' })
    } finally {
      setRestartLoading(false)
    }
  }

  const confirmRestart = async () => {
    if (!restartSeed || !restartPreview) return
    const ok = await confirm({
      title: `重建「${restartSeed.value}」的监控计划？`,
      description: `将删除 ${restartPreview.plans.length} 个计划、${restartPreview.runs} 个批次、${restartPreview.run_targets} 个执行单元，然后按每 ${restartPreview.interval_hours} 小时重建。`,
      confirmText: '重建',
      destructive: true,
    })
    if (!ok) return
    setRestartLoading(true)
    try {
      await seedsApi.restart(restartSeed.id, restartPreview.token)
      toast({ title: '监控计划已重建' })
      setRestartSeed(null)
      setRestartPreview(null)
      invalidateMonitoring()
    } catch (e) {
      toast({ title: '重建失败', description: (e as Error).message, variant: 'destructive' })
    } finally {
      setRestartLoading(false)
    }
  }

  // 批量添加种子：每行一个值，逐条入库并返回状态（重复/非法不中断整批）。
  const submitBatch = async () => {
    const values = batchText
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (values.length === 0) return
    setBatchSubmitting(true)
    try {
      const res = await seedsApi.createBatch({
        project_id: idNum,
        items: values.map((value) => ({ kind: batchKind, value })),
      })
      setBatchResult(res.data ?? null)
      invalidateMonitoring()
      if (res.data) {
        toast({
          title: `批量添加完成：新建 ${res.data.created} 个`,
          description: [
            res.data.duplicate ? `重复 ${res.data.duplicate}` : '',
            res.data.invalid ? `非法 ${res.data.invalid}` : '',
            res.data.failed ? `失败 ${res.data.failed}` : '',
          ]
            .filter(Boolean)
            .join(' · ') || undefined,
        })
      }
    } catch (e) {
      toast({ title: '批量添加失败', description: (e as Error).message, variant: 'destructive' })
    } finally {
      setBatchSubmitting(false)
    }
  }

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


  const seedColumns = buildSeedColumns({
    domainCountMap,
    planBySeedId: new Map(plans.map((p) => [p.seed_id, p])),
    confirm,
    deleteSeedMutation,
    onRestart: (seed) => void openRestartDialog(seed),
  })

  const seedRowSelection: TableProps<Seed>['rowSelection'] = {
    selectedRowKeys: selectedSeedIds,
    onChange: (keys) => setSelectedSeedIds(keys.map(Number).filter((n) => Number.isFinite(n))),
    columnWidth: 48,
  }

  const planColumns = buildPlanColumns({ confirm, updatePlanMutation, triggerPlanMutation, deletePlanMutation })
  const runColumns = buildRunColumns({ executeRunMutation })

  if (!validId) {
    return (
      <Card>
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-10">
          项目 ID 不合法
          <Link to="/projects">
            <Button size="small">返回项目列表</Button>
          </Link>
        </div>
      </Card>
    )
  }

  if (projectQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton loading active title={false} paragraph={{ rows: 1 }} />
        <div className="grid gap-4 md:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} loading active title={false} paragraph={{ rows: 1 }} />
          ))}
        </div>
        <Skeleton loading active title={false} paragraph={{ rows: 6 }} />
      </div>
    )
  }

  if (!project) {
    return (
      <Card>
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-10">
          <AlertTriangle className="text-destructive h-8 w-8" />
          {projectQuery.isError ? '项目加载失败' : '项目不存在'}
          <Link to="/projects">
            <Button size="small">返回项目列表</Button>
          </Link>
        </div>
      </Card>
    )
  }

  const projectPath = `/assets?project_id=${project.id}`
  const topologyPath = `/topology?project_id=${project.id}`

  return (
    <div className="space-y-4">
      <ProjectAssessmentCard projectId={idNum} />
      <Card styles={{ body: { padding: '12px 16px' } }}>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold">采集详情</h2>
          <Link to="/enterprise">
            <Button size="small">企业身份页</Button>
          </Link>
        </div>
        <CollectOverviewCard projectId={idNum} canEdit />
      </Card>
      {/* 顶部：面包屑 + 项目身份 + 操作 */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Link to="/projects" aria-label="返回项目列表">
            <Button type="text" icon={<ArrowLeft className="h-5 w-5" />} />
          </Link>
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
              <Tag className={badgeCls(project.collection_paused ? 'warning' : 'success')}>
                {project.collection_paused ? '已暂停' : '采集中'}
              </Tag>
            </div>
            <p className="text-muted-foreground mt-1 font-mono text-sm">
              {project.code} · {regionLabel(project.region)}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Link to={projectPath}>
            <Button size="small" icon={<Database className="h-4 w-4" />}>
              项目资产
            </Button>
          </Link>
          <Button size="small" icon={<Pencil className="h-4 w-4" />} onClick={() => setEditOpen(true)}>
            编辑资料
          </Button>
          {/* 图标上传走隐藏 input + 按钮触发，入口收在「更多」里 */}
          <input
            ref={iconInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0]
              if (file) uploadIconMutation.mutate(file)
              e.currentTarget.value = ''
            }}
          />
          <Button
            size="small"
            type={project.collection_paused ? 'primary' : 'default'}
            icon={project.collection_paused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            disabled={pauseMutation.isPending}
            onClick={() => pauseMutation.mutate(!project.collection_paused)}
          >
            {project.collection_paused ? '恢复采集' : '暂停采集'}
          </Button>
          <Dropdown
            trigger={['click']}
            menu={{ items: [
              { key: 'report', icon: <FileText className="h-4 w-4" />, label: '信息收集报告', onClick: () => setReportOpen(true) },
              { key: 'topology', icon: <Radio className="h-4 w-4" />, label: '资产星图', onClick: () => navigate(topologyPath) },
              { key: 'vulns', icon: <FileText className="h-4 w-4" />, label: '查看漏洞', onClick: () => navigate(`/vulnerabilities?project_id=${project.id}`) },
              { key: 'icon', icon: <ImagePlus className="h-4 w-4" />, label: '上传图标', onClick: () => iconInputRef.current?.click() },
              ...(project.icon_sha256 ? [{
                key: 'icon-remove',
                icon: <ImageOff className="h-4 w-4" />,
                label: '移除图标',
                onClick: () => clearIconMutation.mutate(),
              }] : []),
            ] }}
          >
            <Button size="small" icon={<ChevronDown className="h-4 w-4" />}>
              更多
            </Button>
          </Dropdown>
          <Button danger type="text" size="small" icon={<Trash2 className="h-4 w-4" />} onClick={handleDeleteProject}>
            删除项目
          </Button>
        </div>
      </div>

      {/* 删除项目：输项目编码确认（与列表页共用 ProjectDeleteModal，后端同样校验，双保险） */}
      <ProjectDeleteModal
        project={project ? { id: project.id, name: project.name, code: project.code } : null}
        open={deleteOpen && !!project}
        onClose={() => setDeleteOpen(false)}
        onDeleted={() => navigate('/projects')}
      />

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
            <SectionHeader
              title="关联任务"
              description="归属于本项目的扫描任务；任务结果会自动并入项目资产。"
              action={
                <div className="flex items-center gap-2">
                  <Button
                    type="text"
                    size="small"
                    onClick={() => tasksQuery.refetch()}
                    disabled={tasksQuery.isFetching}
                  >
                    <RefreshCw
                      className={cn('mr-2 h-4 w-4', tasksQuery.isFetching && 'animate-spin')}
                    />
                    刷新
                  </Button>
                  <Link to={`/tasks/new?project_id=${project.id}`}>
                    <Button type="primary" size="small">
                      <Plus className="mr-2 h-4 w-4" />
                      新建任务
                    </Button>
                  </Link>
                </div>
              }
            />
            <div className="mt-4">
              {tasksQuery.isLoading ? (
                <Skeleton loading active title={false} paragraph={{ rows: 3 }} />
              ) : tasks.length === 0 ? (
                <div className="text-muted-foreground flex flex-col items-center gap-3 py-6 text-sm">
                  <ListTodo className="h-8 w-8 opacity-40" />
                  <p>本项目还没有任务</p>
                  <Link to={`/tasks/new?project_id=${project.id}`}>
                    <Button size="small">
                      <Plus className="mr-2 h-4 w-4" />
                      新建任务
                    </Button>
                  </Link>
                </div>
              ) : (
                <>
                  <Table<Task>
                    columns={taskColumns}
                    dataSource={tasks}
                    rowKey="id"
                    pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
                  />
                  {tasksTotal > tasks.length && (
                    <p className="text-muted-foreground pt-3 text-xs">
                      共 {tasksTotal} 个任务，显示最近 {tasks.length} 个
                    </p>
                  )}
                </>
              )}
            </div>
          </Card>

          <DiscoveryCandidatesPanel projectId={project.id} />

          <Card>
            <SectionHeader
              title="监控种子"
              description="种子决定持续监控的范围；暂停项目后，种子保留但不会到期执行。"
              action={
                <span className="flex gap-2">
                  <Button
                    size="small"
                    onClick={() => {
                      setBatchOpen(true)
                      setBatchResult(null)
                      setBatchText('')
                    }}
                  >
                    批量添加
                  </Button>
                  <Button type="primary" size="small" onClick={() => setSeedOpen(true)}>
                    <Plus className="mr-2 h-4 w-4" />
                    添加种子
                  </Button>
                </span>
              }
            />
            <div className="mt-4">
              {seedsQuery.isLoading ? (
                <Skeleton loading active title={false} paragraph={{ rows: 3 }} />
              ) : seeds.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">
                  还没有种子，先添加一个域名或网段。
                </p>
              ) : (
                <>
                  <div className="mb-3 flex flex-wrap items-center gap-2">
                    <Button
                      type="primary"
                      size="small"
                      disabled={selectedSeedIds.length === 0}
                      loading={collectMutation.isPending && collectMutation.variables?.all !== true}
                      onClick={() => collectMutation.mutate({ ids: selectedSeedIds })}
                    >
                      收集{selectedSeedIds.length > 0 ? `（${selectedSeedIds.length}）` : ''}
                    </Button>
                    <Button
                      size="small"
                      loading={collectMutation.isPending && collectMutation.variables?.all === true}
                      onClick={handleCollectAll}
                    >
                      全部收集
                    </Button>
                    <span className="text-muted-foreground text-xs">
                      {selectedSeedIds.length > 0
                        ? '对选中种子发起一轮收集'
                        : '勾选种子后可单独发起收集'}
                    </span>
                  </div>
                  <Table<Seed>
                    columns={seedColumns}
                    dataSource={seeds}
                    rowKey="id"
                    rowSelection={seedRowSelection}
                    pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
                  />
                </>
              )}
            </div>
          </Card>

          <GitHubMonitorPanel projectId={project.id} />

          <Card>
            <SectionHeader
              title="监控计划"
              description="每个种子按固定间隔生成治理批次；开关只影响该计划。"
            />
            <div className="mt-4">
              {plansQuery.isLoading ? (
                <Skeleton loading active title={false} paragraph={{ rows: 3 }} />
              ) : plans.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">暂无监控计划</p>
              ) : (
                <Table<Plan>
                  columns={planColumns}
                  dataSource={plans}
                  rowKey="id"
                  pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
                />
              )}
            </div>
          </Card>

          <Card>
            <SectionHeader
              title="执行批次"
              description="每次计划到期或手动触发都会生成一个批次，批次里是待探测的目标。"
              action={
                <Button
                  type="text"
                  size="small"
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
            <div className="mt-4">
              {runsQuery.isLoading ? (
                <Skeleton loading active title={false} paragraph={{ rows: 3 }} />
              ) : runs.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-sm">
                  暂无执行批次，触发一个计划即可生成。
                </p>
              ) : (
                <Table<Run>
                  columns={runColumns}
                  dataSource={runs}
                  rowKey="id"
                  pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
                />
              )}
            </div>
          </Card>
        </div>

        {/* 右：项目资料 + 巡航/队列状态（sticky 吸顶，滚动时右侧始终有内容） */}
        <div className="space-y-4 xl:sticky xl:top-4 xl:self-start">
          <Card>
            <SectionHeader title="项目资料" description="项目的基本信息与采集状态。" />
            <div className="divide-y">
              <InfoRow label="项目编码">
                <span className="font-mono">{project.code}</span>
              </InfoRow>
              <InfoRow label="地区">{regionLabel(project.region)}</InfoRow>
              <InfoRow label="采集周期">{project.cycle_interval_days} 天</InfoRow>
              <InfoRow label="采集状态">
                <Tag className={badgeCls(project.collection_paused ? 'warning' : 'success')}>
                  {project.collection_paused ? '已暂停' : '采集中'}
                </Tag>
              </InfoRow>
              {project.collection_paused && (
                <InfoRow label="暂停原因">{project.collection_pause_reason || '—'}</InfoRow>
              )}
              <InfoRow label="主页">
                {project.homepage_url ? (
                  <a
                    href={safeExternalURL(project.homepage_url) ?? undefined}
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
            </div>
          </Card>

          <Card>
            <SectionHeader
              title="巡航概览"
              description="自动发现与站点巡检的最新进展。"
            />
            {!cruiseStatusQuery.isError && (
              <div className="mt-3 grid grid-cols-2 gap-2">
                {cruiseStatusQuery.isLoading || !cruise ? (
                  <Skeleton
                    className="col-span-2"
                    active
                    title={false}
                    paragraph={{ rows: 4 }}
                  />
                ) : (
                  <>
                    <MiniStat
                      className="col-span-2"
                      label="最近发现轮"
                      value={
                        cruise.discovery
                          ? `${fmtDate(cruise.discovery.ran_at)} · 新增 ${cruise.discovery.new_count}`
                          : '尚未运行'
                      }
                      tone={cruise.discovery ? 'primary' : undefined}
                    />
                    <MiniStat
                      label="待处理候选"
                      value={cruise.watch.candidates_pending}
                      tone={cruise.watch.candidates_pending > 0 ? 'primary' : undefined}
                    />
                    <MiniStat label="收集进行中" value={cruise.watch.collect_active} />
                    <MiniStat label="证书透明" value={cruise.discovery?.from_ctlog ?? 0} />
                    <MiniStat label="测绘引擎" value={cruise.discovery?.from_engines ?? 0} />
                    <MiniStat label="站点可达" value={cruise.watch.reachable} />
                    <MiniStat label="24h 已查" value={cruise.watch.checked_24h} />
                    <MiniStat label="累计变更" value={cruise.watch.changed_total} />
                  </>
                )}
              </div>
            )}
          </Card>

          <Card>
            <SectionHeader
              title="种子构成"
              description="监控范围按种子类型拆解；覆盖站点为种子解析出的实际站点数。"
            />
            <div className="mt-3">
              {seedsQuery.isLoading ? (
                <Skeleton loading active title={false} paragraph={{ rows: 3 }} />
              ) : seeds.length === 0 ? (
                <p className="text-muted-foreground py-4 text-center text-sm">
                  添加种子后这里会展示监控范围的构成。
                </p>
              ) : (
                <div className="divide-y">
                  {seedBreakdown.entries.map(([kind, e]) => (
                    <div key={kind} className="flex items-center justify-between gap-3 py-2 text-sm">
                      <span className="flex items-center gap-2">
                        <Tag className={badgeCls('outline')}>{seedKindLabel[kind]}</Tag>
                      </span>
                      <span className="text-right tabular-nums">
                        <span className="font-medium">{e.count}</span>
                        <span className="text-muted-foreground ml-2 text-xs">
                          覆盖 {e.sites} 站点
                        </span>
                      </span>
                    </div>
                  ))}
                  <div className="text-muted-foreground pt-2 text-xs">
                    共 {seeds.length} 个种子 · 解析出 {seedBreakdown.totalSites} 个站点
                  </div>
                </div>
              )}
            </div>
          </Card>

          <Card>
            <SectionHeader
              title="收集队列"
              description="种子收集作业排队串行执行；进行中时每 10 秒刷新。"
              action={
                collectActive > 0 ? <Badge count={collectActive} size="small" /> : undefined
              }
            />
            <Table<SeedCollectionJob>
              className="mt-3"
              columns={jobColumns}
              dataSource={collectJobs}
              rowKey="id"
              loading={collectJobsQuery.isLoading}
              size="small"
              pagination={{ pageSize: 5, hideOnSinglePage: true, showSizeChanger: false }}
            />
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

      {/* 种子重建计划：预览影响面 → 确认执行（一次性 token，15 分钟有效） */}
      <Modal
        open={restartSeed !== null}
        onCancel={() => {
          setRestartSeed(null)
          setRestartPreview(null)
        }}
        title={restartSeed ? `重建监控计划 · ${restartSeed.value}` : '重建监控计划'}
        width={560}
        footer={
          <div className="flex justify-end gap-2">
            <Button
              onClick={() => {
                setRestartSeed(null)
                setRestartPreview(null)
              }}
            >
              取消
            </Button>
            <Button onClick={refreshRestartPreview} loading={restartLoading}>
              重新预览
            </Button>
            <Button
              type="primary"
              danger
              disabled={!restartPreview}
              loading={restartLoading}
              onClick={confirmRestart}
            >
              确认重建
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">间隔（小时）</span>
            <Input
              className="w-28"
              type="number"
              min={1}
              max={720}
              value={restartInterval}
              onChange={(e) => setRestartInterval(e.target.value)}
            />
            <span className="text-muted-foreground text-xs">
              调整后点「重新预览」刷新影响面
            </span>
          </div>
          {restartPreview && (
            <div className="rounded-md border bg-muted/20 p-3 text-sm">
              <p className="text-muted-foreground mb-1 text-xs">预览（一次性 token 已生成，15 分钟内有效）：</p>
              <p>
                将删除 <b>{restartPreview.plans.length}</b> 个计划、<b>{restartPreview.runs}</b> 个批次、
                <b> {restartPreview.run_targets}</b> 个执行单元，然后按每{' '}
                <b>{restartPreview.interval_hours}</b> 小时重建。
              </p>
            </div>
          )}
        </div>
      </Modal>

      {/* 批量添加种子：每行一个值，逐条入库（重复/非法不中断整批） */}
      <Modal
        open={batchOpen}
        onCancel={() => setBatchOpen(false)}
        title="批量添加种子"
        width={560}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setBatchOpen(false)}>关闭</Button>
            <Button
              type="primary"
              loading={batchSubmitting}
              disabled={!batchText.trim()}
              onClick={submitBatch}
            >
              提交
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">类型</span>
            <Select
              className="w-40"
              value={batchKind}
              onChange={(v) => setBatchKind(v)}
              options={Object.entries(seedKindLabel).map(([value, label]) => ({ value, label }))}
            />
          </div>
          <Input.TextArea
            rows={6}
            placeholder={'每行一个种子值，例如：\nexample.com\nfoo.example.org'}
            value={batchText}
            onChange={(e) => setBatchText(e.target.value)}
          />
          {batchResult && (
            <div className="rounded-md border bg-muted/20 p-3 text-sm">
              <p>
                共 {batchResult.requested} 条：新建 <b>{batchResult.created}</b> · 重复{' '}
                {batchResult.duplicate} · 非法 {batchResult.invalid} · 失败 {batchResult.failed}
              </p>
              {batchResult.items
                .filter((it) => it.status !== 'created' && it.status !== 'created_plan_failed')
                .slice(0, 8)
                .map((it, i) => (
                  <p key={i} className="text-muted-foreground text-xs">
                    {it.value}: {it.status}
                    {it.error ? `（${it.error}）` : ''}
                  </p>
                ))}
            </div>
          )}
        </div>
      </Modal>

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

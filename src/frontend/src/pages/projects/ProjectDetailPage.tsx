import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
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
import { Badge, Button, Card, Dropdown, Input, Modal, Skeleton, Table, Tag } from 'antd'
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
import {
  buildPlanColumns,
  buildRunColumns,
  buildSeedColumns,
  fmtDate,
  jobColumns,
  taskColumns,
} from './components/columns'
import AddSeedDialog from './components/AddSeedDialog'
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
    <Card styles={{ body: { padding: 16 } }}>
      <div className="flex items-center gap-3">
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
  const [confirmCode, setConfirmCode] = useState('')
  const pendingCodeRef = useRef('')

  const [editOpen, setEditOpen] = useState(false)
  const [seedOpen, setSeedOpen] = useState(false)
  const [reportOpen, setReportOpen] = useState(false)
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

  // 永久删除项目：危险区按钮触发，输项目编码确认；后端级联清任务/资产/巡航等全部归属数据
  const deleteMutation = useMutation({
    mutationFn: (confirm_code: string) => projectApi.delete(idNum, confirm_code),
    onSuccess: (res) => {
      const d = res.data
      toast({
        title: `项目「${d?.name ?? project?.name ?? ''}」已删除`,
        description: `站点 ${d?.sites ?? 0} · 原始记录 ${d?.records ?? 0} · 任务 ${d?.tasks ?? 0} · 扫描结果 ${d?.scan_results ?? 0} · 巡航 ${d?.cruise_tasks ?? 0}`,
      })
      queryClient.removeQueries({ queryKey: ['project', idNum] })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      queryClient.invalidateQueries({ queryKey: ['asset-projects'] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      navigate('/projects')
    },
    onError: (e) => {
      toast({ title: '删除项目失败', description: (e as Error).message, variant: 'destructive' })
    },
  })

  // 列表页「删除」深链：?delete=1 且项目已加载时自动弹确认框
  useEffect(() => {
    if (searchParams.get('delete') === '1' && project && !deleteOpen) {
      setConfirmCode('')
      pendingCodeRef.current = project.code
      setDeleteOpen(true)
      setSearchParams({}, { replace: true })
    }
  }, [searchParams, project, deleteOpen, setSearchParams])

  const handleDeleteProject = () => {
    if (!project) return
    // 输码弹窗内已含完整范围警告与强确认（输项目编码），不再叠加一道 confirm
    setConfirmCode('')
    pendingCodeRef.current = project.code
    setDeleteOpen(true)
  }

  const confirmDelete = () => {
    if (confirmCode.trim() !== pendingCodeRef.current) {
      toast({ title: '项目编码不一致，未删除', variant: 'destructive' })
      return
    }
    deleteMutation.mutate(confirmCode.trim())
    setDeleteOpen(false)
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
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-16">
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
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-16">
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

      {/* 删除项目：输项目编码确认（后端同样校验，双保险） */}
      <Modal
        open={deleteOpen}
        title={`永久删除项目「${project?.name ?? ''}」`}
        onCancel={() => setDeleteOpen(false)}
        width={480}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setDeleteOpen(false)}>取消</Button>
            <Button
              danger
              type="primary"
              disabled={confirmCode.trim() !== pendingCodeRef.current}
              loading={deleteMutation.isPending}
              onClick={confirmDelete}
            >
              永久删除
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">
          将删除编码 <span className="font-mono text-foreground">{pendingCodeRef.current}</span>{' '}
          归属的全部数据：站点、原始记录、种子、巡航计划、任务（含扫描结果与队列作业）、巡航任务、关系图谱、企业身份、ICP
          备案。<span className="text-destructive">此操作不可恢复。</span>
        </p>
        <div className="mt-3">
          <label className="text-sm font-medium" htmlFor="project-delete-confirm">
            请输入项目编码 <span className="font-mono text-destructive">{pendingCodeRef.current}</span> 确认：
          </label>
          <Input
            id="project-delete-confirm"
            className="mt-1.5"
            value={confirmCode}
            onChange={(e) => setConfirmCode(e.target.value)}
            placeholder={pendingCodeRef.current}
            autoComplete="off"
          />
        </div>
      </Modal>

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
                <Button type="primary" size="small" onClick={() => setSeedOpen(true)}>
                  <Plus className="mr-2 h-4 w-4" />
                  添加种子
                </Button>
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

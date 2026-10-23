import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  ChevronDown,
  ChevronRight,
  Database,
  ExternalLink,
  FileText,
  ImageOff,
  ImagePlus,
  Layers,
  ListTodo,
  Loader2,
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
import { Badge, Button, Card, Dropdown, Input, Modal, Progress, Skeleton, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import {
  projectApi,
  seedKindLabel,
  type Plan,
  type ProjectInput,
  type Run,
  type Seed,
  type SeedKind,
  planTriggerModeLabel,
  type PlanTriggerMode,
} from '@/api/projects'
import AddSeedDialog from './components/AddSeedDialog'
import {
  seedCollectionApi,
  type SeedCollectionJob,
  type SeedCollectionJobStatus,
} from '@/api/seedCollection'
import { taskApi, type Task } from '@/api/tasks'
import { ProjectFormDialog } from '@/components/projects/ProjectFormDialog'
import { DiscoveryCandidatesPanel } from '@/components/projects/DiscoveryCandidatesPanel'
import { ReportGenerateDialog } from '@/components/reports/ReportGenerateDialog'
import { reportApi, type ReportProfile } from '@/api/reports'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, formatNumber } from '@/lib/utils'
import { statusTagClass } from '@/components/ui/StatusTag'

const regionLabel = (region: string) => {
  if (!region) return '—'
  if (region === 'domestic') return '国内'
  if (region === 'intl' || region === 'overseas') return '国际'
  return region
}

const fmtDate = (v?: string | null) => (v ? formatDate(v) : '—')

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass
const runStatusMeta: Record<Run['status'], { label: string; variant: BadgeVariant }> = {
  queued: { label: '排队中', variant: 'secondary' },
  running: { label: '执行中', variant: 'info' },
  partial: { label: '部分完成', variant: 'warning' },
  done: { label: '已完成', variant: 'success' },
  failed: { label: '失败', variant: 'destructive' },
}

const taskStatusMeta: Record<string, { label: string; variant: BadgeVariant }> = {
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

const collectJobStatusMeta: Record<
  SeedCollectionJobStatus,
  { label: string; variant: BadgeVariant }
> = {
  queued: { label: '待处理', variant: 'secondary' },
  running: { label: '处理中', variant: 'info' },
  done: { label: '完成', variant: 'success' },
  error: { label: '失败', variant: 'destructive' },
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
  // 种子表勾选（收集入口）+ 收集队列折叠态
  const [selectedSeedIds, setSelectedSeedIds] = useState<number[]>([])
  const [queueOpen, setQueueOpen] = useState(false)

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
      toast({
        title: `已入队 ${d?.enqueued ?? 0} 个收集任务`,
        description: d?.skipped?.length
          ? `跳过 ${d.skipped.length} 个：${d.skipped.join('、')}`
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

  const taskColumns: TableProps<Task>['columns'] = [
    {
      title: '任务',
      dataIndex: 'name',
      key: 'name',
      render: (_, task) => <div className="max-w-[220px] truncate font-medium">{task.name}</div>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (_, task) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {taskTypeLabel[task.type] || task.type}
        </span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (_, task) => {
        const meta = taskStatusMeta[task.status] ?? {
          label: task.status,
          variant: 'outline' as const,
        }
        return <Tag className={badgeCls(meta.variant)}>{meta.label}</Tag>
      },
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (_, task) => (
        <div className="flex min-w-[110px] items-center gap-2">
          <Progress percent={task.progress} showInfo={false} strokeWidth={6} className="w-16" />
          <span className="text-muted-foreground w-9 tabular-nums text-xs">{task.progress}%</span>
        </div>
      ),
    },
    {
      title: '目标',
      dataIndex: 'targets',
      key: 'targets',
      render: (_, task) => <span className="text-muted-foreground text-xs">{task.targets.length} 个</span>,
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (_, task) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {fmtDate(task.createdAt)}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      align: 'right',
      render: (_, task) => (
        <div className="flex justify-end">
          <Link to={`/tasks/${task.id}`}>
            <Button type="text" size="small">
              查看
            </Button>
          </Link>
        </div>
      ),
    },
  ]

  const seedColumns: TableProps<Seed>['columns'] = [
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      render: (_, seed) => (
        <Tag className={badgeCls('outline')}>{seedKindLabel[seed.kind] || seed.kind}</Tag>
      ),
    },
    {
      title: '种子值',
      dataIndex: 'value',
      key: 'value',
      render: (_, seed) => (
        <div className="max-w-[280px] truncate font-mono text-xs">
          {seed.value}
          {seed.kind === 'domain' && (
            <div className="text-muted-foreground mt-1 font-sans text-[11px]">
              覆盖 {domainCountMap.get(seed.id) ?? 0} 个站点
            </div>
          )}
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (_, seed) => (
        <Tag className={badgeCls(seed.enabled ? 'success' : 'secondary')}>
          {seed.enabled ? '启用' : '停用'}
        </Tag>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (_, seed) => (
        <span className="text-muted-foreground text-xs">{fmtDate(seed.created_at)}</span>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 48,
      render: (_, seed) => (
        <Button
          type="text"
          size="small"
          title="删除种子"
          icon={<Trash2 className="text-destructive size-4" />}
          onClick={async () => {
            if (
              await confirm({
                title: '删除这个种子？',
                description: '种子和它关联的监控计划都会删除，已经产生的批次记录保留。',
                confirmText: '删除',
                destructive: true,
              })
            )
              deleteSeedMutation.mutate(seed.id)
          }}
        />
      ),
    },
  ]

  const seedRowSelection: TableProps<Seed>['rowSelection'] = {
    selectedRowKeys: selectedSeedIds,
    onChange: (keys) => setSelectedSeedIds(keys.map(Number).filter((n) => Number.isFinite(n))),
    columnWidth: 48,
  }

  const jobColumns: TableProps<SeedCollectionJob>['columns'] = [
    {
      title: '种子值',
      dataIndex: 'value',
      key: 'value',
      render: (_, job) => (
        <span className="block max-w-[240px] truncate font-mono text-xs">{job.value}</span>
      ),
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 110,
      render: (_, job) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {seedKindLabel[job.kind as SeedKind] ?? job.kind}
        </span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (_, job) => {
        const meta = collectJobStatusMeta[job.status] ?? {
          label: job.status,
          variant: 'outline' as const,
        }
        return (
          <span className="flex items-center gap-1.5">
            <Tag className={badgeCls(meta.variant)}>
              {job.status === 'running' && <Loader2 className="mr-1 inline size-3 animate-spin" />}
              {meta.label}
            </Tag>
            {job.status === 'done' && (
              <span className="text-muted-foreground text-xs">+{job.found} 候选</span>
            )}
            {job.status === 'error' && (
              <span className="text-muted-foreground max-w-[200px] truncate text-xs" title={job.error}>
                {job.error}
              </span>
            )}
          </span>
        )
      },
    },
  ]

  const planColumns: TableProps<Plan>['columns'] = [
    {
      title: '种子',
      dataIndex: 'seed_value',
      key: 'seed_value',
      render: (_, plan) => <div className="max-w-[220px] truncate font-mono text-xs">{plan.seed_value}</div>,
    },
    {
      title: '间隔',
      dataIndex: 'interval_hours',
      key: 'interval_hours',
      render: (_, plan) => (
        <span className="whitespace-nowrap text-sm">
          {plan.interval_hours} 小时 ·{' '}
          {planTriggerModeLabel[plan.trigger_mode] ?? plan.trigger_mode ?? '固定周期'}
        </span>
      ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (_, plan) => (
        <Switch
          checked={plan.enabled}
          disabled={updatePlanMutation.isPending}
          onChange={(enabled) => updatePlanMutation.mutate({ planId: plan.id, enabled })}
        />
      ),
    },
    {
      title: '下次执行',
      dataIndex: 'next_run_at',
      key: 'next_run_at',
      render: (_, plan) => <span className="text-muted-foreground text-xs">{fmtDate(plan.next_run_at)}</span>,
    },
    {
      title: '上次执行',
      dataIndex: 'last_run_at',
      key: 'last_run_at',
      render: (_, plan) => <span className="text-muted-foreground text-xs">{fmtDate(plan.last_run_at)}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      align: 'right',
      render: (_, plan) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            type="text"
            size="small"
            title="立即触发"
            disabled={triggerPlanMutation.isPending}
            onClick={() => triggerPlanMutation.mutate(plan.id)}
            icon={<Zap className="size-4" />}
          />
          <Button
            type="text"
            size="small"
            title="删除计划"
            icon={<Trash2 className="text-destructive size-4" />}
            onClick={async () => {
              if (
                await confirm({
                  title: '删除这个监控计划？',
                  description: '不会删除种子，只停止按此计划生成批次。',
                  confirmText: '删除',
                  destructive: true,
                })
              )
                deletePlanMutation.mutate(plan.id)
            }}
          />
        </div>
      ),
    },
  ]

  const runColumns: TableProps<Run>['columns'] = [
    {
      title: '批次',
      dataIndex: 'id',
      key: 'id',
      render: (_, run) => <span className="font-mono text-xs">#{run.id}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (_, run) => {
        const meta = runStatusMeta[run.status] ?? {
          label: run.status,
          variant: 'outline' as const,
        }
        return <Tag className={badgeCls(meta.variant)}>{meta.label}</Tag>
      },
    },
    {
      title: '周期开始',
      dataIndex: 'cycle_start',
      key: 'cycle_start',
      render: (_, run) => <span className="text-muted-foreground text-xs">{fmtDate(run.cycle_start)}</span>,
    },
    {
      title: '统计',
      dataIndex: 'stats',
      key: 'stats',
      render: (_, run) => (
        <span className="text-muted-foreground max-w-[240px] truncate text-xs">
          {Object.keys(run.stats ?? {}).length > 0
            ? Object.entries(run.stats)
                .slice(0, 3)
                .map(([k, v]) => `${k}: ${String(v)}`)
                .join(' · ')
            : '—'}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      align: 'right',
      render: (_, run) => (
        <div className="flex justify-end">
          <Button
            size="small"
            disabled={
              executeRunMutation.isPending || run.status === 'done' || run.status === 'failed'
            }
            onClick={() => executeRunMutation.mutate(run.id)}
          >
            <Play className="mr-1 h-3.5 w-3.5" />
            执行
          </Button>
        </div>
      ),
    },
  ]

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
            <Button size="small">
              <Database className="mr-2 h-4 w-4" />
              项目资产
            </Button>
          </Link>
          <Button size="small" onClick={() => setEditOpen(true)}>
            <Pencil className="mr-2 h-4 w-4" />
            编辑资料
          </Button>
          {/* 图标上传走隐藏 input + 按钮触发，样式统一跟 Button，不手抄 */}
          <Button size="small" onClick={() => iconInputRef.current?.click()}>
            <ImagePlus className="mr-2 h-4 w-4" />
            图标
          </Button>
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
          {project.icon_sha256 && (
            <Button
              type="text"
              size="small"
              disabled={clearIconMutation.isPending}
              onClick={() => clearIconMutation.mutate()}
            >
              <ImageOff className="mr-2 h-4 w-4" />
              移除图标
            </Button>
          )}
          <Button
            type={project.collection_paused ? 'primary' : 'default'}
            size="small"
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
            <Button size="small">
              <ChevronDown className="mr-1 h-4 w-4" />
              更多
            </Button>
          </Dropdown>
          <Button danger type="text" size="small" onClick={handleDeleteProject}>
            <Trash2 className="mr-2 h-4 w-4" />
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
                  <div className="mt-4 border-t pt-3">
                    <button
                      type="button"
                      className="flex items-center gap-1 text-sm font-medium"
                      onClick={() => setQueueOpen((v) => !v)}
                    >
                      {queueOpen ? (
                        <ChevronDown className="size-4" />
                      ) : (
                        <ChevronRight className="size-4" />
                      )}
                      收集队列
                      {collectActive > 0 && <Badge count={collectActive} size="small" />}
                      <span className="text-muted-foreground ml-1 text-xs font-normal">
                        最近 {collectJobs.length} 条
                        {collectActive > 0 ? ` · 进行中 ${collectActive}` : ''}
                      </span>
                    </button>
                    {queueOpen && (
                      <Table<SeedCollectionJob>
                        className="mt-2"
                        columns={jobColumns}
                        dataSource={collectJobs}
                        rowKey="id"
                        loading={collectJobsQuery.isLoading}
                        size="small"
                        pagination={{ pageSize: 10, hideOnSinglePage: true, showSizeChanger: false }}
                      />
                    )}
                  </div>
                </>
              )}
            </div>
          </Card>

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

        {/* 右：项目资料（表单式字段） */}
        <div className="space-y-4">
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

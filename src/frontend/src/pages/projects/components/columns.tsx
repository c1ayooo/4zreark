import { Link } from 'react-router-dom'
import { Button, Progress, Switch, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Loader2, Play, Trash2, Zap } from 'lucide-react'
import {
  seedKindLabel,
  planTriggerModeLabel,
  type Plan,
  type Run,
  type Seed,
  type SeedKind,
} from '@/api/projects'
import type { SeedCollectionJob, SeedCollectionJobStatus } from '@/api/seedCollection'
import type { Task } from '@/api/tasks'
import { statusTagClass } from '@/components/ui/StatusTag'
import { useConfirm } from '@/components/common/confirm-provider'
import { formatDate } from '@/lib/utils'

const badgeCls = statusTagClass
export const fmtDate = (v?: string | null) => (v ? formatDate(v) : '—')

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'

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

// 确认框句柄由页面传入，列工厂内部不再挂 hook
type ConfirmFn = ReturnType<typeof useConfirm>

export const taskColumns: TableProps<Task>['columns'] = [
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

export const buildSeedColumns = ({ domainCountMap, confirm, deleteSeedMutation }: {
  domainCountMap: Map<number, number>
  confirm: ConfirmFn
  deleteSeedMutation: { mutate: (seedId: number) => void }
}): TableProps<Seed>['columns'] => [
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

export const jobColumns: TableProps<SeedCollectionJob>['columns'] = [
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

export const buildPlanColumns = ({ confirm, updatePlanMutation, triggerPlanMutation, deletePlanMutation }: {
  confirm: ConfirmFn
  updatePlanMutation: { isPending: boolean; mutate: (v: { planId: number; enabled: boolean }) => void }
  triggerPlanMutation: { isPending: boolean; mutate: (planId: number) => void }
  deletePlanMutation: { isPending: boolean; mutate: (planId: number) => void }
}): TableProps<Plan>['columns'] => [
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

export const buildRunColumns = ({ executeRunMutation }: {
  executeRunMutation: { isPending: boolean; mutate: (runId: number) => void }
}): TableProps<Run>['columns'] => [
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

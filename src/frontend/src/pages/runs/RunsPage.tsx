import { useState } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { Activity, Play, RefreshCw } from 'lucide-react'
import { Button, Card, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { projectApi } from '@/api/projects'
import {
  runApi,
  runStatusLabel,
  runStatusVariant,
  targetStateLabel,
  type RunTarget,
} from '@/api/runs'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'

// stats.targets 可能是数字，也可能是按状态聚合的对象（{done:3, skipped:1}）。
// 直接渲染对象会触发 React #31，这里统一折算成总数。
function targetTotal(stats?: Record<string, unknown>): number | undefined {
  if (!stats) return undefined
  const raw = stats.targets
  if (typeof raw === 'number') return raw
  if (typeof stats.total_targets === 'number') return stats.total_targets
  if (raw && typeof raw === 'object') {
    return Object.values(raw as Record<string, unknown>).reduce<number>(
      (sum, v) => sum + (typeof v === 'number' ? v : Number(v) || 0),
      0
    )
  }
  return undefined
}

const TARGET_STATES = [
  { value: '', label: '全部' },
  { value: 'pending', label: '待执行' },
  { value: 'running', label: '执行中' },
  { value: 'done', label: '完成' },
  { value: 'failed', label: '失败' },
  { value: 'skipped', label: '跳过' },
]

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'default' | 'secondary' | 'destructive' | 'outline') =>
  variant === 'default'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : ''

export default function RunsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')

  const [projectId, setProjectId] = useState('0')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [targetState, setTargetState] = useState('')

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const runs = useQuery({
    queryKey: ['runs', projectId],
    queryFn: () => runApi.list(Number(projectId) || undefined, 100),
  })
  const detail = useQuery({
    queryKey: ['run', selectedId],
    queryFn: () => runApi.detail(selectedId as number),
    enabled: selectedId !== null,
  })
  const targets = useQuery({
    queryKey: ['run-targets', selectedId, targetState],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () => runApi.targets(selectedId as number, targetState || undefined, 200),
    enabled: selectedId !== null,
  })

  const execute = useMutation({
    mutationFn: () => runApi.execute(selectedId as number, 50),
    onSuccess: (res) => {
      const stats = res.data ?? {}
      toast({
        title: '已执行一批目标',
        description:
          Object.entries(stats)
            .map(([k, v]) => `${k}: ${String(v)}`)
            .join(' · ') || '没有待执行目标',
      })
      queryClient.invalidateQueries({ queryKey: ['run', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['run-targets', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['runs'] })
    },
    onError: (e: any) =>
      toast({ title: '执行失败', description: e?.message, variant: 'destructive' }),
  })

  const projectName = (id: number) =>
    projects.data?.data?.find((p) => p.id === id)?.name ?? `#${id}`

  const list = runs.data?.data ?? []
  const run = detail.data?.data?.run
  const targetStats = detail.data?.data?.target_stats ?? {}
  const targetList: RunTarget[] = targets.data?.data ?? []

  const runColumns: TableProps<(typeof list)[number]>['columns'] = [
    {
      title: '批次',
      dataIndex: 'id',
      key: 'id',
      width: 70,
      render: (v: number) => <span className="font-mono text-sm">#{v}</span>,
    },
    {
      title: '项目',
      dataIndex: 'project_id',
      key: 'project_id',
      render: (v: number) => <span className="text-sm">{projectName(v)}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => (
        <Tag className={badgeCls(runStatusVariant(v))}>{runStatusLabel[v] ?? v}</Tag>
      ),
    },
    {
      title: '周期开始',
      dataIndex: 'cycle_start',
      key: 'cycle_start',
      width: 140,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{formatDate(v)}</span>
      ),
    },
    {
      title: '目标',
      key: 'targets',
      width: 90,
      render: (_, r) => <span className="text-sm">{targetTotal(r.stats) ?? '—'}</span>,
    },
  ]

  const targetColumns: TableProps<RunTarget>['columns'] = [
    {
      title: '目标',
      key: 'host_port',
      render: (_, t) => <span className="font-mono text-xs">{t.host}:{t.port}</span>,
    },
    {
      title: '状态',
      dataIndex: 'state',
      key: 'state',
      width: 80,
      render: (v: string) => (
        <Tag className={badgeCls(v === 'failed' ? 'destructive' : 'outline')}>
          {targetStateLabel[v] ?? v}
        </Tag>
      ),
    },
    {
      title: '尝试',
      dataIndex: 'attempts',
      key: 'attempts',
      width: 60,
      render: (v: number) => <span className="text-xs">{v}</span>,
    },
  ]

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">执行记录</h1>
          <p className="text-sm text-muted-foreground">
            治理计划到点后生成的批次；可查看执行单元状态，并对剩余目标手动推进
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select
            className="w-44"
            value={projectId}
            placeholder="全部项目"
            onChange={(v) => setProjectId(v)}
            options={[
              { value: '0', label: '全部项目' },
              ...(projects.data?.data ?? []).map((p) => ({ value: String(p.id), label: p.name })),
            ]}
          />
          <Button onClick={() => runs.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <div className="rounded-md border xl:col-span-3">
          <Table
            columns={runColumns}
            dataSource={list}
            rowKey="id"
            loading={runs.isLoading}
            pagination={false}
            locale={{
              emptyText: (
                <EmptyState
                  title="还没有批次（计划到点或手动触发后会生成）"
                  className="border-0"
                />
              ),
            }}
            onRow={(r) => ({
              onClick: () => setSelectedId(r.id),
              className: 'cursor-pointer' + (selectedId === r.id ? ' bg-muted/60' : ''),
            })}
          />
        </div>

        <Card
          className="xl:col-span-2"
          title={
            <span className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4" />
              {run ? `批次 #${run.id}` : '批次详情'}
            </span>
          }
        >
          <div className="space-y-4">
            {!run && (
              <p className="text-sm text-muted-foreground">
                从左侧选择一个批次，查看执行单元与统计
              </p>
            )}
            {run && (
              <>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <dt className="text-muted-foreground">项目</dt>
                  <dd>{projectName(run.project_id)}</dd>
                  <dt className="text-muted-foreground">计划</dt>
                  <dd className="font-mono">#{run.plan_id}</dd>
                  <dt className="text-muted-foreground">状态</dt>
                  <dd>
                    <Tag className={badgeCls(runStatusVariant(run.status))}>
                      {runStatusLabel[run.status] ?? run.status}
                    </Tag>
                  </dd>
                  <dt className="text-muted-foreground">周期开始</dt>
                  <dd className="text-xs">{formatDate(run.cycle_start)}</dd>
                  <dt className="text-muted-foreground">开始</dt>
                  <dd className="text-xs">{run.started_at ? formatDate(run.started_at) : '—'}</dd>
                  <dt className="text-muted-foreground">结束</dt>
                  <dd className="text-xs">{run.ended_at ? formatDate(run.ended_at) : '—'}</dd>
                </dl>

                <div className="flex flex-wrap gap-2">
                  {Object.entries(targetStats).map(([state, n]) => (
                    <Tag key={state}>
                      {targetStateLabel[state] ?? state} {n}
                    </Tag>
                  ))}
                  {Object.keys(targetStats).length === 0 && (
                    <span className="text-sm text-muted-foreground">暂无执行单元统计</span>
                  )}
                </div>

                {isAdmin && (
                  <Button
                    type="primary"
                    className="w-full"
                    onClick={() => execute.mutate()}
                    disabled={execute.isPending || run.status === 'done' || run.status === 'failed'}
                  >
                    <Play className="mr-2 h-4 w-4" />
                    {execute.isPending ? '执行中…' : '执行剩余目标（50 条）'}
                  </Button>
                )}

                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    {TARGET_STATES.map((s) => (
                      <button
                        key={s.value}
                        className={
                          'rounded-full border px-3 py-1 text-xs ' +
                          (targetState === s.value
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-muted')
                        }
                        onClick={() => setTargetState(s.value)}
                      >
                        {s.label}
                      </button>
                    ))}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {targetList.length} 条
                    </span>
                  </div>
                  <div className="max-h-[360px] overflow-auto rounded-md border">
                    <Table
                      columns={targetColumns}
                      dataSource={targetList}
                      rowKey="id"
                      loading={targets.isLoading}
                      pagination={false}
                      size="small"
                      locale={{
                        emptyText: <EmptyState title="没有执行单元" className="border-0 py-6" />,
                      }}
                    />
                  </div>
                </div>
              </>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

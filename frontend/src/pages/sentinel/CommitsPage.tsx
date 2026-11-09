import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Drawer, Progress, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Link, useSearchParams } from 'react-router-dom'
import { History } from 'lucide-react'
import { sentinelApi, SentinelCommit, SentinelRun, SentinelRunEvent } from '@/api/sentinel'
import { formatDate } from '@/lib/utils'
import { fmtRelative } from './audit/shared'

const statusMeta: Record<string, { label: string; color: string }> = {
  pending: { label: '待判定', color: 'default' },
  judged: { label: '已判定', color: 'blue' },
  skipped: { label: '已跳过', color: 'default' },
  failed: { label: '判定失败', color: 'red' },
}

const severityColor: Record<string, string> = {
  critical: 'magenta',
  high: 'red',
  medium: 'orange',
  low: 'gold',
  info: 'default',
}

const runStatusMeta: Record<string, { label: string; color: string }> = {
  running: { label: '判定中', color: 'processing' },
  completed: { label: '已完成', color: 'success' },
  failed: { label: '失败', color: 'error' },
  cancelled: { label: '已取消', color: 'default' },
  pending: { label: '排队中', color: 'default' },
}

const eventKindMeta: Record<string, { label: string; color: string }> = {
  judge_start: { label: '开始', color: 'blue' },
  judge_done: { label: '完成', color: 'green' },
  judge_skipped: { label: '跳过', color: 'default' },
  judge_failed: { label: '失败', color: 'red' },
}

/** 判定批次卡：实时展示判定过程（judge_start → judge_done/skipped/failed）。 */
function JudgeRunsCard({ onOpenEvents }: { onOpenEvents: (run: SentinelRun) => void }) {
  const runsQuery = useQuery({
    queryKey: ['sentinel-runs', 'judge'],
    queryFn: () => sentinelApi.runs({ run_type: 'judge', limit: 8 }),
    refetchInterval: 5000,
  })
  const runs = runsQuery.data ?? []
  if (runs.length === 0) return null

  return (
    <Card
      size="small"
      className="border-border/60"
      title={
        <span className="flex items-center gap-2 text-sm">
          <History className="h-4 w-4" /> 判定批次
          <span className="text-xs font-normal text-muted-foreground">实时刷新</span>
        </span>
      }
    >
      <div className="space-y-2">
        {runs.map((run) => {
          const meta = runStatusMeta[run.status] ?? runStatusMeta.pending
          return (
            <div key={run.id} className="flex items-center gap-3 rounded-md border border-border/40 px-3 py-2 text-sm">
              <Tag color={meta.color}>{meta.label}</Tag>
              <span className="font-mono text-xs text-muted-foreground">#{run.id}</span>
              <span className="text-xs text-muted-foreground">
                处理 {run.processed}/{run.total}
                {run.failed > 0 ? ` · 失败 ${run.failed}` : ''}
              </span>
              <span className="ml-auto text-xs text-muted-foreground">{fmtRelative(run.created_at)}</span>
              <Button size="small" type="link" onClick={() => onOpenEvents(run)}>
                过程
              </Button>
            </div>
          )
        })}
      </div>
    </Card>
  )
}

/** 批次事件抽屉：run 进行中时 3s 轮询事件流。 */
function RunEventsDrawer({ run, onClose }: { run: SentinelRun | null; onClose: () => void }) {
  const eventsQuery = useQuery({
    queryKey: ['sentinel-run-events', run?.id],
    queryFn: () => sentinelApi.runEvents(run!.id, 0, 100),
    enabled: !!run,
    refetchInterval: run && (run.status === 'running' || run.status === 'pending') ? 3000 : false,
  })

  const payloadOf = (ev: SentinelRunEvent): Record<string, unknown> =>
    typeof ev.payload === 'object' && ev.payload !== null ? (ev.payload as Record<string, unknown>) : {}

  return (
    <Drawer title={`判定批次 #${run?.id ?? ''} 事件流`} open={!!run} onClose={onClose} width={520}>
      <div className="space-y-3">
        {(eventsQuery.data ?? []).map((ev) => {
          const meta = eventKindMeta[ev.kind]
          const payload = payloadOf(ev)
          return (
            <div key={ev.id} className="rounded-md border border-border/40 px-3 py-2">
              <div className="flex items-center gap-2">
                {meta ? <Tag color={meta.color}>{meta.label}</Tag> : <Tag>{ev.kind}</Tag>}
                <span className="text-xs text-muted-foreground">{formatDate(ev.created_at)}</span>
              </div>
              <div className="mt-1 text-sm">{ev.message}</div>
              {ev.kind === 'judge_done' && typeof payload.confidence === 'number' && (
                <div className="mt-1 flex flex-wrap gap-2 text-xs">
                  <Tag color={payload.is_security_fix ? 'red' : 'default'}>
                    {payload.is_security_fix ? '安全修复' : '非安全修复'}
                  </Tag>
                  <Tag>{String(payload.vuln_class ?? '')}</Tag>
                  <Tag color={severityColor[String(payload.severity)] ?? 'default'}>{String(payload.severity ?? '')}</Tag>
                  <span className="text-muted-foreground">置信度 {Math.round((payload.confidence as number) * 100)}%</span>
                </div>
              )}
            </div>
          )
        })}
        {eventsQuery.isLoading && <div className="text-sm text-muted-foreground">加载事件…</div>}
      </div>
    </Drawer>
  )
}

export default function SentinelCommitsPage() {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)
  const [eventsRun, setEventsRun] = useState<SentinelRun | null>(null)

  const repoID = params.get('repo_id') ?? ''
  const status = params.get('status') ?? ''
  const onlyFix = params.get('security_fix') === 'true'

  const reposQuery = useQuery({
    queryKey: ['sentinel-repos', ''],
    queryFn: () => sentinelApi.listRepos(),
  })

  const commitsQuery = useQuery({
    queryKey: ['sentinel-commits', repoID, status, onlyFix, page, size],
    queryFn: () =>
      sentinelApi.listCommits({
        repo_id: repoID || undefined,
        status: status || undefined,
        security_fix: onlyFix || undefined,
        page,
        size,
      }),
    // 判定由后台 worker 异步执行：10s 轮询让「待判定 → 已判定」状态自动翻新。
    refetchInterval: 10000,
  })

  const patchParams = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params)
    Object.entries(patch).forEach(([key, value]) => {
      if (value) next.set(key, value)
      else next.delete(key)
    })
    setPage(1)
    setParams(next, { replace: true })
  }

  const columns: TableProps<SentinelCommit>['columns'] = [
    {
      title: 'SHA',
      dataIndex: 'sha',
      width: 120,
      render: (value: string, row) => (
        <Link to={`/sentinel/commits/${row.id}`} className="font-mono text-xs text-primary hover:underline">
          {value.slice(0, 8)}
        </Link>
      ),
    },
    {
      title: '仓库',
      dataIndex: 'repo_full_name',
      width: 200,
      ellipsis: true,
      render: (value: string) => <span className="text-xs text-muted-foreground">{value}</span>,
    },
    {
      title: '提交信息',
      dataIndex: 'subject',
      ellipsis: true,
      render: (value: string, row) => (
        <Link to={`/sentinel/commits/${row.id}`} className="hover:text-primary">
          {value}
        </Link>
      ),
    },
    {
      title: '规模',
      key: 'size',
      width: 130,
      render: (_, row) => (
        <span className="font-mono text-xs">
          <span className="text-emerald-600 dark:text-emerald-400">+{row.additions}</span>{' '}
          <span className="text-rose-600 dark:text-rose-400">-{row.deletions}</span>{' '}
          <span className="text-muted-foreground">/{row.files_changed}f</span>
        </span>
      ),
    },
    {
      title: '判定',
      key: 'judged',
      width: 170,
      render: (_, row) => {
        if (row.judged) {
          return row.is_security_fix ? (
            <Tag color="red">安全修复 · {row.vuln_class}</Tag>
          ) : (
            <Tag>非安全修复</Tag>
          )
        }
        const meta = statusMeta[row.status] ?? statusMeta.pending
        return (
          <Tag color={meta.color}>
            {meta.label}
            {row.skip_reason ? ` · ${row.skip_reason}` : ''}
          </Tag>
        )
      },
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 130,
      render: (value: number, row) =>
        row.judged ? <Progress percent={Math.round((value ?? 0) * 100)} size="small" /> : <span className="text-xs text-muted-foreground">—</span>,
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      width: 90,
      render: (value: string, row) =>
        row.judged && row.is_security_fix ? (
          <Tag color={severityColor[value] ?? 'default'}>{value || 'info'}</Tag>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
    {
      title: '提交时间',
      dataIndex: 'committed_at',
      width: 160,
      render: (value: string) => <span className="text-xs text-muted-foreground">{formatDate(value)}</span>,
    },
  ]

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">提交</h1>
        <p className="text-sm text-muted-foreground">
          列表不含 diff 正文（详情页才取），判定结果由模型给出并受枚举与 evidence 校验约束。
        </p>
      </header>

      <JudgeRunsCard onOpenEvents={setEventsRun} />
      <RunEventsDrawer run={eventsRun} onClose={() => setEventsRun(null)} />

      <Card className="border-border/60">
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <Select
            value={repoID || undefined}
            onChange={(value) => patchParams({ repo_id: value ?? '' })}
            placeholder="全部仓库"
            allowClear
            className="min-w-[220px]"
            loading={reposQuery.isLoading}
            options={(reposQuery.data?.items ?? []).map((repo) => ({
              label: repo.full_name,
              value: repo.id,
            }))}
          />
          <Select
            value={status || undefined}
            onChange={(value) => patchParams({ status: value ?? '' })}
            placeholder="全部状态"
            allowClear
            className="min-w-[160px]"
            options={[
              { label: '待判定', value: 'pending' },
              { label: '已判定', value: 'judged' },
              { label: '已跳过', value: 'skipped' },
              { label: '判定失败', value: 'failed' },
            ]}
          />
          <label className="flex cursor-pointer items-center gap-2 text-sm text-muted-foreground">
            <Switch size="small" checked={onlyFix} onChange={(checked) => patchParams({ security_fix: checked ? 'true' : '' })} />
            仅看安全修复
          </label>
        </div>

        <Table<SentinelCommit>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={commitsQuery.data?.list ?? []}
          loading={commitsQuery.isLoading}
          scroll={{ x: 1200 }}
          pagination={{
            current: page,
            pageSize: size,
            total: commitsQuery.data?.total ?? 0,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            showTotal: (total) => `共 ${total} 条提交`,
            onChange: (nextPage, nextSize) => {
              setPage(nextPage)
              setSize(nextSize)
            },
          }}
          locale={{ emptyText: '没有符合条件的提交' }}
        />
      </Card>
    </div>
  )
}

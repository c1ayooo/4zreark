/**
 * 代码审计 · 分析结果
 *
 * 只回答两件事：这条提交被判成了什么、凭什么（reasoning + hunk 证据）。
 * 判定幂等：同一 (commit, model) 只有一条，已判定过的不会重判。
 *
 * 真实接口：
 *   GET  /api/sentinel/commits?repo_id=&status=&security_fix=&sha=&page=&size=
 *   GET  /api/sentinel/commits/{id}   → {commit, judgment, findings}
 *   POST /api/sentinel/commits/{id}/judge
 */
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Button, Drawer, Input, Select, Table, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { Play, Search, Sparkles } from 'lucide-react'
import { sentinelApi, type SentinelCommit } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import {
  CommitStatusTag,
  ConfidenceBar,
  EmptyBlock,
  ErrorPanel,
  Metric,
  PageHeader,
  SeverityTag,
  VerdictTag,
  fmtNumber,
  fmtTime,
} from './shared'

const STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'pending', label: '待判定' },
  { value: 'judged', label: '已判定' },
  { value: 'skipped', label: '已跳过' },
  { value: 'failed', label: '失败' },
]

/** evidence 是 []string（真实 hunk 头），后端会对不上 hunk 的结论降权。 */
function evidenceList(ev: unknown): string[] {
  if (!Array.isArray(ev)) return []
  return ev.filter((x): x is string => typeof x === 'string' && x.trim() !== '')
}

export default function AnalysisResultsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()

  const [repoId, setRepoId] = useState('')
  const [status, setStatus] = useState('')
  const [onlyFix, setOnlyFix] = useState(false)
  const [sha, setSha] = useState('')
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)

  const commitParam = Number(searchParams.get('commit') || 0)
  const [activeId, setActiveId] = useState<number | null>(commitParam || null)

  useEffect(() => {
    if (commitParam > 0) setActiveId(commitParam)
  }, [commitParam])

  const reposQuery = useQuery({
    queryKey: ['sentinel', 'repos', ''],
    queryFn: () => sentinelApi.repos(),
  })
  const repos = reposQuery.data?.items ?? []

  const commitsQuery = useQuery({
    queryKey: ['sentinel', 'commits', { repoId, status, onlyFix, sha, page, size }],
    queryFn: () =>
      sentinelApi.commits({
        repo_id: repoId || undefined,
        status: status || undefined,
        security_fix: onlyFix || undefined,
        sha: sha.trim() || undefined,
        page,
        size,
      }),
    refetchInterval: 30000,
  })

  const items = commitsQuery.data?.list ?? []
  const total = commitsQuery.data?.total ?? 0

  const detailQuery = useQuery({
    queryKey: ['sentinel', 'commit', activeId],
    queryFn: () => sentinelApi.commit(activeId as number),
    enabled: !!activeId,
  })
  const detail = detailQuery.data

  const judgeMutation = useMutation({
    mutationFn: (id: number) => sentinelApi.judge(id),
    onSuccess: (res) => {
      toast({ title: res.message || '已加入判定队列' })
      queryClient.invalidateQueries({ queryKey: ['sentinel'] })
    },
    onError: (e: Error) =>
      toast({ title: '入队失败', description: e?.message, variant: 'destructive' }),
  })

  const openDetail = (id: number) => {
    setActiveId(id)
    const next = new URLSearchParams(searchParams)
    next.set('commit', String(id))
    setSearchParams(next, { replace: true })
  }

  const closeDetail = () => {
    setActiveId(null)
    const next = new URLSearchParams(searchParams)
    next.delete('commit')
    setSearchParams(next, { replace: true })
  }

  /** 命中率用当前页近似，避免为了一个数字多打一次聚合查询。 */
  const pageFixCount = useMemo(() => items.filter((i) => i.is_security_fix).length, [items])

  const columns: TableProps<SentinelCommit>['columns'] = [
    {
      title: '提交',
      key: 'commit',
      render: (_, r) => (
        <div className="min-w-[300px]">
          <div className="truncate text-[12.5px] font-medium text-foreground">{r.subject || '(无标题)'}</div>
          <div className="flex items-center gap-1.5 font-mono text-[10.5px] text-muted-foreground">
            <span>{r.repo_full_name || r.repo_id}</span>
            <span className="text-border">·</span>
            <span>{r.sha.slice(0, 8)}</span>
            <span className="text-border">·</span>
            <span>{r.author_name || '—'}</span>
          </div>
        </div>
      ),
    },
    {
      title: '判定',
      key: 'verdict',
      width: 132,
      render: (_, r) => (
        <div className="flex flex-col items-start gap-1">
          <VerdictTag judged={r.judged} isSecurityFix={r.is_security_fix} />
          {r.judged && r.vuln_class && (
            <span className="font-mono text-[10px] text-muted-foreground">{r.vuln_class}</span>
          )}
        </div>
      ),
    },
    {
      title: '严重度',
      key: 'severity',
      width: 92,
      render: (_, r) => <SeverityTag severity={r.judged ? r.severity : ''} />,
    },
    {
      title: '置信度',
      key: 'confidence',
      width: 108,
      render: (_, r) => <ConfidenceBar value={r.judged ? r.confidence : undefined} />,
    },
    {
      title: '规模',
      key: 'size',
      width: 116,
      render: (_, r) => (
        <span className="font-mono text-[10.5px] text-muted-foreground">
          {r.files_changed} 文件 / <span className="text-emerald-700">+{r.additions}</span>{' '}
          <span className="text-rose-700">-{r.deletions}</span>
        </span>
      ),
    },
    {
      title: '状态',
      key: 'status',
      width: 92,
      render: (_, r) => (
        <Tooltip title={r.skip_reason || undefined}>
          <span>
            <CommitStatusTag status={r.status} />
          </span>
        </Tooltip>
      ),
    },
    {
      title: '提交时间',
      key: 'time',
      width: 124,
      render: (_, r) => (
        <span className="font-mono text-[10.5px] text-muted-foreground">{fmtTime(r.committed_at)}</span>
      ),
    },
    {
      title: '',
      key: 'action',
      width: 92,
      render: (_, r) => (
        <div onClick={(e) => e.stopPropagation()}>
          {r.judged ? (
            <span className="text-[10.5px] text-muted-foreground">已判定</span>
          ) : (
            <Button
              size="small"
              type="text"
              icon={<Play size={11} />}
              className="!px-1.5 text-[11px]"
              loading={judgeMutation.isPending && judgeMutation.variables === r.id}
              onClick={() => judgeMutation.mutate(r.id)}
            >
              判定
            </Button>
          )}
        </div>
      ),
    },
  ]

  const judgment = detail?.judgment ?? null
  const evidence = evidenceList(judgment?.evidence)
  const findings = detail?.findings ?? []

  return (
    <div className="space-y-4">
      <PageHeader
        title="分析结果"
        desc="每条提交的判定结论、置信度与 hunk 证据；判定幂等，失败可重入队"
        actions={
          <Button
            size="small"
            icon={<Search size={13} />}
            onClick={() => commitsQuery.refetch()}
            loading={commitsQuery.isFetching}
          >
            刷新
          </Button>
        }
      />

      {commitsQuery.error ? (
        <ErrorPanel error={commitsQuery.error} onRetry={() => commitsQuery.refetch()} />
      ) : null}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric label="提交总数" value={fmtNumber(total)} hint="当前筛选条件" />
        <Metric
          label="本页安全修复"
          value={`${pageFixCount} / ${items.length}`}
          hint="is_security_fix = true"
          tone={pageFixCount ? 'text-sky-700 dark:text-sky-400' : undefined}
        />
        <Metric
          label="待判定"
          value={fmtNumber(items.filter((i) => i.status === 'pending').length)}
          hint="本页 pending"
          tone={items.some((i) => i.status === 'pending') ? 'text-amber-700 dark:text-amber-400' : undefined}
        />
        <Metric
          label="平均置信度"
          value={
            items.filter((i) => i.judged).length
              ? `${Math.round(
                  (items.filter((i) => i.judged).reduce((s, i) => s + i.confidence, 0) /
                    items.filter((i) => i.judged).length) *
                    100,
                )}%`
              : '—'
          }
          hint="本页已判定提交"
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={repoId}
          onChange={(v) => {
            setRepoId(v)
            setPage(1)
          }}
          className="w-[210px]"
          options={[{ value: '', label: '全部仓库' }, ...repos.map((r) => ({ value: r.id, label: r.full_name }))]}
        />
        <Select
          value={status}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
          className="w-[132px]"
          options={STATUS_OPTIONS}
        />
        <Button
          size="small"
          type={onlyFix ? 'primary' : 'default'}
          icon={<Sparkles size={12} />}
          onClick={() => {
            setOnlyFix((v) => !v)
            setPage(1)
          }}
          className="text-[11px]"
        >
          只看安全修复
        </Button>
        <Input
          value={sha}
          onChange={(e) => {
            setSha(e.target.value)
            setPage(1)
          }}
          placeholder="sha 前缀"
          allowClear
          className="w-[150px]"
        />
        <span className="ml-auto text-[10.5px] text-muted-foreground">
          点行看 diff 与判定依据
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        {!commitsQuery.isLoading && items.length === 0 && !commitsQuery.error ? (
          <div className="p-3">
            <EmptyBlock>
              没有匹配的提交。先去「分析任务」加一个监控仓库并点一次采集。
            </EmptyBlock>
          </div>
        ) : (
          <Table
            rowKey={(r) => r.id}
            size="middle"
            loading={commitsQuery.isLoading}
            columns={columns}
            dataSource={items}
            onRow={(r) => ({ onClick: () => openDetail(r.id), className: 'cursor-pointer' })}
            pagination={{
              current: page,
              pageSize: size,
              total,
              size: 'small',
              showSizeChanger: true,
              pageSizeOptions: [10, 20, 50, 100],
              onChange: (p, s) => {
                setPage(p)
                setSize(s)
              },
              showTotal: (t) => `共 ${t} 条`,
            }}
          />
        )}
      </div>

      <Drawer
        open={!!activeId}
        onClose={closeDetail}
        width={980}
        destroyOnClose
        title={detail ? `${detail.commit.repo_full_name} · ${detail.commit.sha.slice(0, 8)}` : '提交详情'}
      >
        {detailQuery.error ? (
          <ErrorPanel error={detailQuery.error} onRetry={() => detailQuery.refetch()} />
        ) : null}

        {detail && (
          <div className="space-y-3">
            <div className="rounded-xl border border-border bg-card px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-medium text-foreground">
                  {detail.commit.subject || '(无标题)'}
                </span>
                <CommitStatusTag status={detail.commit.status} />
                <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                  {detail.commit.author_name} &lt;{detail.commit.author_email}&gt; ·{' '}
                  {fmtTime(detail.commit.committed_at)}
                </span>
              </div>
              {detail.commit.message && (
                <pre className="m-0 mt-1.5 max-h-24 overflow-auto whitespace-pre-wrap font-mono text-[10.5px] leading-relaxed text-secondary-foreground">
                  {detail.commit.message}
                </pre>
              )}
            </div>

            <div className="grid gap-3 lg:grid-cols-2">
              <div>
                <div className="mb-1.5 flex items-center gap-2">
                  <span className="text-[12px] font-semibold text-foreground">改动</span>
                  <span className="font-mono text-[10px] text-muted-foreground">
                    {detail.commit.files_changed} 文件 · +{detail.commit.additions} / -
                    {detail.commit.deletions}
                  </span>
                </div>
                <pre className="m-0 max-h-[460px] overflow-auto rounded-xl border border-border bg-muted/30 p-2 font-mono text-[10.5px] leading-relaxed">
                  {detail.commit.diff
                    ? detail.commit.diff.split('\n').map((line, i) => (
                        <div
                          key={i}
                          className={
                            line.startsWith('+') && !line.startsWith('+++')
                              ? 'bg-emerald-50 text-emerald-800'
                              : line.startsWith('-') && !line.startsWith('---')
                                ? 'bg-rose-50 text-rose-800'
                                : line.startsWith('@@')
                                  ? 'text-sky-700'
                                  : 'text-secondary-foreground'
                          }
                        >
                          {line || ' '}
                        </div>
                      ))
                    : '（无 diff：可能被过滤规则跳过）'}
                </pre>
              </div>

              <div className="space-y-2.5">
                <div className="rounded-xl border border-border bg-card px-3 py-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[12px] font-semibold text-foreground">判定</span>
                    {judgment ? (
                      <>
                        <VerdictTag judged isSecurityFix={judgment.is_security_fix} />
                        <SeverityTag severity={judgment.severity} />
                        <ConfidenceBar value={judgment.confidence} />
                        {judgment.partial && (
                          <span className="rounded-full bg-amber-50 px-1.5 py-0.5 text-[10px] text-amber-700">
                            partial
                          </span>
                        )}
                        <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                          {judgment.model}
                        </span>
                      </>
                    ) : (
                      <span className="text-[11px] text-muted-foreground">尚未判定</span>
                    )}
                  </div>

                  {judgment && (
                    <>
                      {judgment.title && (
                        <div className="mt-1.5 text-[11.5px] text-secondary-foreground">
                          <span className="text-muted-foreground">组件：</span>
                          <span className="font-mono">{judgment.title}</span>
                          {judgment.vuln_class && (
                            <>
                              <span className="ml-2 text-muted-foreground">类型：</span>
                              <span className="font-mono">{judgment.vuln_class}</span>
                            </>
                          )}
                        </div>
                      )}
                      <div className="mt-1.5 text-[11.5px] leading-relaxed text-secondary-foreground">
                        {judgment.reasoning || '模型未给出理由'}
                      </div>
                      <div className="mt-1.5 flex items-center gap-2 text-[10px] text-muted-foreground">
                        <span className="font-mono">
                          tokens {judgment.prompt_tokens}+{judgment.completion_tokens}
                        </span>
                        <span>{fmtTime(judgment.created_at)}</span>
                      </div>
                    </>
                  )}

                  {!judgment && detail.commit.status !== 'judged' && (
                    <Button
                      size="small"
                      className="mt-2"
                      icon={<Play size={12} />}
                      loading={judgeMutation.isPending}
                      onClick={() => judgeMutation.mutate(detail.commit.id)}
                    >
                      加入判定队列
                    </Button>
                  )}
                </div>

                <div className="rounded-xl border border-border bg-card px-3 py-2.5">
                  <div className="mb-1.5 flex items-center gap-2">
                    <span className="text-[12px] font-semibold text-foreground">证据</span>
                    <span className="text-[10.5px] text-muted-foreground">
                      {evidence.length} 条 hunk 头 · 对不上真实 hunk 会被降权
                    </span>
                  </div>
                  {evidence.length ? (
                    <div className="space-y-1">
                      {evidence.map((ev, i) => (
                        <div
                          key={i}
                          className="rounded-lg border border-border bg-muted/30 px-2 py-1 font-mono text-[10.5px] leading-relaxed text-secondary-foreground"
                        >
                          {ev}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] text-muted-foreground">
                      无 evidence（判为非安全修复，或模型未给出可对齐的 hunk）
                    </div>
                  )}
                </div>

                <div className="rounded-xl border border-border bg-card px-3 py-2.5">
                  <div className="mb-1.5 flex items-center gap-2">
                    <span className="text-[12px] font-semibold text-foreground">发现</span>
                    <span className="text-[10.5px] text-muted-foreground">{findings.length} 条</span>
                  </div>
                  {findings.length ? (
                    <div className="space-y-1.5">
                      {findings.map((f) => (
                        <div key={f.id} className="rounded-lg border border-border px-2 py-1.5">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-[11.5px] font-medium text-foreground">{f.title}</span>
                            <SeverityTag severity={f.severity} />
                            <span className="font-mono text-[10px] text-muted-foreground">{f.vuln_class}</span>
                          </div>
                          {f.detail && (
                            <div className="mt-0.5 text-[11px] leading-relaxed text-secondary-foreground">
                              {f.detail}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] text-muted-foreground">判定未命中，无落地发现</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}

/**
 * 代码审计 · 分析产物
 *
 * 产物 = 判定命中后落地的 finding（可验证发现），每条都能回溯到源提交。
 * 状态流转由后端 finding.status 决定（open → confirmed / ignored / resolved）。
 *
 * 真实接口：
 *   GET /api/sentinel/findings?status=&severity=&repo_id=&page=&size=
 */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Button, Drawer, Select, Table } from 'antd'
import type { TableProps } from 'antd'
import { ArrowUpRight, Package } from 'lucide-react'
import { sentinelApi, type SentinelFinding } from '@/api/sentinel'
import {
  EmptyBlock,
  ErrorPanel,
  FindingStatusTag,
  Metric,
  PageHeader,
  SeverityTag,
  fmtNumber,
  fmtTime,
} from './shared'

const STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'open', label: '待处理' },
  { value: 'confirmed', label: '已确认' },
  { value: 'ignored', label: '已忽略' },
  { value: 'resolved', label: '已处置' },
]

const SEVERITY_OPTIONS = [
  { value: '', label: '全部严重度' },
  { value: 'critical', label: 'critical' },
  { value: 'high', label: 'high' },
  { value: 'medium', label: 'medium' },
  { value: 'low', label: 'low' },
  { value: 'info', label: 'info' },
]

export default function AnalysisArtifactsPage() {
  const navigate = useNavigate()
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [repoId, setRepoId] = useState('')
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)
  const [preview, setPreview] = useState<SentinelFinding | null>(null)

  const reposQuery = useQuery({
    queryKey: ['sentinel', 'repos', ''],
    queryFn: () => sentinelApi.repos(),
  })
  const repos = reposQuery.data?.items ?? []

  const findingsQuery = useQuery({
    queryKey: ['sentinel', 'findings', { status, severity, repoId, page, size }],
    queryFn: () =>
      sentinelApi.findings({
        status: status || undefined,
        severity: severity || undefined,
        repo_id: repoId || undefined,
        page,
        size,
      }),
    refetchInterval: 60000,
  })

  const items = findingsQuery.data?.list ?? []
  const total = findingsQuery.data?.total ?? 0

  const stats = useMemo(() => {
    const critical = items.filter((f) => f.severity === 'critical').length
    const high = items.filter((f) => f.severity === 'high').length
    const open = items.filter((f) => f.status === 'open').length
    const repoSet = new Set(items.map((f) => f.repo_full_name).filter(Boolean))
    return { critical, high, open, repos: repoSet.size }
  }, [items])

  const columns: TableProps<SentinelFinding>['columns'] = [
    {
      title: '发现',
      key: 'title',
      render: (_, r) => (
        <div className="min-w-[260px]">
          <div className="flex items-center gap-1.5">
            <span className="text-[12.5px] font-medium text-foreground">{r.title}</span>
            <span className="rounded-full bg-secondary px-1.5 py-0.5 font-mono text-[9.5px] text-secondary-foreground">
              #{r.id}
            </span>
          </div>
          <div className="font-mono text-[10.5px] text-muted-foreground">{r.vuln_class}</div>
        </div>
      ),
    },
    {
      title: '来源',
      key: 'source',
      render: (_, r) => (
        <div className="min-w-[220px]">
          <div className="font-mono text-[11px] text-secondary-foreground">{r.repo_full_name || r.repo_id}</div>
          <div className="truncate text-[10.5px] text-muted-foreground">
            <span className="font-mono">{r.sha.slice(0, 8)}</span> · {r.subject || '(无标题)'}
          </div>
        </div>
      ),
    },
    { title: '严重度', key: 'severity', width: 92, render: (_, r) => <SeverityTag severity={r.severity} /> },
    { title: '状态', key: 'status', width: 90, render: (_, r) => <FindingStatusTag status={r.status} /> },
    {
      title: '判定模型',
      key: 'model',
      width: 132,
      render: (_, r) => (
        <span className="font-mono text-[10.5px] text-muted-foreground">{r.model || '—'}</span>
      ),
    },
    {
      title: '落地时间',
      key: 'time',
      width: 124,
      render: (_, r) => (
        <span className="font-mono text-[10.5px] text-muted-foreground">{fmtTime(r.created_at)}</span>
      ),
    },
    {
      title: '',
      key: 'action',
      width: 88,
      render: (_, r) => (
        <Button
          size="small"
          type="text"
          icon={<ArrowUpRight size={12} />}
          className="!px-1.5 text-[11px]"
          onClick={(e) => {
            e.stopPropagation()
            navigate(`/sentinel/audit/results?commit=${r.commit_id}`)
          }}
        >
          源提交
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="分析产物"
        desc="判定命中的可验证发现：严重度、状态与来源提交一一对应，不做二次推断"
        actions={
          <Button
            size="small"
            icon={<Package size={13} />}
            onClick={() => findingsQuery.refetch()}
            loading={findingsQuery.isFetching}
          >
            刷新
          </Button>
        }
      />

      {findingsQuery.error ? (
        <ErrorPanel error={findingsQuery.error} onRetry={() => findingsQuery.refetch()} />
      ) : null}

      <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
        <Metric label="发现总数" value={fmtNumber(total)} hint="当前筛选条件" />
        <Metric
          label="critical + high"
          value={fmtNumber(stats.critical + stats.high)}
          hint="本页高危口径"
          tone={stats.critical + stats.high ? 'text-rose-700' : undefined}
        />
        <Metric
          label="待处理"
          value={fmtNumber(stats.open)}
          hint="status = open"
          tone={stats.open ? 'text-amber-700' : undefined}
        />
        <Metric label="涉及仓库" value={fmtNumber(stats.repos)} hint="本页去重" />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={status}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
          className="w-[132px]"
          options={STATUS_OPTIONS}
        />
        <Select
          value={severity}
          onChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
          className="w-[140px]"
          options={SEVERITY_OPTIONS}
        />
        <Select
          value={repoId}
          onChange={(v) => {
            setRepoId(v)
            setPage(1)
          }}
          className="w-[210px]"
          options={[{ value: '', label: '全部仓库' }, ...repos.map((r) => ({ value: r.id, label: r.full_name }))]}
        />
        <span className="ml-auto text-[10.5px] text-muted-foreground">
          {items.length} / {total} 条
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        {!findingsQuery.isLoading && items.length === 0 && !findingsQuery.error ? (
          <div className="p-3">
            <EmptyBlock>
              还没有发现。发现由判定命中产生：先在「分析结果」里让提交跑出 <span className="font-mono">is_security_fix=true</span>。
            </EmptyBlock>
          </div>
        ) : (
          <Table
            rowKey={(r) => r.id}
            size="middle"
            loading={findingsQuery.isLoading}
            columns={columns}
            dataSource={items}
            onRow={(r) => ({ onClick: () => setPreview(r), className: 'cursor-pointer' })}
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

      <div className="text-[10.5px] leading-relaxed text-muted-foreground">
        产物不单独存储漏洞描述，它的可信度完全绑定判定：模型、置信度、evidence 都在源提交的详情里，
        所以这里每条都提供「源提交」跳转，避免脱离上下文使用结论。
      </div>

      <Drawer
        open={!!preview}
        onClose={() => setPreview(null)}
        width={620}
        title={preview ? `发现 #${preview.id}` : ''}
        destroyOnClose
      >
        {preview && (
          <div className="space-y-3">
            <div className="rounded-xl border border-border bg-card px-3 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-medium text-foreground">{preview.title}</span>
                <SeverityTag severity={preview.severity} />
                <FindingStatusTag status={preview.status} />
                <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">
                  {preview.vuln_class}
                </span>
              </div>
              <div className="mt-1.5 text-[11.5px] leading-relaxed text-secondary-foreground">
                {preview.detail || '无详细描述'}
              </div>
            </div>

            <div className="rounded-xl border border-border bg-card px-3 py-2.5">
              <div className="mb-1.5 text-[12px] font-semibold text-foreground">溯源</div>
              <dl className="grid gap-1 text-[11.5px]">
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-muted-foreground">仓库</dt>
                  <dd className="font-mono text-secondary-foreground">
                    {preview.repo_full_name || preview.repo_id}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-muted-foreground">提交</dt>
                  <dd className="min-w-0 font-mono text-secondary-foreground">
                    {preview.sha.slice(0, 12)}
                  </dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-muted-foreground">标题</dt>
                  <dd className="min-w-0 text-secondary-foreground">{preview.subject || '—'}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-muted-foreground">提交时间</dt>
                  <dd className="font-mono text-secondary-foreground">{fmtTime(preview.committed_at)}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-20 shrink-0 text-muted-foreground">判定模型</dt>
                  <dd className="font-mono text-secondary-foreground">{preview.model || '—'}</dd>
                </div>
              </dl>
            </div>

            <Button
              type="primary"
              size="small"
              icon={<ArrowUpRight size={12} />}
              onClick={() => navigate(`/sentinel/audit/results?commit=${preview.commit_id}`)}
            >
              查看源提交与判定依据
            </Button>
          </div>
        )}
      </Drawer>
    </div>
  )
}

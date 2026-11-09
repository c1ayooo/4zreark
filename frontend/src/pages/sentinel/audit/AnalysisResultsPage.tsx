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
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { Button, Drawer, Dropdown, Input, Popconfirm, Select, Table, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { Download, FileText, Play, Search, Sparkles } from 'lucide-react'
import { sentinelApi, type SentinelCommit, type SentinelFindingStatus } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import {
  CommitStatusTag,
  ConfidenceBar,
  EmptyBlock,
  ErrorPanel,
  FindingStatusSelect,
  Metric,
  PageHeader,
  SeverityTag,
  VerdictTag,
  VULN_CLASS_OPTIONS,
  VulnClassTag,
  fmtNumber,
  fmtTime,
  FindingGradeTag,
} from './shared'

const STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'pending', label: '待判定' },
  { value: 'judged', label: '已判定' },
  { value: 'skipped', label: '已跳过' },
  { value: 'failed', label: '失败' },
]

/** 严重度下限（min_severity）：「高危」= high + critical 一起命中 */
const MIN_SEVERITY_OPTIONS = [
  { value: '', label: '全部严重度' },
  { value: 'critical', label: '仅严重（critical）' },
  { value: 'high', label: '高危及以上' },
  { value: 'medium', label: '中危及以上' },
  { value: 'low', label: '低危及以上' },
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
  const [vulnClasses, setVulnClasses] = useState<string[]>([])
  const [minSeverity, setMinSeverity] = useState('')
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
    queryKey: ['sentinel', 'commits', { repoId, status, onlyFix, vulnClasses, minSeverity, sha, page, size }],
    queryFn: () =>
      sentinelApi.commits({
        repo_id: repoId || undefined,
        status: status || undefined,
        security_fix: onlyFix || undefined,
        vuln_class: vulnClasses.length ? vulnClasses.join(',') : undefined,
        min_severity: minSeverity || undefined,
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

  const patchFindingMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: SentinelFindingStatus }) =>
      sentinelApi.patchFinding(id, status),
    onSuccess: (f) => {
      toast({ title: `发现 #${f.id} 状态已更新` })
      queryClient.invalidateQueries({ queryKey: ['sentinel', 'findings'] })
      queryClient.invalidateQueries({ queryKey: ['sentinel', 'commit'] })
    },
    onError: (e: Error) =>
      toast({ title: '状态更新失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const generateNucleiMutation = useMutation({
    mutationFn: (id: number) => sentinelApi.generateFindingNuclei(id),
    onSuccess: (a) => {
      toast({
        title: `nuclei 模板已生成（draft，#${a.id}）`,
        description: '生成物是候选而非结论，到「分析产物」审核 verified 后才可发布。',
        duration: 6,
      })
      queryClient.invalidateQueries({ queryKey: ['sentinel', 'finding-artifacts'] })
    },
    onError: (e: Error) =>
      toast({ title: '生成失败', description: getErrorMessage(e), variant: 'destructive', duration: 6 }),
  })

  /** 导出当前筛选下的发现报告：PDF 走后端 chrome 无头转换，耗时较长 */
  const exportMutation = useMutation({
    mutationFn: (format: 'md' | 'pdf') =>
      sentinelApi.exportFindings(format, {
        vuln_class: vulnClasses.length ? vulnClasses.join(',') : undefined,
        min_severity: minSeverity || undefined,
        repo_id: repoId || undefined,
        status: undefined,
      }),
    onSuccess: () => toast({ title: '报告已导出' }),
    onError: (e: Error) =>
      toast({ title: '导出失败', description: e?.message, variant: 'destructive', duration: 6 }),
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
          {r.judged && r.vuln_class && <VulnClassTag vulnClass={r.vuln_class} />}
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
  const snippets = evidenceList(judgment?.evidence_snippets)
  const findings = detail?.findings ?? []

  /**
   * 富化状态：每条 finding 的产物计数（POC 命中数 / nuclei 草稿 / 复现指南）。
   * 与产物中心共用 ['sentinel', 'finding-artifacts', id] 缓存 key，互不打爆。
   */
  const enrichByFinding = useQueries({
    queries: findings.map((f) => ({
      queryKey: ['sentinel', 'finding-artifacts', f.id] as const,
      queryFn: () => sentinelApi.findingArtifacts(f.id),
      enabled: !!activeId,
    })),
    combine: (results) => {
      const map: Record<number, { poc: number; nuclei: boolean; guide: boolean }> = {}
      results.forEach((r, i) => {
        const arts = r.data ?? []
        map[findings[i].id] = {
          poc: arts.filter((a) => a.kind === 'poc').length,
          nuclei: arts.some((a) => a.kind === 'nuclei'),
          guide: arts.some(
            (a) => a.kind === 'report' && a.title.trim().toLowerCase() === 'repro-guide',
          ),
        }
      })
      return map
    },
  })

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
        <Select
          mode="multiple"
          value={vulnClasses}
          onChange={(v) => {
            setVulnClasses(v)
            setPage(1)
          }}
          className="min-w-[220px]"
          maxTagCount={2}
          allowClear
          placeholder="漏洞类型"
          options={VULN_CLASS_OPTIONS}
          optionFilterProp="label"
        />
        <Select
          value={minSeverity}
          onChange={(v) => {
            setMinSeverity(v)
            setPage(1)
          }}
          className="w-[150px]"
          options={MIN_SEVERITY_OPTIONS}
        />
        <Dropdown
          menu={{
            items: [
              { key: 'md', icon: <FileText size={12} />, label: '导出 Markdown' },
              { key: 'pdf', icon: <Download size={12} />, label: '导出 PDF' },
            ],
            onClick: ({ key }) => exportMutation.mutate(key as 'md' | 'pdf'),
          }}
        >
          <Button
            size="small"
            icon={<Download size={12} />}
            loading={exportMutation.isPending}
            className="text-[11px]"
          >
            导出报告
          </Button>
        </Dropdown>
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
            tableLayout="fixed"
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
                          <span className="text-muted-foreground">标题：</span>
                          <span className="font-medium text-foreground">{judgment.title}</span>
                          {judgment.vuln_class && (
                            <span className="ml-2 inline-flex translate-y-[1px] items-center">
                              <VulnClassTag vulnClass={judgment.vuln_class} />
                            </span>
                          )}
                        </div>
                      )}
                      <div className="mt-1.5 text-[11.5px] leading-relaxed text-secondary-foreground">
                        {judgment.reasoning || '模型未给出理由'}
                      </div>
                      {/* 三段式说明：旧判定无这些字段，全部为空时不渲染区块 */}
                      {(judgment.attack_path || judgment.impact || judgment.fix_evidence) && (
                        <div className="mt-2 space-y-1.5 border-t border-border pt-2">
                          {judgment.attack_path && (
                            <div className="text-[11.5px] leading-relaxed text-secondary-foreground">
                              <span className="font-medium text-foreground">攻击路径：</span>
                              {judgment.attack_path}
                            </div>
                          )}
                          {judgment.impact && (
                            <div className="text-[11.5px] leading-relaxed text-secondary-foreground">
                              <span className="font-medium text-foreground">影响：</span>
                              {judgment.impact}
                            </div>
                          )}
                          {judgment.fix_evidence && (
                            <div className="text-[11.5px] leading-relaxed text-secondary-foreground">
                              <span className="font-medium text-foreground">修复依据：</span>
                              {judgment.fix_evidence}
                            </div>
                          )}
                        </div>
                      )}
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
                  {/* 模型摘录的关键代码行：后端校验对不上真实 diff 会降权 */}
                  {snippets.length > 0 && (
                    <div className="mt-2 border-t border-border pt-2">
                      <div className="mb-1 text-[10.5px] text-muted-foreground">
                        关键代码摘录 {snippets.length} 段
                      </div>
                      <div className="space-y-1">
                        {snippets.map((snip, i) => (
                          <pre
                            key={i}
                            className="m-0 max-h-32 overflow-auto rounded-lg border border-border bg-muted/30 px-2 py-1 font-mono text-[10.5px] leading-relaxed text-secondary-foreground"
                          >
                            {snip}
                          </pre>
                        ))}
                      </div>
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
                            <VulnClassTag vulnClass={f.vuln_class} />
                            <FindingGradeTag grade={(f as { grade?: string }).grade ?? ''} />
                            <span className="ml-auto flex items-center gap-1.5">
                              <Popconfirm
                                title="生成 nuclei 模板？"
                                description="依据修复 diff 由模型草拟，约 30-60 秒，落 draft 待审核。"
                                onConfirm={() => generateNucleiMutation.mutate(f.id)}
                              >
                                <Button
                                  size="small"
                                  type="text"
                                  icon={<Sparkles size={11} />}
                                  className="!px-1.5 text-[11px]"
                                  loading={
                                    generateNucleiMutation.isPending &&
                                    generateNucleiMutation.variables === f.id
                                  }
                                >
                                  生成 nuclei
                                </Button>
                              </Popconfirm>
                              <FindingStatusSelect
                                status={f.status}
                                loading={
                                  patchFindingMutation.isPending &&
                                  patchFindingMutation.variables?.id === f.id
                                }
                                onChange={(next) => patchFindingMutation.mutate({ id: f.id, status: next })}
                              />
                            </span>
                          </div>
                          {(() => {
                            const e = enrichByFinding[f.id]
                            if (!e) return null
                            return (
                              <div className="mt-1 flex flex-wrap items-center gap-1">
                                {e.poc > 0 && (
                                  <Tooltip title="POC 库命中并已挂载为 draft 产物，审核 verified 后可用于差分复现">
                                    <span className="rounded-full bg-secondary px-1.5 py-0.5 text-[9.5px] text-secondary-foreground">
                                      POC 命中 {e.poc}
                                    </span>
                                  </Tooltip>
                                )}
                                {e.nuclei && (
                                  <Tooltip title="已有 nuclei 模板草稿，到「分析产物」审核 verified 后可发布 PoC 库">
                                    <span className="rounded-full bg-secondary px-1.5 py-0.5 text-[9.5px] text-secondary-foreground">
                                      nuclei 草稿
                                    </span>
                                  </Tooltip>
                                )}
                                {e.guide && (
                                  <Tooltip title="复现指南（repro-guide）已生成，含攻击路径与分步复现说明">
                                    <span className="rounded-full bg-secondary px-1.5 py-0.5 text-[9.5px] text-secondary-foreground">
                                      复现指南
                                    </span>
                                  </Tooltip>
                                )}
                              </div>
                            )
                          })()}
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

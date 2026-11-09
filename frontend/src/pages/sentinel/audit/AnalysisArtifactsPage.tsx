/**
 * 代码审计 · 产物中心
 *
 * 产物 = 发现的证据链：poc / nuclei / report / patch / repro_log。
 * 状态机：draft → pending_review → verified / rejected → deprecated；
 * 铁律沿用文档：非 verified 产物不可下载、不可发布到 PoC 库；
 * nuclei 模板由模型草拟（分析结果页触发），人工 verified 后才进扫描分发链。
 *
 * 真实接口：
 *   GET  /api/sentinel/findings?status=&page=&size=
 *   GET  /api/sentinel/findings/{id}/artifacts
 *   POST /api/sentinel/findings/{id}/artifacts
 *   PUT  /api/sentinel/artifacts/{id}/status
 *   GET  /api/sentinel/artifacts/{id}/download   （仅 verified）
 *   POST /api/sentinel/artifacts/{id}/publish    （仅 verified 的 nuclei）
 */
import { useState } from 'react'
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Button, Drawer, Input, Popconfirm, Select, Table, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { Download, Package, Upload } from 'lucide-react'
import {
  sentinelApi,
  type SentinelArtifact,
  type SentinelArtifactKind,
  type SentinelArtifactStatus,
  type SentinelFinding,
} from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import {
  ArtifactStatusSelect,
  ARTIFACT_STATUS_LABELS,
  EmptyBlock,
  ErrorPanel,
  FindingGradeTag,
  FindingStatusTag,
  PageHeader,
  SeverityTag,
  fmtTime,
} from './shared'

const STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'open', label: '待处理' },
  { value: 'confirmed', label: '已确认' },
  { value: 'ignored', label: '已忽略' },
  { value: 'resolved', label: '已处置' },
]

const KIND_OPTIONS: { value: SentinelArtifactKind; label: string }[] = [
  { value: 'poc', label: 'PoC' },
  { value: 'nuclei', label: 'nuclei 模板' },
  { value: 'report', label: '报告' },
  { value: 'patch', label: '补丁' },
  { value: 'repro_log', label: '复现日志' },
]

const CREATE_FORM_INIT: { kind: SentinelArtifactKind; title: string; content: string } = {
  kind: 'poc',
  title: '',
  content: '',
}

const PREVIEW_LINES = 12

/** content 预览：默认最多 12 行，可展开 */
function ContentPreview({ content }: { content: string }) {
  const [open, setOpen] = useState(false)
  const lines = content.split('\n')
  const clipped = !open && lines.length > PREVIEW_LINES
  return (
    <div className="mt-1.5">
      <pre
        className={`m-0 whitespace-pre-wrap rounded-lg border border-border bg-muted/30 p-2 font-mono text-[10.5px] leading-relaxed text-secondary-foreground ${
          clipped ? 'max-h-[200px] overflow-hidden' : 'max-h-80 overflow-auto'
        }`}
      >
        {(clipped ? lines.slice(0, PREVIEW_LINES) : lines).join('\n')}
      </pre>
      {lines.length > PREVIEW_LINES && (
        <Button size="small" type="link" className="!px-0 text-[10.5px]" onClick={() => setOpen((v) => !v)}>
          {open ? '收起' : `展开全部 ${lines.length} 行`}
        </Button>
      )}
    </div>
  )
}

/** 抽屉主体：单个发现的产物列表 + 新增产物表单。数据流收敛在这里，页面只管选行。 */
function FindingArtifacts({ finding }: { finding: SentinelFinding }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [form, setForm] = useState(CREATE_FORM_INIT)

  const artifactsQuery = useQuery({
    queryKey: ['sentinel', 'finding-artifacts', finding.id],
    queryFn: () => sentinelApi.findingArtifacts(finding.id),
  })
  const artifacts = artifactsQuery.data ?? []

  const invalidateArtifacts = () =>
    queryClient.invalidateQueries({ queryKey: ['sentinel', 'finding-artifacts'] })

  const statusMutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: SentinelArtifactStatus }) =>
      sentinelApi.setArtifactStatus(id, status),
    onSuccess: (a) => {
      toast({ title: `产物 #${a.id} 状态已更新为「${ARTIFACT_STATUS_LABELS[a.status] ?? a.status}」` })
      invalidateArtifacts()
    },
    onError: (e: Error) =>
      toast({ title: '状态更新失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const downloadMutation = useMutation({
    mutationFn: (a: SentinelArtifact) => sentinelApi.downloadArtifact(a),
    onError: (e: Error) =>
      toast({ title: '下载失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const publishMutation = useMutation({
    mutationFn: (id: number) => sentinelApi.publishArtifact(id),
    onSuccess: (res) => {
      toast({ title: `已发布到 PoC 库（模板 #${res.template_id}）`, duration: 6 })
      invalidateArtifacts()
    },
    onError: (e: Error) =>
      toast({ title: '发布失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const createMutation = useMutation({
    mutationFn: (body: { kind: SentinelArtifactKind; title: string; content: string }) =>
      sentinelApi.createFindingArtifact(finding.id, body),
    onSuccess: (a) => {
      toast({ title: `产物已创建（draft，#${a.id}）` })
      setForm(CREATE_FORM_INIT)
      invalidateArtifacts()
    },
    onError: (e: Error) =>
      toast({ title: '创建失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-border bg-card px-3 py-2.5">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[13px] font-medium text-foreground">{finding.title}</span>
          <SeverityTag severity={finding.severity} />
          <FindingStatusTag status={finding.status} />
          <span className="ml-auto font-mono text-[10.5px] text-muted-foreground">{finding.vuln_class}</span>
        </div>
        <div className="mt-1 flex items-center gap-2 text-[10.5px] text-muted-foreground">
          <Link
            to={`/sentinel/commits/${finding.commit_id}`}
            className="font-mono text-primary hover:underline"
          >
            {finding.sha.slice(0, 8)}
          </Link>
          <span className="font-mono">{finding.repo_full_name || finding.repo_id}</span>
          <span className="truncate">{finding.subject}</span>
        </div>
      </div>

      <div>
        <div className="mb-1.5 flex items-center gap-2">
          <span className="text-[12px] font-semibold text-foreground">产物</span>
          <span className="text-[10.5px] text-muted-foreground">{artifacts.length} 条</span>
          <Button
            size="small"
            type="text"
            className="ml-auto !px-1.5 text-[11px]"
            onClick={() => artifactsQuery.refetch()}
            loading={artifactsQuery.isFetching}
          >
            刷新
          </Button>
        </div>

        {artifactsQuery.error ? (
          <ErrorPanel error={artifactsQuery.error} onRetry={() => artifactsQuery.refetch()} />
        ) : null}

        {artifacts.length === 0 && !artifactsQuery.isLoading && !artifactsQuery.error ? (
          <EmptyBlock>
            还没有产物：可在「分析结果」让模型依据修复 diff 草拟 nuclei 模板，或在下方手工提交。
          </EmptyBlock>
        ) : null}

        <div className="space-y-2">
          {artifacts.map((a) => {
            const canDownload = a.status === 'verified'
            const canPublish = a.kind === 'nuclei' && a.status === 'verified'
            return (
              <div key={a.id} className="rounded-xl border border-border bg-card px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="rounded-full bg-secondary px-1.5 py-0.5 font-mono text-[9.5px] text-secondary-foreground">
                    {a.kind}
                  </span>
                  <span className="text-[12.5px] font-medium text-foreground">
                    {a.title || '(无标题)'}
                  </span>
                  <span className="ml-auto">
                    <ArtifactStatusSelect
                      status={a.status}
                      loading={statusMutation.isPending && statusMutation.variables?.id === a.id}
                      onChange={(next) => statusMutation.mutate({ id: a.id, status: next })}
                    />
                  </span>
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                  <span className="font-mono">{fmtTime(a.updated_at)}</span>
                  {a.path && <span className="truncate font-mono">{a.path}</span>}
                  <span className="ml-auto flex items-center gap-1">
                    <Tooltip title={canDownload ? undefined : '铁律：非 verified 产物不可下载'}>
                      <span>
                        <Button
                          size="small"
                          type="text"
                          icon={<Download size={11} />}
                          className="!px-1.5 text-[11px]"
                          disabled={!canDownload}
                          loading={
                            downloadMutation.isPending && downloadMutation.variables?.id === a.id
                          }
                          onClick={() => downloadMutation.mutate(a)}
                        >
                          下载
                        </Button>
                      </span>
                    </Tooltip>
                    <Popconfirm title="发布到 PoC 库？" onConfirm={() => publishMutation.mutate(a.id)}>
                      <Button
                        size="small"
                        type="text"
                        icon={<Upload size={11} />}
                        className="!px-1.5 text-[11px]"
                        disabled={!canPublish}
                        loading={publishMutation.isPending && publishMutation.variables === a.id}
                      >
                        发布
                      </Button>
                    </Popconfirm>
                  </span>
                </div>
                <ContentPreview content={a.content} />
              </div>
            )
          })}
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card px-3 py-2.5">
        <div className="mb-1.5 text-[12px] font-semibold text-foreground">新增产物</div>
        <div className="space-y-2">
          <Select
            value={form.kind}
            onChange={(kind) => setForm((f) => ({ ...f, kind: kind as SentinelArtifactKind }))}
            className="w-[170px]"
            options={KIND_OPTIONS}
          />
          <Input
            value={form.title}
            onChange={(e) => setForm((f) => ({ ...f, title: e.target.value }))}
            placeholder="标题"
            allowClear
          />
          <Input.TextArea
            value={form.content}
            onChange={(e) => setForm((f) => ({ ...f, content: e.target.value }))}
            placeholder="粘贴 PoC / nuclei 模板 / 报告内容"
            rows={5}
          />
          <Button
            type="primary"
            size="small"
            loading={createMutation.isPending}
            disabled={!form.content.trim()}
            onClick={() =>
              createMutation.mutate({ kind: form.kind, title: form.title.trim(), content: form.content })
            }
          >
            提交（落 draft 待审核）
          </Button>
        </div>
      </div>
    </div>
  )
}

export default function AnalysisArtifactsPage() {
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)
  const [active, setActive] = useState<SentinelFinding | null>(null)

  const findingsQuery = useQuery({
    queryKey: ['sentinel', 'findings', { status, page, size }],
    queryFn: () => sentinelApi.findings({ status: status || undefined, page, size }),
    refetchInterval: 60000,
  })
  const items = findingsQuery.data?.list ?? []
  const total = findingsQuery.data?.total ?? 0

  // 产物数：一页一条查询（含 content，与抽屉共用同一缓存 key），mutations 后按前缀失效
  const artifactCounts = useQueries({
    queries: items.map((f) => ({
      queryKey: ['sentinel', 'finding-artifacts', f.id] as const,
      queryFn: () => sentinelApi.findingArtifacts(f.id),
    })),
    combine: (results) => {
      const counts: Record<number, number> = {}
      results.forEach((r, i) => {
        if (r.data) counts[items[i].id] = r.data.length
      })
      return counts
    },
  })

  const columns: TableProps<SentinelFinding>['columns'] = [
    {
      title: '发现',
      key: 'title',
      render: (_, r) => (
        <div className="min-w-[240px]">
          <div className="flex items-center gap-1.5">
            <span className="text-[12.5px] font-medium text-foreground">{r.title}</span>
            <span className="rounded-full bg-secondary px-1.5 py-0.5 font-mono text-[9.5px] text-secondary-foreground">
              #{r.id}
            </span>
          </div>
          <div className="truncate text-[10.5px] text-muted-foreground">{r.repo_full_name || r.repo_id}</div>
        </div>
      ),
    },
    {
      title: 'SHA',
      key: 'sha',
      width: 110,
      render: (_, r) => (
        <Link
          to={`/sentinel/commits/${r.commit_id}`}
          className="font-mono text-[11px] text-primary hover:underline"
          onClick={(e) => e.stopPropagation()}
        >
          {r.sha.slice(0, 8)}
        </Link>
      ),
    },
    {
      title: '类型',
      key: 'vuln_class',
      width: 130,
      render: (_, r) => (
        <>
          <span className="font-mono text-[10.5px] text-muted-foreground">{r.vuln_class}</span>
          {r.grade ? <FindingGradeTag grade={r.grade} /> : null}
        </>
      ),
    },
    { title: '严重度', key: 'severity', width: 90, render: (_, r) => <SeverityTag severity={r.severity} /> },
    { title: '状态', key: 'status', width: 90, render: (_, r) => <FindingStatusTag status={r.status} /> },
    {
      title: '产物数',
      key: 'artifacts',
      width: 80,
      render: (_, r) => {
        const n = artifactCounts[r.id]
        return n === undefined ? (
          <span className="text-[10.5px] text-muted-foreground">…</span>
        ) : (
          <span className="font-mono text-[11px] tabular-nums">{n}</span>
        )
      },
    },
    {
      title: '落地时间',
      key: 'time',
      width: 110,
      render: (_, r) => (
        <span className="font-mono text-[10.5px] text-muted-foreground">{fmtTime(r.created_at)}</span>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        title="分析产物"
        desc="发现的证据链：PoC / nuclei / 报告 / 补丁，verified 前不可下载与发布"
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
        <span className="ml-auto text-[10.5px] text-muted-foreground">
          点行打开产物抽屉 · 共 {total} 条发现
        </span>
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        {!findingsQuery.isLoading && items.length === 0 && !findingsQuery.error ? (
          <div className="p-3">
            <EmptyBlock>
              还没有发现。发现由判定命中产生：先在「分析结果」里让提交跑出安全修复。
            </EmptyBlock>
          </div>
        ) : (
          <Table
            rowKey={(r) => r.id}
            size="middle"
            loading={findingsQuery.isLoading}
            columns={columns}
            dataSource={items}
            onRow={(r) => ({ onClick: () => setActive(r), className: 'cursor-pointer' })}
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
        open={!!active}
        onClose={() => setActive(null)}
        width={640}
        title={active ? `发现 #${active.id} · ${active.title}` : ''}
        destroyOnClose
      >
        {active && <FindingArtifacts finding={active} />}
      </Drawer>
    </div>
  )
}

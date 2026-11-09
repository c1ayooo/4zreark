import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Select, Table, Tag, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { ExternalLink, Search, ShieldAlert } from 'lucide-react'
import { githubMonitorApi, type GitHubFinding } from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { safeExternalURL } from '@/lib/safeUrl'
import { cn, formatDate } from '@/lib/utils'
import {
  FINDING_STATUS_LABEL,
  FINDING_STATUS_OPTIONS,
  LEAK_GLOBAL_FINDINGS_KEY,
  LEAK_OPS_KEY,
  VERIFY_STATUS_OPTIONS,
  severityClass,
} from './shared'

const statusClass: Record<string, string> = {
  new: 'text-primary',
  confirmed: 'text-destructive',
  false_positive: 'text-amber-500',
  ignored: 'text-muted-foreground',
  resolved: 'text-emerald-500',
}

/** 全局命中列表：不带项目过滤，展示全库 findings；H4 语义下不显示明文。 */
export function GlobalFindingsTable() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState('')
  const [keyword, setKeyword] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)

  const findingsQuery = useQuery({
    queryKey: [...LEAK_GLOBAL_FINDINGS_KEY, { status, keyword, q, page }],
    queryFn: () =>
      githubMonitorApi.globalFindings({
        status: status || undefined,
        keyword: keyword || undefined,
        q: q || undefined,
        page,
        page_size: 20,
      }),
    refetchInterval: 60000,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: LEAK_GLOBAL_FINDINGS_KEY })
    queryClient.invalidateQueries({ queryKey: LEAK_OPS_KEY })
  }

  const statusMutation = useMutation({
    mutationFn: ({ fid, next }: { fid: string; next: string }) => githubMonitorApi.globalUpdateFindingStatus(fid, next),
    onSuccess: () => {
      toast({ title: '已更新' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '处置失败', description: e.message, variant: 'destructive' }),
  })

  const verifyMutation = useMutation({
    mutationFn: ({ fid, verifyStatus }: { fid: string; verifyStatus: string }) =>
      githubMonitorApi.globalRecordVerifyResult(fid, { verify_status: verifyStatus }),
    onSuccess: () => {
      toast({ title: '验证结论已回写' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '回写失败', description: e.message, variant: 'destructive' }),
  })

  const columns: TableProps<GitHubFinding>['columns'] = [
    {
      title: '类型 / 仓库',
      key: 'repo',
      width: 260,
      render: (_, f) => (
        <div className="space-y-1">
          <div className="flex items-center gap-1.5">
            <Tag className={cn('m-0', severityClass(f.severity))}>{f.secret_type}</Tag>
            <span className="text-[10px] text-muted-foreground">{f.confidence}</span>
          </div>
          <a
            href={safeExternalURL(f.html_url) ?? undefined}
            target="_blank"
            rel="noreferrer"
            className="block max-w-[240px] truncate font-mono text-xs hover:underline"
          >
            {f.repository}
          </a>
          <Tooltip title={`${f.path}${f.line ? ':' + f.line : ''}`}>
            <span className="block max-w-[240px] truncate text-[10px] text-muted-foreground">{f.path}</span>
          </Tooltip>
        </div>
      ),
    },
    {
      title: '规则',
      dataIndex: 'rule_name',
      key: 'rule_name',
      width: 150,
      ellipsis: true,
      render: (v: string) => <span className="text-xs">{v}</span>,
    },
    {
      title: '验证',
      dataIndex: 'verify_status',
      key: 'verify_status',
      width: 120,
      render: (v: string, f) => (
        <Select
          size="small"
          className="w-24"
          value={v || undefined}
          placeholder="未验证"
          allowClear
          options={VERIFY_STATUS_OPTIONS}
          loading={verifyMutation.isPending && verifyMutation.variables?.fid === f.id}
          onChange={(val) => val && verifyMutation.mutate({ fid: f.id, verifyStatus: val })}
        />
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => (
        <span className={cn('text-xs', statusClass[v] ?? 'text-muted-foreground')}>
          {FINDING_STATUS_LABEL[v] ?? v}
        </span>
      ),
    },
    {
      title: '首次 / 最近发现',
      key: 'times',
      width: 150,
      render: (_, f) => (
        <div className="text-[10px] leading-relaxed text-muted-foreground">
          <div>{formatDate(f.first_seen_at ?? f.first_seen ?? '')}</div>
          <div>{formatDate(f.last_seen_at ?? f.last_seen ?? '')}</div>
        </div>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      render: (_, f) => (
        <div className="flex flex-wrap gap-1.5">
          {f.status !== 'confirmed' && (
            <Button type="link" size="small" className="h-auto p-0 text-xs" onClick={() => statusMutation.mutate({ fid: f.id, next: 'confirmed' })}>
              确认
            </Button>
          )}
          {f.status !== 'false_positive' && (
            <Button type="link" size="small" className="h-auto p-0 text-xs" onClick={() => statusMutation.mutate({ fid: f.id, next: 'false_positive' })}>
              误报
            </Button>
          )}
          {f.status !== 'ignored' && (
            <Button type="link" size="small" className="h-auto p-0 text-xs" onClick={() => statusMutation.mutate({ fid: f.id, next: 'ignored' })}>
              忽略
            </Button>
          )}
          <Button type="link" size="small" className="h-auto p-0 text-xs" onClick={() => statusMutation.mutate({ fid: f.id, next: 'resolved' })}>
            处置
          </Button>
          <a href={safeExternalURL(f.html_url) ?? undefined} target="_blank" rel="noreferrer" className="text-xs">
            <ExternalLink className="inline size-3" /> 原文
          </a>
        </div>
      ),
    },
  ]

  const items = findingsQuery.data?.data?.items ?? []

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <ShieldAlert className="size-4 text-primary" /> 全局命中
          <span className="text-xs font-normal text-muted-foreground">
            共 {findingsQuery.data?.data?.total ?? 0} 条 · 全库，不按项目过滤
          </span>
        </div>
        <div className="flex flex-wrap gap-2">
          <Select
            size="small"
            className="w-32"
            value={status}
            onChange={(v) => {
              setStatus(v)
              setPage(1)
            }}
            options={FINDING_STATUS_OPTIONS}
          />
          <Input
            size="small"
            className="w-44"
            prefix={<Search className="size-3" />}
            placeholder="规则 / 仓库 / 路径"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onPressEnter={() => setPage(1)}
            allowClear
          />
          <Input
            size="small"
            className="w-40"
            placeholder="关键词精确筛选"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onPressEnter={() => setPage(1)}
            allowClear
          />
          <Button size="small" onClick={() => findingsQuery.refetch()}>
            刷新
          </Button>
        </div>
      </div>
      <Table<GitHubFinding>
        rowKey="id"
        columns={columns}
        dataSource={items}
        loading={findingsQuery.isLoading}
        size="small"
        tableLayout="fixed"
        scroll={{ x: 980 }}
        locale={{ emptyText: '暂无命中——规则生效后每轮巡查自动补充' }}
        expandable={{
          expandedRowRender: (f) => (
            <div className="space-y-1.5 text-xs">
              <div className="text-muted-foreground">脱敏摘录（H4：明文不出 API）</div>
              <pre className="m-0 max-h-32 overflow-auto rounded-lg border border-border bg-muted/30 px-2 py-1 font-mono text-[11px] leading-relaxed">
                {f.masked_excerpt || '—'}
              </pre>
              <div className="flex flex-wrap gap-4 text-[10px] text-muted-foreground">
                {f.secret_key && <span>字段：<code>{f.secret_key}</code></span>}
                {f.fingerprint && <span>指纹：<code>{f.fingerprint.slice(0, 16)}…</code></span>}
                {f.verify_evidence && <span>验证依据：{f.verify_evidence}</span>}
                {f.source_updated_at && <span>源文件提交：{formatDate(f.source_updated_at)}</span>}
              </div>
            </div>
          ),
        }}
        pagination={{
          current: page,
          pageSize: 20,
          total: findingsQuery.data?.data?.total ?? 0,
          showSizeChanger: false,
          onChange: setPage,
          hideOnSinglePage: true,
        }}
      />
    </div>
  )
}

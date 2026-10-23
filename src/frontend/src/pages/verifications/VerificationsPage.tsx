import { useEffect, useState } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { RefreshCw, RotateCcw, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { Button, Card, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { projectApi } from '@/api/projects'
import { verificationApi, type VerificationRow } from '@/api/verifications'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

const STATUS_OPTIONS = [
  { value: 'all', label: '全部状态' },
  { value: 'verified', label: '可达' },
  { value: 'failed', label: '失败' },
  { value: 'inconclusive', label: '不确定' },
]

const statusLabel: Record<string, string> = {
  verified: '可达',
  failed: '失败',
  inconclusive: '不确定',
  pending: '待验证',
}

const statusVariant = (status: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (status === 'verified') return 'default'
  if (status === 'failed') return 'destructive'
  if (status === 'inconclusive') return 'outline'
  return 'secondary'
}

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'default' | 'secondary' | 'destructive' | 'outline') =>
  variant === 'default'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : ''

export default function VerificationsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')
  const [projectId, setProjectId] = useState('0')
  const [status, setStatus] = useState('all')
  const [reason, setReason] = useState('')
  const debouncedReason = useDebouncedValue(reason)
  useEffect(() => { setPage(1) }, [debouncedReason])
  const [page, setPage] = useState(1)
  const pageSize = 30

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const stats = useQuery({
    queryKey: ['verification-stats', projectId],
    queryFn: () => verificationApi.stats(Number(projectId) || undefined),
  })
  const list = useQuery({
    queryKey: ['verifications', projectId, status, debouncedReason, page],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      verificationApi.list({
        project_id: Number(projectId) || undefined,
        status: status === 'all' ? undefined : status,
        reason_code: debouncedReason.trim() || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const preview = useMutation({
    mutationFn: () => verificationApi.previewBatch(Number(projectId) || 0),
    onSuccess: (res) => {
      toast({
        title: '批量复验预览',
        description: `当前筛选会重置 ${res.data?.total ?? 0} 个站点`,
      })
    },
    onError: (e: any) =>
      toast({ title: '预览失败', description: e?.message, variant: 'destructive' }),
  })

  const execute = useMutation({
    mutationFn: () => verificationApi.executeBatch(Number(projectId) || 0),
    onSuccess: (res) => {
      const d = res.data
      toast({
        title: '批量复验完成',
        description: `匹配 ${d?.matched ?? 0}，重置 ${d?.recheck?.reset ?? 0}，跳过 ${
          d?.recheck?.skipped ?? 0
        }${d?.truncated ? '（已截断到 500 条）' : ''}`,
      })
      queryClient.invalidateQueries({ queryKey: ['verifications'] })
      queryClient.invalidateQueries({ queryKey: ['verification-stats'] })
    },
    onError: (e: any) =>
      toast({ title: '批量复验失败', description: e?.message, variant: 'destructive' }),
  })

  const singleRecheck = useMutation({
    mutationFn: (siteId: number) => verificationApi.recheck([siteId]),
    onSuccess: (res) => {
      toast({ title: '已重置复验', description: `reset=${res.data?.reset ?? 0}` })
      queryClient.invalidateQueries({ queryKey: ['verifications'] })
    },
    onError: (e: any) =>
      toast({ title: '复验失败', description: e?.message, variant: 'destructive' }),
  })

  const rows: VerificationRow[] = list.data?.data?.items ?? []
  const total = list.data?.data?.total ?? 0
  const byStatus = stats.data?.data?.by_status ?? []
  const countOf = (key: string) => byStatus.find((s) => s.key === key)?.count ?? 0
  const allCount = byStatus.reduce((sum, s) => sum + s.count, 0)

  const cards = [
    { key: 'all', label: '验证流水', value: allCount, icon: ShieldQuestion },
    { key: 'verified', label: '可达', value: countOf('verified'), icon: ShieldCheck },
    { key: 'failed', label: '失败', value: countOf('failed'), icon: ShieldAlert },
    { key: 'inconclusive', label: '不确定', value: countOf('inconclusive'), icon: ShieldQuestion },
  ]

  const columns: TableProps<VerificationRow>['columns'] = [
    {
      title: '时间',
      dataIndex: 'observed_at',
      key: 'observed_at',
      width: 170,
      render: (v: string) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">{formatDate(v)}</span>
      ),
    },
    {
      title: '站点',
      dataIndex: 'host',
      key: 'host',
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '结果',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => (
        <Tag className={badgeCls(statusVariant(v))}>{statusLabel[v] || v}</Tag>
      ),
    },
    {
      title: '原因',
      dataIndex: 'reason_code',
      key: 'reason_code',
      render: (v: string) => <span className="text-xs">{v || '—'}</span>,
    },
    {
      title: 'HTTP',
      dataIndex: 'http_status',
      key: 'http_status',
      width: 90,
      render: (v: number) => <span className="text-xs">{v || '—'}</span>,
    },
    {
      title: '尝试',
      dataIndex: 'attempts',
      key: 'attempts',
      width: 70,
      render: (v: number) => <span className="text-xs">{v}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      align: 'right',
      render: (_, r) =>
        isAdmin && (
          <Button
            type="text"
            size="small"
            disabled={singleRecheck.isPending}
            onClick={() => singleRecheck.mutate(r.site_id)}
          >
            复验
          </Button>
        ),
    },
  ]

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">验证状态</h1>
          <p className="text-sm text-muted-foreground">
            可达性历史与失败原因；按项目批量重置 attempts 后，下一轮回归会立即重跑
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select
            className="w-44"
            value={projectId}
            placeholder="全部项目"
            onChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
            options={[
              { value: '0', label: '全部项目' },
              ...(projects.data?.data ?? []).map((p) => ({ value: String(p.id), label: p.name })),
            ]}
          />
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((c) => {
          const Icon = c.icon
          return (
            <Card
              key={c.key}
              title={<span className="text-sm font-medium">{c.label}</span>}
              extra={<Icon className="h-4 w-4 text-muted-foreground" />}
            >
              <div className="text-2xl font-bold">{c.value}</div>
              <p className="text-muted-foreground text-xs">
                {c.key === 'all' ? '按当前项目筛选' : '占全部流水的比例'}
              </p>
            </Card>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          className="w-40"
          value={status}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
          options={STATUS_OPTIONS}
        />
        <Input
          className="w-48"
          placeholder="失败原因，如 conn_fail"
          value={reason}
          onChange={(e) => {
            setReason(e.target.value)
            setPage(1)
          }}
        />
        {isAdmin && (
          <>
            <Button size="small" onClick={() => preview.mutate()}>
              预览批量复验
            </Button>
            <Button type="primary" size="small" onClick={() => execute.mutate()} disabled={execute.isPending}>
              <RotateCcw className="mr-2 h-4 w-4" />
              执行批量复验
            </Button>
          </>
        )}
      </div>

      <div className="rounded-md border">
        <Table
          columns={columns}
          dataSource={rows}
          rowKey="id"
          loading={list.isLoading}
          locale={{ emptyText: <EmptyState title="暂无验证流水" className="border-0" /> }}
          pagination={{
            current: page,
            pageSize,
            total,
            showQuickJumper: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p) => setPage(p),
          }}
        />
      </div>
    </div>
  )
}

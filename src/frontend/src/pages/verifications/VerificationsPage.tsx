import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, RotateCcw, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'

import { projectApi } from '@/api/projects'
import { verificationApi, type VerificationRow } from '@/api/verifications'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'

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

export default function VerificationsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')
  const [projectId, setProjectId] = useState('0')
  const [status, setStatus] = useState('all')
  const [reason, setReason] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 30

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const stats = useQuery({
    queryKey: ['verification-stats', projectId],
    queryFn: () => verificationApi.stats(Number(projectId) || undefined),
  })
  const list = useQuery({
    queryKey: ['verifications', projectId, status, reason, page],
    queryFn: () =>
      verificationApi.list({
        project_id: Number(projectId) || undefined,
        status: status === 'all' ? undefined : status,
        reason_code: reason.trim() || undefined,
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
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const byStatus = stats.data?.data?.by_status ?? []
  const countOf = (key: string) => byStatus.find((s) => s.key === key)?.count ?? 0
  const allCount = byStatus.reduce((sum, s) => sum + s.count, 0)

  const cards = [
    { key: 'all', label: '验证流水', value: allCount, icon: ShieldQuestion },
    { key: 'verified', label: '可达', value: countOf('verified'), icon: ShieldCheck },
    { key: 'failed', label: '失败', value: countOf('failed'), icon: ShieldAlert },
    { key: 'inconclusive', label: '不确定', value: countOf('inconclusive'), icon: ShieldQuestion },
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
            value={projectId}
            onValueChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="全部项目" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">全部项目</SelectItem>
              {(projects.data?.data ?? []).map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((c) => {
          const Icon = c.icon
          return (
            <Card key={c.key}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">{c.label}</CardTitle>
                <Icon className="text-muted-foreground h-4 w-4" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{c.value}</div>
                <p className="text-muted-foreground text-xs">
                  {c.key === 'all' ? '按当前项目筛选' : '占全部流水的比例'}
                </p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
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
            <Button variant="outline" size="sm" onClick={() => preview.mutate()}>
              预览批量复验
            </Button>
            <Button size="sm" onClick={() => execute.mutate()} disabled={execute.isPending}>
              <RotateCcw className="mr-2 h-4 w-4" />
              执行批量复验
            </Button>
          </>
        )}
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>时间</TableHead>
              <TableHead>站点</TableHead>
              <TableHead>结果</TableHead>
              <TableHead>原因</TableHead>
              <TableHead>HTTP</TableHead>
              <TableHead>尝试</TableHead>
              <TableHead className="text-right">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.id}>
                <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
                  {formatDate(r.observed_at)}
                </TableCell>
                <TableCell className="font-mono text-xs">{r.host}</TableCell>
                <TableCell>
                  <Badge variant={statusVariant(r.status)}>
                    {statusLabel[r.status] || r.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs">{r.reason_code || '—'}</TableCell>
                <TableCell className="text-xs">{r.http_status || '—'}</TableCell>
                <TableCell className="text-xs">{r.attempts}</TableCell>
                <TableCell className="text-right">
                  {isAdmin && (
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={singleRecheck.isPending}
                      onClick={() => singleRecheck.mutate(r.site_id)}
                    >
                      复验
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="text-muted-foreground py-10 text-center text-sm">
                  暂无验证流水
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="text-muted-foreground flex items-center justify-between text-xs">
        <span>
          共 {total} 条 · 第 {page}/{totalPages} 页
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            上一页
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            下一页
          </Button>
        </div>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetApi, Site } from '@/api/assets'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useToast } from '@/components/ui/use-toast'
import { RefreshCw, Search, Radar, MoreHorizontal, ShieldCheck, ShieldAlert, Lock } from 'lucide-react'

const stateLabel: Record<string, string> = {
  reachable: '可访问',
  lost: '失联',
  archived: '已归档',
  pending: '待验证',
}

const stateVariant = (state: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (state === 'reachable') return 'default'
  if (state === 'lost') return 'destructive'
  if (state === 'archived') return 'outline'
  return 'secondary'
}

const verdictLabel: Record<string, string> = {
  reachable: '可达',
  unreachable: '不可达',
  inconclusive: '判不出（环境噪声）',
}

export default function AssetsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [q, setQ] = useState('')
  const [appliedQ, setAppliedQ] = useState('')
  const [projectId, setProjectId] = useState<string>('0')
  const [page, setPage] = useState(1)
  const pageSize = 20

  const overview = useQuery({ queryKey: ['asset-overview'], queryFn: () => assetApi.overview() })
  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const list = useQuery({
    queryKey: ['assets', page, appliedQ, projectId],
    queryFn: () =>
      assetApi.list({
        page,
        page_size: pageSize,
        q: appliedQ || undefined,
        project_id: Number(projectId) || undefined,
      }),
  })

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['assets'] })
    queryClient.invalidateQueries({ queryKey: ['asset-overview'] })
  }

  const probe = useMutation({
    mutationFn: (site: Site) => assetApi.probe(site.id),
    onSuccess: (res) => {
      const verdict = res.data?.verdict ?? ''
      toast({
        title: `${res.data?.host ?? ''} ${verdictLabel[verdict] ?? verdict}`,
        description: (res.data?.endpoints ?? [])
          .map((e) => `${e.scheme}:${e.port} → ${e.outcome}${e.status_code ? ` (${e.status_code})` : ''}`)
          .join(' · '),
        variant: verdict === 'unreachable' ? 'destructive' : 'default',
      })
      refresh()
    },
    onError: (e: any) => toast({ title: '探测失败', description: e?.message, variant: 'destructive' }),
  })

  const verify = useMutation({
    mutationFn: ({ site, reachable }: { site: Site; reachable: boolean }) =>
      assetApi.verify(site.id, {
        reachable,
        status_code: reachable ? site.http_status || 200 : 0,
        reason: reachable ? '' : 'manual_failed',
      }),
    onSuccess: () => {
      toast({ title: '人工判定已记录' })
      refresh()
    },
    onError: (e: any) => toast({ title: '操作失败', description: e?.message, variant: 'destructive' }),
  })

  const protect = useMutation({
    mutationFn: (site: Site) => assetApi.protect(site.id, 90),
    onSuccess: () => toast({ title: '已设 90 天保护期，期间不会被自动归档' }),
    onError: (e: any) => toast({ title: '设置失败', description: e?.message, variant: 'destructive' }),
  })

  const applyQuery = () => {
    const next = q.trim()
    if (!next) {
      setAppliedQ('')
      setPage(1)
      return
    }
    assetApi
      .checkQuery(next)
      .then(() => {
        setAppliedQ(next)
        setPage(1)
      })
      .catch((e: any) => toast({ title: '查询语法错误', description: e?.message, variant: 'destructive' }))
  }

  const items = list.data?.data?.items ?? []
  const total = list.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const stats = overview.data?.data
  const busy = probe.isPending || verify.isPending || protect.isPending

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">资产探索</h1>
          <p className="text-sm text-muted-foreground">
            原始记录 {(stats?.record_count ?? 0).toLocaleString()} 条 · 归并站点{' '}
            {(stats?.sites ?? 0).toLocaleString()} 个 · 域名 {(stats?.domains ?? 0).toLocaleString()} 个 ·
            可访问 {(stats?.verified_sites ?? 0).toLocaleString()} 个 · 失联{' '}
            {(stats?.lost_count ?? 0).toLocaleString()} 个
          </p>
        </div>
        <Button variant="outline" onClick={() => list.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[320px]">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="pl-9 font-mono text-sm"
            placeholder='status_code="200" && domain="example.com"'
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && applyQuery()}
          />
        </div>
        <Button onClick={applyQuery}>查询</Button>
        <Button
          variant="ghost"
          onClick={() => {
            setQ('')
            setAppliedQ('')
            setPage(1)
          }}
        >
          清空
        </Button>
        <Select value={projectId} onValueChange={(v) => { setProjectId(v); setPage(1) }}>
          <SelectTrigger className="w-[220px]">
            <SelectValue placeholder="全部项目" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="0">全部项目</SelectItem>
            {(projects.data?.data ?? []).map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}（{p.asset_count}）
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {appliedQ && (
        <div className="rounded border bg-muted/40 px-3 py-2 font-mono text-xs text-muted-foreground">
          q = {appliedQ}
        </div>
      )}

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>资产</TableHead>
              <TableHead className="w-[90px]">状态码</TableHead>
              <TableHead>标题</TableHead>
              <TableHead className="w-[120px]">项目</TableHead>
              <TableHead className="w-[110px]">发现时间</TableHead>
              <TableHead className="w-[110px]">连通</TableHead>
              <TableHead className="w-[150px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isLoading && (
              <TableRow>
                <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!list.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                  没有匹配的资产
                </TableCell>
              </TableRow>
            )}
            {items.map((s) => {
              const endpoints = s.endpoints ?? []
              return (
                <TableRow key={s.id}>
                  <TableCell>
                    <div className="font-mono text-sm">{s.value}</div>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      {endpoints.length > 0 ? (
                        endpoints.map((e) => (
                          <span
                            key={`${e.scheme}-${e.port}`}
                            title={`最近状态码 ${e.status_code || '—'}`}
                            className="rounded border px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground"
                          >
                            {e.scheme}:{e.port}
                          </span>
                        ))
                      ) : (
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {s.protocol}:{s.port}
                        </span>
                      )}
                      <span className="ml-1 text-[11px] text-muted-foreground">
                        {s.ip || '—'}
                        {s.technology_stack.length > 0 && ` · ${s.technology_stack.join(', ')}`}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant={s.http_status >= 200 && s.http_status < 400 ? 'default' : 'secondary'}>
                      {s.http_status || '—'}
                    </Badge>
                  </TableCell>
                  <TableCell className="max-w-[260px] truncate text-sm">{s.title || '—'}</TableCell>
                  <TableCell className="text-sm">{s.project_name}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {s.first_seen?.slice(0, 10)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={stateVariant(s.state)}>{stateLabel[s.state] ?? s.state}</Badge>
                    {s.consecutive_failures > 0 && (
                      <span className="ml-1 text-xs text-destructive">×{s.consecutive_failures}</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => probe.mutate(s)}
                        disabled={busy}
                      >
                        <Radar className="mr-1 h-3.5 w-3.5" /> 探测
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button size="sm" variant="ghost" disabled={busy}>
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => verify.mutate({ site: s, reachable: true })}>
                            <ShieldCheck className="mr-2 h-3.5 w-3.5" /> 人工标记可达
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => verify.mutate({ site: s, reachable: false })}>
                            <ShieldAlert className="mr-2 h-3.5 w-3.5" /> 人工标记失败
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => protect.mutate(s)}>
                            <Lock className="mr-2 h-3.5 w-3.5" /> 保护 90 天
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          共 {total.toLocaleString()} 条 · 第 {page} / {pages} 页
        </span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
            上一页
          </Button>
          <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>
            下一页
          </Button>
        </div>
      </div>
    </div>
  )
}

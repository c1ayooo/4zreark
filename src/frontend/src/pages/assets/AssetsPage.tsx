import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  assetApi,
  AssetCatalog,
  AssetKind,
  AssetView,
  DomainRow,
  EndpointRow,
  IPRow,
  Site,
} from '@/api/assets'
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

const KINDS: { value: AssetKind; label: string }[] = [
  { value: 'site', label: '站点' },
  { value: 'domain', label: '域名' },
  { value: 'ip', label: 'IP' },
]

const CATALOGS: { value: AssetCatalog; label: string }[] = [
  { value: 'all', label: '全部' },
  { value: 'verified', label: '已验证' },
  { value: 'candidates', label: '候选' },
]

const VIEWS: { value: AssetView; label: string }[] = [
  { value: '', label: '缺省' },
  { value: 'clues', label: '线索' },
  { value: 'lost', label: '失联' },
  { value: 'icons', label: '图标' },
  { value: 'technologies', label: '技术栈' },
]

/** 三段切换的小控件 */
function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
}: {
  value: T
  options: { value: T; label: string }[]
  onChange: (v: T) => void
  disabled?: boolean
}) {
  return (
    <div className="inline-flex overflow-hidden rounded-md border">
      {options.map((o) => (
        <button
          key={o.value || 'default'}
          type="button"
          disabled={disabled}
          onClick={() => onChange(o.value)}
          className={
            'px-3 py-1.5 text-sm transition-colors ' +
            (value === o.value
              ? 'bg-primary text-primary-foreground'
              : 'bg-background hover:bg-muted disabled:opacity-50')
          }
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

export default function AssetsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [q, setQ] = useState('')
  const [appliedQ, setAppliedQ] = useState('')
  const [projectId, setProjectId] = useState<string>('0')
  const [kind, setKind] = useState<AssetKind>('site')
  const [catalog, setCatalog] = useState<AssetCatalog>('all')
  const [view, setView] = useState<AssetView>('')
  const [siteGroup, setSiteGroup] = useState(true)
  const [page, setPage] = useState(1)
  const pageSize = 20

  const overview = useQuery({ queryKey: ['asset-overview'], queryFn: () => assetApi.overview() })
  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const clusterView = view === 'icons' || view === 'technologies'
  const list = useQuery({
    queryKey: ['assets', page, appliedQ, projectId, kind, catalog, view, siteGroup],
    enabled: !clusterView,
    queryFn: () =>
      assetApi.list({
        page,
        page_size: pageSize,
        q: appliedQ || undefined,
        project_id: Number(projectId) || undefined,
        kind,
        catalog,
        view,
        site_group: siteGroup ? 1 : 0,
      }),
  })

  const iconClusters = useQuery({
    queryKey: ['asset-icons', projectId, appliedQ, page],
    enabled: view === 'icons',
    queryFn: () =>
      assetApi.icons({
        project_id: Number(projectId) || undefined,
        q: appliedQ || undefined,
        page,
        page_size: 60,
      }),
  })

  const techClusters = useQuery({
    queryKey: ['asset-technologies', projectId, appliedQ, page],
    enabled: view === 'technologies',
    queryFn: () =>
      assetApi.technologies({
        project_id: Number(projectId) || undefined,
        q: appliedQ || undefined,
        page,
        page_size: 60,
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
        description: [
          ...(res.data?.endpoints ?? []).map(
            (e) => `${e.scheme}:${e.port} → ${e.outcome}${e.status_code ? ` (${e.status_code})` : ''}`
          ),
          ...(res.data?.tech?.length ? [`指纹：${res.data.tech.join(' / ')}`] : []),
        ].join(' · '),
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

  // 切换粒度会清掉视图与口径（它们对新粒度没有意义）；切换视图只保留项目与查询串
  const changeKind = (v: AssetKind) => {
    setKind(v)
    setView('')
    setCatalog('all')
    setPage(1)
  }
  const changeView = (v: AssetView) => {
    setView(v)
    setCatalog('all')
    setPage(1)
  }

  const data = list.data?.data
  const items = data?.items ?? []
  const total = data?.total ?? 0
  const size = data?.page_size ?? pageSize
  const pages = Math.max(1, Math.ceil(total / size))
  const stats = overview.data?.data
  const policy = data?.connectivity_policy
  const busy = probe.isPending || verify.isPending || protect.isPending
  const expanded = kind === 'site' && !siteGroup

  const colCount = expanded ? 7 : kind === 'site' ? 7 : 5

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">资产探索</h1>
          <p className="text-sm text-muted-foreground">
            原始记录 {(stats?.record_count ?? 0).toLocaleString()} 条 · 归并站点{' '}
            {(stats?.sites ?? 0).toLocaleString()} 个 · 域名 {(stats?.domains ?? 0).toLocaleString()} 个 ·
            可访问 {(stats?.verified_sites ?? 0).toLocaleString()} 个 · 失联{' '}
            {(stats?.lost_count ?? 0).toLocaleString()} 个
          </p>
          {policy && (
            <p className="mt-1 text-xs text-muted-foreground">
              判定口径：连续失败 {policy.failure_threshold} 次转失联 · 重试间隔 {policy.first_hours}/
              {policy.second_hours}/{policy.repeat_hours} 小时 · 失联 {policy.cleanup_days} 天后可归档
              {policy.auto_cleanup ? '（自动）' : '（手动）'}
            </p>
          )}
        </div>
        <Button variant="outline" onClick={() => list.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[300px]">
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
          <SelectTrigger className="w-[200px]">
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

      <div className="flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">粒度</span>
          <Segmented value={kind} options={KINDS} onChange={changeKind} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">口径</span>
          <Segmented value={catalog} options={CATALOGS} onChange={(v) => { setCatalog(v); setPage(1) }} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">视图</span>
          <Segmented value={view} options={VIEWS} onChange={changeView} />
        </div>
        {kind === 'site' && (
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={siteGroup}
              onChange={(e) => { setSiteGroup(e.target.checked); setPage(1) }}
            />
            按站点归并
          </label>
        )}
        <span className="ml-auto text-sm text-muted-foreground">
          共 {total.toLocaleString()} 条
        </span>
      </div>

      {appliedQ && (
        <div className="rounded border bg-muted/40 px-3 py-2 font-mono text-xs text-muted-foreground">
          q = {appliedQ}
        </div>
      )}

      {view === 'icons' && (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            共 {iconClusters.data?.data.total ?? 0} 组图标 · 点开站点看详情（图标按内容哈希去重）
          </p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {(iconClusters.data?.data.items ?? []).map((ic) => (
              <div key={ic.icon_sha256} className="flex flex-col items-center gap-2 rounded-md border p-3">
                <img
                  src={assetApi.iconURL(ic.icon_sha256)}
                  alt={ic.sample_host}
                  className="h-10 w-10 rounded"
                  onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
                />
                <div className="w-full truncate text-center text-xs" title={ic.sample_title || ic.sample_host}>
                  {ic.sample_title || ic.sample_host}
                </div>
                <div className="text-[11px] text-muted-foreground">{ic.site_count} 个站点</div>
              </div>
            ))}
            {!iconClusters.isLoading && (iconClusters.data?.data.items ?? []).length === 0 && (
              <div className="col-span-full rounded border border-dashed py-8 text-center text-sm text-muted-foreground">
                还没有采集到图标（探测站点时会顺手抓 favicon）
              </div>
            )}
          </div>
        </div>
      )}

      {view === 'technologies' && (
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            共 {techClusters.data?.data.total ?? 0} 种技术 · 数字是命中的站点数
          </p>
          <div className="flex flex-wrap gap-2">
            {(techClusters.data?.data.items ?? []).map((t) => (
              <span
                key={t.name}
                className="rounded-full border px-3 py-1 text-sm"
                title={`${t.site_count} 个站点`}
              >
                {t.name}
                <span className="ml-1 text-xs text-muted-foreground">{t.site_count}</span>
              </span>
            ))}
            {!techClusters.isLoading && (techClusters.data?.data.items ?? []).length === 0 && (
              <div className="w-full rounded border border-dashed py-8 text-center text-sm text-muted-foreground">
                还没有技术栈数据（需要先有指纹规则并探测过站点）
              </div>
            )}
          </div>
        </div>
      )}

      {!clusterView && data && data.view_supported === false && (
        <div className="rounded border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
          {data.note || '这个视图还没实现'}
        </div>
      )}

      {!clusterView && (!data || data.view_supported !== false) && (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{expanded ? '入口' : kind === 'site' ? '资产' : kind === 'domain' ? '域名' : 'IP'}</TableHead>
                {kind === 'site' && !expanded && <TableHead className="w-[90px]">状态码</TableHead>}
                {kind === 'site' && !expanded && <TableHead>标题</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="w-[120px]">项目</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="w-[110px]">发现时间</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="w-[110px]">连通</TableHead>}
                {expanded && <TableHead className="w-[90px]">协议</TableHead>}
                {expanded && <TableHead>标题</TableHead>}
                {expanded && <TableHead className="w-[90px]">记录数</TableHead>}
                {expanded && <TableHead className="w-[110px]">连通</TableHead>}
                {expanded && <TableHead className="w-[110px]">最近发现</TableHead>}
                {expanded && <TableHead className="w-[120px]">项目</TableHead>}
                {kind === 'domain' && <TableHead className="w-[100px]">站点数</TableHead>}
                {kind === 'domain' && <TableHead className="w-[100px]">可达</TableHead>}
                {kind === 'domain' && <TableHead className="w-[120px]">项目</TableHead>}
                {kind === 'ip' && <TableHead className="w-[100px]">站点数</TableHead>}
                {kind === 'ip' && <TableHead className="w-[100px]">域名数</TableHead>}
                {kind === 'ip' && <TableHead className="w-[110px]">最近发现</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="w-[150px]">操作</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.isLoading && (
                <TableRow>
                  <TableCell colSpan={colCount} className="py-8 text-center text-muted-foreground">
                    加载中…
                  </TableCell>
                </TableRow>
              )}
              {!list.isLoading && items.length === 0 && (
                <TableRow>
                  <TableCell colSpan={colCount} className="py-8 text-center text-muted-foreground">
                    没有匹配的资产
                  </TableCell>
                </TableRow>
              )}

              {kind === 'site' && !expanded &&
                (items as Site[]).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <div className="font-mono text-sm">{s.value}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-1">
                        {(s.endpoints ?? []).length > 0 ? (
                          (s.endpoints ?? []).map((e) => (
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
                    <TableCell className="text-xs text-muted-foreground">{s.first_seen?.slice(0, 10)}</TableCell>
                    <TableCell>
                      <Badge variant={stateVariant(s.state)}>{stateLabel[s.state] ?? s.state}</Badge>
                      {s.consecutive_failures > 0 && (
                        <span className="ml-1 text-xs text-destructive">×{s.consecutive_failures}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Button size="sm" variant="outline" onClick={() => probe.mutate(s)} disabled={busy}>
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
                ))}

              {expanded &&
                (items as EndpointRow[]).map((e) => (
                  <TableRow key={`${e.host}-${e.port}-${e.protocol}`}>
                    <TableCell>
                      <div className="font-mono text-sm">
                        {e.host}:{e.port}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        {e.value || '—'} · 站点 #{e.site_id} · 采集 {e.record_count} 次
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{e.protocol || '—'}</Badge>
                    </TableCell>
                    <TableCell className="max-w-[260px] truncate text-sm">{e.title || '—'}</TableCell>
                    <TableCell className="text-sm">{e.record_count}</TableCell>
                    <TableCell>
                      <Badge variant={stateVariant(e.state)}>{stateLabel[e.state] ?? e.state}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{e.last_seen?.slice(0, 10)}</TableCell>
                    <TableCell className="text-sm">{e.project_name}</TableCell>
                  </TableRow>
                ))}

              {kind === 'domain' &&
                (items as DomainRow[]).map((d) => (
                  <TableRow key={d.host}>
                    <TableCell className="font-mono text-sm">{d.host}</TableCell>
                    <TableCell className="text-sm">{d.site_count}</TableCell>
                    <TableCell className="text-sm">{d.reachable_count}</TableCell>
                    <TableCell className="text-sm">{d.project_name}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{d.last_seen?.slice(0, 10)}</TableCell>
                  </TableRow>
                ))}

              {kind === 'ip' &&
                (items as IPRow[]).map((r) => (
                  <TableRow key={r.ip}>
                    <TableCell className="font-mono text-sm">{r.ip}</TableCell>
                    <TableCell className="text-sm">{r.site_count}</TableCell>
                    <TableCell className="text-sm">{r.domain_count}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{r.last_seen?.slice(0, 10)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">#{r.project_id}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          共{' '}
          {(clusterView
            ? view === 'icons'
              ? iconClusters.data?.data.total ?? 0
              : techClusters.data?.data.total ?? 0
            : total
          ).toLocaleString()}{' '}
          条 · 第 {page} /{' '}
          {Math.max(
            1,
            Math.ceil(
              (clusterView
                ? view === 'icons'
                  ? iconClusters.data?.data.total ?? 0
                  : techClusters.data?.data.total ?? 0
                : total) / (clusterView ? 60 : size)
            )
          )}{' '}
          页
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

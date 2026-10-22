import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  assetApi,
  AssetCatalog,
  AssetKind,
  AssetView,
  DomainRow,
  EndpointRow,
  IPRow,
  RawRecordRow,
  Site,
} from '@/api/assets'
import { Button } from '@/components/ui/button'
import EmptyState from '@/components/common/EmptyState'
import CreateTaskFromAssetsDialog from '@/components/tasks/CreateTaskFromAssetsDialog'
import { Checkbox } from '@/components/ui/checkbox'
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
import { RefreshCw, Search, Radar, MoreHorizontal, ShieldCheck, ShieldAlert, Lock, Globe, Rocket, X } from 'lucide-react'

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

const priorityLabel = (p: string) => (p ? p.toUpperCase() : '—')

const priorityVariant = (p: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (p === 'p0' || p === 'p1') return 'destructive'
  if (p === 'p2') return 'default'
  if (p === 'p3') return 'secondary'
  return 'outline'
}

const riskTitle = (s: Site) => {
  const base = `风险评分 ${s.risk_score}`
  if (!s.risk_factors || s.risk_factors.length === 0) return base
  return [
    base,
    ...s.risk_factors.map((f) => `${f.points > 0 ? '+' : ''}${f.points} ${f.detail}`),
  ].join('\n')
}

// 站点 favicon。图标只在探测可达后采集，还没探过的站点显示占位。
function SiteIcon({ sha256, alt }: { sha256: string; alt: string }) {
  const [failed, setFailed] = useState(false)
  if (!sha256 || failed) {
    return <Globe className="text-muted-foreground size-4 shrink-0" />
  }
  return (
    <img
      src={assetApi.iconURL(sha256)}
      alt={alt}
      loading="lazy"
      className="size-6 shrink-0 rounded-sm object-contain"
      onError={() => setFailed(true)}
    />
  )
}

const verdictLabel: Record<string, string> = {
  reachable: '可达',
  unreachable: '不可达',
  inconclusive: '判不出（环境噪声）',
}

const KINDS: { value: AssetKind; label: string }[] = [
  { value: 'record', label: '原始记录' },
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

type AssetSort = 'first_seen' | 'risk'

const SORTS: { value: AssetSort; label: string }[] = [
  { value: 'first_seen', label: '最近发现' },
  { value: 'risk', label: '风险优先' },
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
              ? 'bg-foreground text-background'
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
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [q, setQ] = useState(() => searchParams.get('q') || '')
  const [appliedQ, setAppliedQ] = useState(() => searchParams.get('q') || '')
  const [projectId, setProjectId] = useState<string>(() => searchParams.get('project_id') || '0')
  const [kind, setKind] = useState<AssetKind>(() => {
    const v = searchParams.get('kind')
    return v === 'domain' || v === 'ip' || v === 'record' ? v : 'record'
  })
  const [catalog, setCatalog] = useState<AssetCatalog>(() => {
    const v = searchParams.get('catalog')
    return v === 'verified' || v === 'candidates' ? v : 'all'
  })
  const [view, setView] = useState<AssetView>(() => (searchParams.get('view') as AssetView) || '')
  const [siteGroup, setSiteGroup] = useState(() => searchParams.get('site_group') !== '0')
  const [sort, setSort] = useState<AssetSort>(() => (searchParams.get('sort') === 'risk' ? 'risk' : 'first_seen'))
  const [page, setPage] = useState(() => Math.max(1, Number(searchParams.get('page')) || 1))
  const [pageSize, setPageSize] = useState(() => {
    const n = Number(searchParams.get('page_size'))
    return [20, 50, 100, 200, 500].includes(n) ? n : 50
  })
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined])
  const cursor = cursorStack[cursorStack.length - 1]
  const clusterView = view === 'icons' || view === 'technologies'
  const riskSort = kind === 'site' && siteGroup && sort === 'risk'
  const cursorMode = !clusterView && !riskSort && (kind === 'site' ? siteGroup : true)

  // 外部入口（顶部全局搜索、分享链接）改了 q：先同步进列表状态，再让下方回写。
  const urlQ = searchParams.get('q') || ''
  useEffect(() => {
    if (urlQ !== appliedQ) {
      setQ(urlQ)
      setAppliedQ(urlQ)
      setPage(1)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [urlQ])

  // 所有筛选/分页同步进 URL：刷新、分享链接、浏览器后退都能还原完整视图。
  useEffect(() => {
    setPage(1)
    setCursorStack([undefined])
  }, [appliedQ, projectId, kind, catalog, view, siteGroup, sort, pageSize])

  useEffect(() => {
    // URL 上的 q 还没被应用时先跳过回写，否则会把外部传来的查询条件立即冲掉。
    if (urlQ !== appliedQ) return
    const next = new URLSearchParams()
    if (appliedQ) next.set('q', appliedQ)
    if (projectId !== '0') next.set('project_id', projectId)
    if (kind !== 'site') next.set('kind', kind)
    if (catalog !== 'all') next.set('catalog', catalog)
    if (view) next.set('view', view)
    if (!siteGroup) next.set('site_group', '0')
    if (sort === 'risk') next.set('sort', 'risk')
    if (pageSize !== 50) next.set('page_size', String(pageSize))
    if (!cursorMode && page > 1) next.set('page', String(page))
    setSearchParams(next, { replace: true })
  }, [appliedQ, urlQ, projectId, kind, catalog, view, siteGroup, sort, pageSize, page, cursorMode, setSearchParams])

  const overview = useQuery({ queryKey: ['asset-overview'], queryFn: () => assetApi.overview() })
  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const hasFilters = !!appliedQ || kind !== 'record' || catalog !== 'all' || !!view

  // 站点默认/域名/IP 用 keyset；风险排序、展开入口和聚类仍走 page。
  const list = useQuery({
    queryKey: ['assets', cursorMode ? `c:${cursor ?? ''}` : `p:${page}`, pageSize, appliedQ, projectId, kind, catalog, view, siteGroup, riskSort],
    enabled: !clusterView,
    staleTime: 30_000,
    queryFn: () =>
      assetApi.list({
        ...(cursorMode ? { cursor: cursor ?? '' } : { page }),
        page_size: pageSize,
        q: appliedQ || undefined,
        project_id: Number(projectId) || undefined,
        kind,
        catalog,
        view,
        site_group: siteGroup ? 1 : 0,
        sort: riskSort ? 'risk' : undefined,
      }),
  })

  const iconClusters = useQuery({
    queryKey: ['asset-icons', projectId, appliedQ, page],
    enabled: view === 'icons',
    staleTime: 30_000,
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
    staleTime: 30_000,
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

  // 项目筛选只改状态；URL 同步由上面的 useEffect 统一处理。
  const changeProject = (v: string) => {
    setProjectId(v)
    setPage(1)
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
    setSort('first_seen')
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
  const nextCursor = data?.next_cursor ?? ''
  const hasMore = data?.has_more ?? false
  const stats = overview.data?.data
  const policy = data?.connectivity_policy
  const busy = probe.isPending || verify.isPending || protect.isPending
  const expanded = kind === 'site' && !siteGroup

  const colCount = expanded ? 7 : kind === 'site' ? 10 : kind === 'record' ? 7 : 5

  // 资产多选：选中后可直接对这些资产派新任务（选资产 → 选类型 → 起任务）
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set())
  const [createOpen, setCreateOpen] = useState(false)
  const pageHosts = kind === 'site' && !expanded ? (items as Site[]).map((s) => s.value) : []
  const allPageSelected = pageHosts.length > 0 && pageHosts.every((h) => selectedHosts.has(h))
  const toggleHost = (host: string) => {
    setSelectedHosts((prev) => {
      const next = new Set(prev)
      if (next.has(host)) next.delete(host)
      else next.add(host)
      return next
    })
  }
  const togglePageHosts = () => {
    setSelectedHosts((prev) => {
      const next = new Set(prev)
      if (allPageSelected) pageHosts.forEach((h) => next.delete(h))
      else pageHosts.forEach((h) => next.add(h))
      return next
    })
  }

  // 大页（>=100 行）启用虚拟滚动：只渲染视口附近的站点行。
  const virtualize = kind === 'site' && !expanded && pageSize >= 100 && !clusterView
  const scrollRef = useRef<HTMLDivElement>(null)
  const rowVirtualizer = useVirtualizer({
    count: virtualize ? (items as Site[]).length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 68,
    overscan: 8,
  })
  const virtualItems = rowVirtualizer.getVirtualItems()

  const renderSiteRow = (s: Site, virtualIndex?: number) => (
    <TableRow
      key={s.id}
      ref={virtualIndex !== undefined ? rowVirtualizer.measureElement : undefined}
      data-index={virtualIndex}
      className="hover:bg-muted/40 cursor-pointer"
      data-state={selectedHosts.has(s.value) ? 'selected' : undefined}
      onClick={() => navigate(`/assets/${s.id}`)}
    >
      <TableCell onClick={(e) => e.stopPropagation()}>
        <Checkbox
          checked={selectedHosts.has(s.value)}
          onCheckedChange={() => toggleHost(s.value)}
          aria-label={`选择 ${s.value}`}
        />
      </TableCell>
      <TableCell>
        <div className="break-all text-sm font-medium">{s.value}</div>
        <div className="mt-1 flex flex-wrap items-center gap-1">
          {(s.endpoints ?? []).length > 0 ? (
            (s.endpoints ?? []).map((e) => (
              <span
                key={`${e.scheme}-${e.port}`}
                title={`最近状态码 ${e.status_code || '—'}`}
                className="rounded-sm bg-muted px-1.5 py-0.5 text-[13px] text-muted-foreground"
              >
                {e.scheme}:{e.port}
              </span>
            ))
          ) : (
            <span className="text-[13px] text-muted-foreground">
              {s.protocol}:{s.port}
            </span>
          )}
          <span className="ml-1 text-[13px] text-muted-foreground">
            {s.ip || '—'}
            {s.technology_stack.length > 0 && ` · ${s.technology_stack.join(', ')}`}
          </span>
        </div>
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <SiteIcon sha256={s.icon_sha256} alt={s.host} />
      </TableCell>
      <TableCell className="hidden text-right lg:table-cell">
        <Badge variant={priorityVariant(s.priority)} title={riskTitle(s)}>
          {priorityLabel(s.priority)} · {s.risk_score}
        </Badge>
      </TableCell>
      <TableCell className="hidden text-right sm:table-cell">
        <Badge variant={s.http_status >= 200 && s.http_status < 400 ? 'default' : 'secondary'}>
          {s.http_status || '—'}
        </Badge>
      </TableCell>
      <TableCell className="hidden max-w-[260px] truncate text-sm md:table-cell">{s.title || '—'}</TableCell>
      <TableCell className="hidden text-sm lg:table-cell">{s.project_name}</TableCell>
      <TableCell className="hidden text-right text-[13px] tabular-nums text-muted-foreground xl:table-cell">{s.first_seen?.slice(0, 10)}</TableCell>
      <TableCell>
        <Badge variant={stateVariant(s.state)}>{stateLabel[s.state] ?? s.state}</Badge>
        {s.consecutive_failures > 0 && (
          <span className="ml-1 text-[13px] text-destructive">×{s.consecutive_failures}</span>
        )}
      </TableCell>
      <TableCell className="hidden sm:table-cell" onClick={(e) => e.stopPropagation()}>
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
  )

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
            <p className="mt-1 text-[13px] text-muted-foreground">
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
            placeholder={kind === 'record' ? '搜索主机 / URL / 标题' : 'status_code="200" && domain="example.com"'}
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
        <Select value={projectId} onValueChange={changeProject}>
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
          <span className="text-[13px] text-muted-foreground">粒度</span>
          <Segmented value={kind} options={KINDS} onChange={changeKind} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[13px] text-muted-foreground">口径</span>
          <Segmented value={catalog} options={CATALOGS} onChange={(v) => { setCatalog(v); setPage(1) }} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[13px] text-muted-foreground">视图</span>
          <Segmented value={view} options={VIEWS} onChange={changeView} />
        </div>
        {kind === 'site' && (
          <label className="flex items-center gap-2 text-[13px] text-muted-foreground">
            <Checkbox
              checked={siteGroup}
              onCheckedChange={(v) => { setSiteGroup(v === true); setPage(1) }}
            />
            按站点归并
          </label>
        )}
        {kind === 'site' && siteGroup && (
          <div className="flex items-center gap-2">
            <span className="text-[13px] text-muted-foreground">排序</span>
            <Segmented value={sort} options={SORTS} onChange={(v) => { setSort(v); setPage(1) }} />
          </div>
        )}
        <div className="flex items-center gap-2">
          <span className="text-[13px] text-muted-foreground">每页</span>
          <Select
            value={String(pageSize)}
            onValueChange={(v) => { setPageSize(Number(v)); setPage(1) }}
          >
            <SelectTrigger className="h-8 w-[76px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[20, 50, 100, 200, 500].map((n) => (
                <SelectItem key={n} value={String(n)}>{n}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <span className="ml-auto text-sm text-muted-foreground">
          {cursorMode ? `已加载 ${items.length} 条` : `共 ${total.toLocaleString()} 条`}
        </span>
      </div>

      {appliedQ && (
        <div className="rounded border bg-muted/40 px-3 py-2 font-mono text-[13px] text-muted-foreground">
          q = {appliedQ}
        </div>
      )}

      {view === 'icons' && (
        <div className="space-y-3">
          <p className="text-[13px] text-muted-foreground">
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
                <div className="w-full truncate text-center text-[13px]" title={ic.sample_title || ic.sample_host}>
                  {ic.sample_title || ic.sample_host}
                </div>
                <div className="text-[13px] text-muted-foreground">{ic.site_count} 个站点</div>
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
          <p className="text-[13px] text-muted-foreground">
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
                <span className="ml-1 text-[13px] text-muted-foreground">{t.site_count}</span>
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

      {kind === 'site' && !expanded && selectedHosts.size > 0 && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 text-sm">
          <span className="text-muted-foreground">
            已选 <span className="text-foreground font-medium">{selectedHosts.size}</span> 个资产
          </span>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Rocket className="mr-1 h-4 w-4" />
            用选中资产创建任务
          </Button>
          <Button variant="outline" size="sm" onClick={() => setSelectedHosts(new Set())}>
            <X className="mr-1 h-4 w-4" />
            清空选择
          </Button>
        </div>
      )}

      {!clusterView && (!data || data.view_supported !== false) && (
        <div ref={scrollRef} className={virtualize ? 'max-h-[70vh] overflow-auto rounded-md border [&>div]:overflow-visible' : 'rounded-md border'}>
          <Table>
            <TableHeader className={virtualize ? 'sticky top-0 z-10 bg-background' : undefined}>
              <TableRow>
                {kind === 'site' && !expanded && (
                  <TableHead className="w-10">
                    <Checkbox checked={allPageSelected} onCheckedChange={togglePageHosts} aria-label="选中本页资产" />
                  </TableHead>
                )}
                <TableHead>{expanded ? '入口' : kind === 'site' ? '资产' : kind === 'domain' ? '域名' : kind === 'record' ? '原始记录' : 'IP'}</TableHead>
                {kind === 'record' && <TableHead className="w-[90px]">来源</TableHead>}
                {kind === 'record' && <TableHead className="w-[90px] text-right">状态码</TableHead>}
                {kind === 'record' && <TableHead>标题</TableHead>}
                {kind === 'record' && <TableHead className="w-[150px]">IP / 服务</TableHead>}
                {kind === 'record' && <TableHead className="w-[170px] text-right">观察时间</TableHead>}
                {kind === 'record' && <TableHead className="w-[120px]">项目</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[52px] sm:table-cell">图标</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[90px] text-right lg:table-cell">风险</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[90px] text-right sm:table-cell">状态码</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden md:table-cell">标题</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[120px] lg:table-cell">项目</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[110px] text-right xl:table-cell">发现时间</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="w-[110px]">连通</TableHead>}
                {expanded && <TableHead className="w-[90px]">协议</TableHead>}
                {expanded && <TableHead className="hidden md:table-cell">标题</TableHead>}
                {expanded && <TableHead className="w-[90px] text-right">记录数</TableHead>}
                {expanded && <TableHead className="w-[110px]">连通</TableHead>}
                {expanded && <TableHead className="w-[110px] text-right">最近发现</TableHead>}
                {expanded && <TableHead className="hidden w-[120px] lg:table-cell">项目</TableHead>}
                {kind === 'domain' && <TableHead className="w-[100px] text-right">站点数</TableHead>}
                {kind === 'domain' && <TableHead className="w-[100px] text-right">可达</TableHead>}
                {kind === 'domain' && <TableHead className="hidden w-[120px] lg:table-cell">项目</TableHead>}
                {kind === 'ip' && <TableHead className="w-[100px] text-right">站点数</TableHead>}
                {kind === 'ip' && <TableHead className="w-[100px] text-right">域名数</TableHead>}
                {kind === 'ip' && <TableHead className="w-[110px] text-right">最近发现</TableHead>}
                {kind === 'site' && !expanded && <TableHead className="hidden w-[150px] sm:table-cell">操作</TableHead>}
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
                  <TableCell colSpan={colCount} className="p-0">
                    {hasFilters ? (
                      <EmptyState
                        icon={Search}
                        title="没有匹配的资产"
                        description="当前筛选条件下没有任何资产，资产本身可能已经存在。"
                        hints={[
                          appliedQ ? `关键词：${appliedQ}` : '关键词：无',
                          `资产类型：${KINDS.find((k) => k.value === kind)?.label ?? '全部'}`,
                          '清空筛选后能看到项目内的全部资产',
                        ]}
                        actions={
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              setQ('')
                              setAppliedQ('')
                              setPage(1)
                              setSearchParams({})
                            }}
                          >
                            清空筛选
                          </Button>
                        }
                      />
                    ) : (
                      <EmptyState
                        icon={Radar}
                        title="这个项目还没有资产"
                        description="资产是任务跑出来的：子域、端口、URL 结果经入口探测与指纹识别后归并成站点。项目刚建、还没跑任务时为空是正常的。"
                        hints={[
                          '第一步：建一个侦察任务，选子域枚举 + 端口指纹，目标填主域名',
                          '任务开始后，原始结果先落「本次任务资产」之外的明细页签',
                          '归并成站点后，这里会按 host 列出入口、标题、技术栈与风险',
                        ]}
                        actions={
                          <>
                            <Button size="sm" onClick={() => navigate('/tasks/new' + (projectId && projectId !== '0' ? `?project_id=${projectId}` : ''))}>
                              建第一个侦察任务
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => navigate('/tasks' + (projectId && projectId !== '0' ? `?project_id=${projectId}` : ''))}>
                              看任务列表
                            </Button>
                          </>
                        }
                      />
                    )}
                  </TableCell>
                </TableRow>
              )}

              {kind === 'site' && !expanded && !virtualize &&
                (items as Site[]).map((s) => renderSiteRow(s))}

              {virtualize && virtualItems.length > 0 && (
                <TableRow style={{ height: virtualItems[0].start }}>
                  <TableCell colSpan={colCount} style={{ padding: 0 }} />
                </TableRow>
              )}
              {virtualize && virtualItems.map((vi) => renderSiteRow((items as Site[])[vi.index], vi.index))}
              {virtualize && virtualItems.length > 0 && (
                <TableRow
                  style={{
                    height: Math.max(0, rowVirtualizer.getTotalSize() - virtualItems[virtualItems.length - 1].end),
                  }}
                >
                  <TableCell colSpan={colCount} style={{ padding: 0 }} />
                </TableRow>
              )}

              {expanded &&
                (items as EndpointRow[]).map((e) => (
                  <TableRow
                    key={`${e.host}-${e.port}-${e.protocol}`}
                    className="hover:bg-muted/40 cursor-pointer"
                    onClick={() => navigate(`/assets/${e.site_id}`)}
                  >
                    <TableCell>
                      <div className="text-sm font-medium">
                        {e.host}:{e.port}
                      </div>
                      <div className="text-[13px] text-muted-foreground">
                        {e.value || '—'} · 站点 #{e.site_id} · 采集 {e.record_count} 次
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{e.protocol || '—'}</Badge>
                    </TableCell>
                    <TableCell className="max-w-[260px] truncate text-sm">{e.title || '—'}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums">{e.record_count}</TableCell>
                    <TableCell>
                      <Badge variant={stateVariant(e.state)}>{stateLabel[e.state] ?? e.state}</Badge>
                    </TableCell>
                    <TableCell className="text-right text-[13px] tabular-nums text-muted-foreground">{e.last_seen?.slice(0, 10)}</TableCell>
                    <TableCell className="text-sm">{e.project_name}</TableCell>
                  </TableRow>
                ))}

              {kind === 'record' &&
                (items as RawRecordRow[]).map((r) => (
                  <TableRow
                    key={r.id}
                    className={r.site_id > 0 ? 'cursor-pointer hover:bg-muted/40' : undefined}
                    onClick={() => r.site_id > 0 && navigate(`/assets/${r.site_id}`)}
                  >
                    <TableCell>
                      <div className="break-all text-sm font-medium">
                        {r.value || `${r.protocol}://${r.host}:${r.port}`}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {r.host}:{r.port} · {r.protocol}
                      </div>
                    </TableCell>
                    <TableCell className="text-[13px] text-muted-foreground">{r.source || '—'}</TableCell>
                    <TableCell className="text-right">
                      <Badge variant={r.status_code >= 200 && r.status_code < 400 ? 'default' : 'secondary'}>
                        {r.status_code || '—'}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-[280px] truncate text-sm">{r.title || '—'}</TableCell>
                    <TableCell className="text-[13px]">
                      <div>{r.ip || '—'}</div>
                      {r.server && <div className="text-muted-foreground">{r.server}</div>}
                    </TableCell>
                    <TableCell className="text-right text-[13px] tabular-nums text-muted-foreground">
                      {r.observed_at?.replace('T', ' ').slice(0, 19)}
                    </TableCell>
                    <TableCell className="text-[13px]">{r.project_name || '—'}</TableCell>
                  </TableRow>
                ))}

              {kind === 'domain' &&
                (items as DomainRow[]).map((d) => (
                  <TableRow key={d.host}>
                    <TableCell className="text-sm font-medium">{d.host}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums">{d.site_count}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums">{d.reachable_count}</TableCell>
                    <TableCell className="text-sm">{d.project_name}</TableCell>
                    <TableCell className="text-right text-[13px] tabular-nums text-muted-foreground">{d.last_seen?.slice(0, 10)}</TableCell>
                  </TableRow>
                ))}

              {kind === 'ip' &&
                (items as IPRow[]).map((r) => (
                  <TableRow key={r.ip}>
                    <TableCell className="text-sm font-medium">{r.ip}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums">{r.site_count}</TableCell>
                    <TableCell className="text-right text-sm tabular-nums">{r.domain_count}</TableCell>
                    <TableCell className="text-right text-[13px] tabular-nums text-muted-foreground">{r.last_seen?.slice(0, 10)}</TableCell>
                    <TableCell className="text-[13px] text-muted-foreground">#{r.project_id}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </div>
      )}

      {cursorMode ? (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            第 {cursorStack.length} 页 · 本页 {items.length} 条
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={cursorStack.length <= 1}
              onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
            >
              上一页
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!hasMore || !nextCursor}
              onClick={() => setCursorStack((stack) => [...stack, nextCursor])}
            >
              下一页
            </Button>
          </div>
        </div>
      ) : (
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
      )}

      <CreateTaskFromAssetsDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        hosts={[...selectedHosts]}
        projectId={projectId !== '0' ? projectId : undefined}
      />
    </div>
  )
}

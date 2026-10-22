import { Fragment, useEffect, useRef, useState } from 'react'
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
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import {
  RefreshCw,
  Search,
  Radar,
  MoreHorizontal,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Globe,
  Rocket,
  X,
  Eye,
  Bookmark,
  Download,
  Plus,
  Trash2,
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
  RotateCcw,
} from 'lucide-react'

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
  { value: 'site', label: '站点' },
  { value: 'domain', label: '域名' },
  { value: 'ip', label: 'IP' },
  { value: 'record', label: '原始记录' },
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
  { value: 'interfaces', label: '接口' },
  { value: 'icons', label: '图标' },
  { value: 'technologies', label: '技术栈' },
]

type AssetSort = 'first_seen' | 'risk'

const SORTS: { value: AssetSort; label: string }[] = [
  { value: 'first_seen', label: '最近发现' },
  { value: 'risk', label: '风险优先' },
]

// 保存视图只存筛选条件与粒度，不存页码/游标：资产在变，位置没有意义。
type SavedAssetView = {
  id: string
  name: string
  q: string
  projectId: string
  kind: AssetKind
  catalog: AssetCatalog
  view: AssetView
  siteGroup: boolean
  sort: AssetSort
  pageSize: number
}

const SAVED_VIEW_KEY = 'zre.asset.savedViews.v1'

function loadSavedViews(): SavedAssetView[] {
  try {
    const raw = localStorage.getItem(SAVED_VIEW_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((v): v is SavedAssetView =>
      v && typeof v.id === 'string' && typeof v.name === 'string'
    )
  } catch {
    return []
  }
}

function csvCell(value: unknown): string {
  let text = String(value ?? '')
  // CSV 公式注入：以这些字符开头的单元格加前缀，避免被表格软件执行。
  if (/^[=+\-@]/.test(text)) text = `'${text}`
  return `"${text.replace(/"/g, '""')}"`
}

function downloadCSV(filename: string, rows: unknown[][]) {
  const csv = '\uFEFF' + rows.map((row) => row.map(csvCell).join(',')).join('\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

type SiteColumn = 'icon' | 'risk' | 'status' | 'title' | 'records' | 'project' | 'first_seen' | 'actions'

const SITE_COLUMNS: { key: SiteColumn; label: string }[] = [
  { key: 'icon', label: '图标' },
  { key: 'risk', label: '风险' },
  { key: 'status', label: '状态码' },
  { key: 'title', label: '标题' },
  { key: 'records', label: '记录 / 最近记录' },
  { key: 'project', label: '项目' },
  { key: 'first_seen', label: '发现时间' },
  { key: 'actions', label: '操作' },
]

const DEFAULT_SITE_COLUMNS: Record<SiteColumn, boolean> = {
  icon: true, risk: true, status: true, title: true,
  records: true, project: true, first_seen: true, actions: true,
}

const SITE_COLUMNS_KEY = 'zre.asset.siteColumns.v1'

function loadSiteColumns(): Record<SiteColumn, boolean> {
  try {
    const raw = localStorage.getItem(SITE_COLUMNS_KEY)
    if (!raw) return { ...DEFAULT_SITE_COLUMNS }
    const parsed = JSON.parse(raw)
    if (!parsed || typeof parsed !== 'object') return { ...DEFAULT_SITE_COLUMNS }
    return { ...DEFAULT_SITE_COLUMNS, ...parsed }
  } catch {
    return { ...DEFAULT_SITE_COLUMNS }
  }
}

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
    return v === 'domain' || v === 'ip' || v === 'record' ? v : 'site'
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
  const [detailSite, setDetailSite] = useState<Site | null>(null)
  const [detailTab, setDetailTab] = useState<'overview' | 'endpoints' | 'records' | 'fingerprints' | 'verifications'>('overview')
  const [recordsCursorStack, setRecordsCursorStack] = useState<Array<string | undefined>>([undefined])
  const [recordsInterfaceOnly, setRecordsInterfaceOnly] = useState(false)
  const [savedViews, setSavedViews] = useState<SavedAssetView[]>(loadSavedViews)
  const [saveViewOpen, setSaveViewOpen] = useState(false)
  const [viewName, setViewName] = useState('')
  const [siteCols, setSiteCols] = useState<Record<SiteColumn, boolean>>(loadSiteColumns)
  const [expandedSiteIDs, setExpandedSiteIDs] = useState<Set<number>>(new Set())
  const recordsCursor = recordsCursorStack[recordsCursorStack.length - 1]
  const cursor = cursorStack[cursorStack.length - 1]
  const clusterView = view === 'icons' || view === 'technologies'
  const riskSort = kind === 'site' && siteGroup && sort === 'risk'
  const cursorMode = !clusterView && !riskSort && (kind === 'site' ? siteGroup : true)
  // 只有真的展开了某一行才请求最近记录，正常浏览列表不付这份查询成本。
  const recentLoaded = kind === 'site' && siteGroup && expandedSiteIDs.size > 0

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

  const hasFilters = !!appliedQ || kind !== 'site' || catalog !== 'all' || !!view

  // 站点默认/域名/IP 用 keyset；风险排序、展开入口和聚类仍走 page。
  const list = useQuery({
    queryKey: ['assets', cursorMode ? `c:${cursor ?? ''}` : `p:${page}`, pageSize, appliedQ, projectId, kind, catalog, view, siteGroup, riskSort, recentLoaded ? 'recent' : 'plain'],
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
        ...(recentLoaded ? { with_recent: 1 as const, recent_limit: 3 } : {}),
      }),
  })

  const detailQuery = useQuery({
    queryKey: ['asset-detail', detailSite?.id],
    queryFn: () => assetApi.detail(detailSite!.id),
    enabled: !!detailSite,
    staleTime: 30_000,
  })
  const detail = detailQuery.data?.data
  const recordsQuery = useQuery({
    queryKey: ['asset-records', detailSite?.id, recordsCursor, recordsInterfaceOnly],
    queryFn: () =>
      assetApi.records(detailSite!.id, {
        cursor: recordsCursor ?? '',
        limit: 50,
        ...(recordsInterfaceOnly ? { interface: 1 as const } : {}),
      }),
    enabled: !!detailSite && detailTab === 'records',
    staleTime: 30_000,
  })
  const recordsPage = recordsQuery.data?.data
  const records = recordsPage?.items ?? []

  useEffect(() => {
    setDetailTab('overview')
    setRecordsCursorStack([undefined])
    setRecordsInterfaceOnly(false)
  }, [detailSite?.id])

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

  const persistSavedViews = (next: SavedAssetView[]) => {
    setSavedViews(next)
    try {
      localStorage.setItem(SAVED_VIEW_KEY, JSON.stringify(next))
    } catch {
      toast({ title: '保存失败', description: '浏览器存储不可用', variant: 'destructive' })
    }
  }

  const applySavedView = (v: SavedAssetView) => {
    setQ(v.q)
    setAppliedQ(v.q)
    setProjectId(v.projectId)
    setKind(v.kind)
    setCatalog(v.catalog)
    setView(v.view)
    setSiteGroup(v.siteGroup)
    setSort(v.sort)
    setPageSize(v.pageSize)
    setPage(1)
    setCursorStack([undefined])
  }

  const saveCurrentView = () => {
    const name = viewName.trim()
    if (!name) return
    const saved: SavedAssetView = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name,
      q: appliedQ,
      projectId,
      kind,
      catalog,
      view,
      siteGroup,
      sort,
      pageSize,
    }
    // 同名覆盖，避免反复保存出现一堆同名项。
    persistSavedViews([saved, ...savedViews.filter((v) => v.name !== name)])
    setSaveViewOpen(false)
    setViewName('')
    toast({ title: `已保存视图「${name}」` })
  }

  const deleteSavedView = (id: string) => {
    persistSavedViews(savedViews.filter((v) => v.id !== id))
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

  const exportCurrent = (siteSubset?: Site[]) => {
    const stamp = new Date().toISOString().slice(0, 10)
    let rows: unknown[][] = []
    if (kind === 'site') {
      const sites = siteSubset ?? (items as Site[])
      rows = [
        ['资产', '标题', 'IP', '协议', '端口', '状态码', '状态', '风险', '记录数', '项目'],
        ...sites.map((s) => [
          s.value || s.host, s.title, s.ip, s.protocol, s.port, s.http_status,
          stateLabel[s.state] ?? s.state, `${priorityLabel(s.priority)} ${s.risk_score}`,
          s.record_count, s.project_name,
        ]),
      ]
    } else if (kind === 'record') {
      rows = [
        ['URL', '方法', '接口', '来源', '状态码', '主机', 'IP', '观察时间', '项目'],
        ...(items as RawRecordRow[]).map((r) => [
          r.value, r.method || 'GET', r.is_interface ? '是' : '否', r.source,
          r.status_code, `${r.host}:${r.port}`, r.ip, r.observed_at, r.project_name,
        ]),
      ]
    } else if (kind === 'domain') {
      rows = [
        ['域名', '站点数', '可达', '项目', '最近发现'],
        ...(items as DomainRow[]).map((d) => [d.host, d.site_count, d.reachable_count, d.project_name, d.last_seen]),
      ]
    } else if (kind === 'ip') {
      rows = [
        ['IP', '站点数', '域名数', '最近发现'],
        ...(items as IPRow[]).map((r) => [r.ip, r.site_count, r.domain_count, r.last_seen]),
      ]
    } else {
      rows = [
        ['入口', '协议', '标题', '记录数', '状态', '项目', '最近发现'],
        ...(items as EndpointRow[]).map((e) => [
          `${e.host}:${e.port}`, e.protocol, e.title, e.record_count, e.state, e.project_name, e.last_seen,
        ]),
      ]
    }
    if (rows.length <= 1) {
      toast({ title: '当前没有可导出的数据' })
      return
    }
    downloadCSV(`assets-${kind}-${stamp}.csv`, rows)
  }

  const visibleSiteCols = SITE_COLUMNS.reduce((n, c) => n + (siteCols[c.key] ? 1 : 0), 0)
  const colCount = expanded ? 7 : kind === 'site' ? 3 + visibleSiteCols : kind === 'record' ? 7 : 5

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
  const virtualize = kind === 'site' && !expanded && pageSize >= 100 && !clusterView && expandedSiteIDs.size === 0
  const scrollRef = useRef<HTMLDivElement>(null)
  const rowVirtualizer = useVirtualizer({
    count: virtualize ? (items as Site[]).length : 0,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 68,
    overscan: 8,
  })
  const virtualItems = rowVirtualizer.getVirtualItems()

  const renderSiteRow = (s: Site, virtualIndex?: number) => {
    const isOpen = expandedSiteIDs.has(s.id)
    const recent = s.recent_records ?? []
    return (
      <Fragment key={s.id}>
      <TableRow
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
      {siteCols.icon && (
        <TableCell className="hidden sm:table-cell">
          <SiteIcon sha256={s.icon_sha256} alt={s.host} />
        </TableCell>
      )}
      {siteCols.risk && (
        <TableCell className="hidden text-right lg:table-cell">
          <Badge variant={priorityVariant(s.priority)} title={riskTitle(s)}>
            {priorityLabel(s.priority)} · {s.risk_score}
          </Badge>
        </TableCell>
      )}
      {siteCols.status && (
        <TableCell className="hidden text-right sm:table-cell">
          <Badge variant={s.http_status >= 200 && s.http_status < 400 ? 'default' : 'secondary'}>
            {s.http_status || '—'}
          </Badge>
        </TableCell>
      )}
      {siteCols.title && (
        <TableCell className="hidden max-w-[260px] truncate text-sm md:table-cell">{s.title || '—'}</TableCell>
      )}
      {siteCols.records && (
        <TableCell
          className="hidden text-right text-sm tabular-nums lg:table-cell"
          title={`入口 ${s.endpoint_count} · 原始记录 ${s.record_count} · 指纹 ${s.fingerprint_count}`}
        >
          <div className="flex items-center justify-end gap-1">
            <button
              type="button"
              aria-label={isOpen ? '收起最近记录' : '展开最近记录'}
              className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
              onClick={(e) => {
                e.stopPropagation()
                setExpandedSiteIDs((prev) => {
                  const next = new Set(prev)
                  if (next.has(s.id)) next.delete(s.id)
                  else next.add(s.id)
                  return next
                })
              }}
            >
              {isOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
            </button>
            <span>{s.record_count}</span>
          </div>
        </TableCell>
      )}
      {siteCols.project && <TableCell className="hidden text-sm lg:table-cell">{s.project_name}</TableCell>}
      {siteCols.first_seen && (
        <TableCell className="hidden text-right text-[13px] tabular-nums text-muted-foreground xl:table-cell">{s.first_seen?.slice(0, 10)}</TableCell>
      )}
      <TableCell>
        <Badge variant={stateVariant(s.state)}>{stateLabel[s.state] ?? s.state}</Badge>
        {s.consecutive_failures > 0 && (
          <span className="ml-1 text-[13px] text-destructive">×{s.consecutive_failures}</span>
        )}
      </TableCell>
      {siteCols.actions && (
      <TableCell className="hidden sm:table-cell" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="outline" onClick={() => setDetailSite(s)} disabled={busy}>
            <Eye className="mr-1 h-3.5 w-3.5" /> 详情
          </Button>
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
              <DropdownMenuItem
                onClick={() => {
                  setExpandedSiteIDs((prev) => {
                    const next = new Set(prev)
                    if (next.has(s.id)) next.delete(s.id)
                    else next.add(s.id)
                    return next
                  })
                }}
              >
                {isOpen ? <ChevronUp className="mr-2 h-3.5 w-3.5" /> : <ChevronDown className="mr-2 h-3.5 w-3.5" />}
                {isOpen ? '收起最近记录' : '展开最近记录'}
              </DropdownMenuItem>
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
      )}
      </TableRow>
      {isOpen && (
        <TableRow className="bg-muted/30 hover:bg-muted/30">
          <TableCell colSpan={colCount} className="p-0">
            <div className="space-y-2 px-3 py-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>最近 {recent.length} 条采集证据 · 共 {s.record_count} 条</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 px-2 text-xs"
                  onClick={() => {
                    setDetailSite(s)
                    setDetailTab('records')
                  }}
                >
                  <Eye className="mr-1 h-3 w-3" /> 查看全部记录
                </Button>
              </div>
              {recent.length === 0 ? (
                <div className="text-xs text-muted-foreground">这个站点还没有原始记录。</div>
              ) : (
                <div className="space-y-1">
                  {recent.map((r) => (
                    <div key={r.id} className="flex items-start gap-2 font-mono text-xs">
                      <Badge variant="outline" className="shrink-0 text-[10px]">{r.method || 'GET'}</Badge>
                      {r.is_interface && (
                        <Badge variant="secondary" className="shrink-0 text-[10px]">接口</Badge>
                      )}
                      <span className="break-all">{r.value}</span>
                      <span className="ml-auto shrink-0 tabular-nums text-muted-foreground">
                        {r.status_code || '—'} · {formatDate(r.observed_at)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
      </Fragment>
    )
  }

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
        <div className="flex flex-wrap items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">
                <Bookmark className="mr-2 h-4 w-4" /> 保存的视图
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-60">
              {savedViews.length === 0 ? (
                <div className="px-2 py-1.5 text-sm text-muted-foreground">还没有保存的视图</div>
              ) : (
                savedViews.map((v) => (
                  <DropdownMenuItem
                    key={v.id}
                    className="gap-2"
                    onSelect={() => applySavedView(v)}
                  >
                    <span className="flex-1 truncate">{v.name}</span>
                    <button
                      type="button"
                      aria-label={`删除视图 ${v.name}`}
                      className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                      onPointerDown={(e) => e.stopPropagation()}
                      onClick={(e) => {
                        e.stopPropagation()
                        deleteSavedView(v.id)
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </DropdownMenuItem>
                ))
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onSelect={() => {
                  setViewName('')
                  setSaveViewOpen(true)
                }}
              >
                <Plus className="mr-2 h-4 w-4" /> 保存当前视图
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          <Button variant="outline" onClick={() => exportCurrent()} disabled={items.length === 0}>
            <Download className="mr-2 h-4 w-4" /> 导出本页
          </Button>
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          {kind === 'site' && siteGroup && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline">
                <SlidersHorizontal className="mr-2 h-4 w-4" /> 列
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52">
              <DropdownMenuLabel>站点列表列</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {SITE_COLUMNS.map((c) => (
                <DropdownMenuCheckboxItem
                  key={c.key}
                  checked={siteCols[c.key]}
                  onCheckedChange={(v) => {
                    const next = { ...siteCols, [c.key]: v === true }
                    setSiteCols(next)
                    try {
                      localStorage.setItem(SITE_COLUMNS_KEY, JSON.stringify(next))
                    } catch { /* 存储不可用时只影响本次会话 */ }
                  }}
                >
                  {c.label}
                </DropdownMenuCheckboxItem>
              ))}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onSelect={() => {
                  setSiteCols({ ...DEFAULT_SITE_COLUMNS })
                  try {
                    localStorage.removeItem(SITE_COLUMNS_KEY)
                  } catch { /* noop */ }
                }}
              >
                <RotateCcw className="mr-2 h-4 w-4" /> 恢复默认列
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          )}
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
        </div>
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

      {view === 'interfaces' && (
        <div className="rounded border bg-muted/40 px-3 py-2 text-[13px] text-muted-foreground">
          接口候选不要求 <span className="font-mono">/api</span> 前缀：非 GET 方法、JSON 响应、
          jsluice 来源、带查询串或接口路径段（graphql / gateway / rest 等）都会命中。
          {kind === 'site' ? '当前列出含接口的站点，切换粒度到「原始记录」可看具体 URL。' : ''}
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
          <Button
            variant="outline"
            size="sm"
            onClick={() => exportCurrent((items as Site[]).filter((s) => selectedHosts.has(s.value)))}
          >
            <Download className="mr-1 h-4 w-4" />
            导出所选
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
                {kind === 'record' && <TableHead className="w-[110px]">来源 / 方法</TableHead>}
                {kind === 'record' && <TableHead className="w-[90px] text-right">状态码</TableHead>}
                {kind === 'record' && <TableHead>标题</TableHead>}
                {kind === 'record' && <TableHead className="w-[150px]">IP / 服务</TableHead>}
                {kind === 'record' && <TableHead className="w-[170px] text-right">观察时间</TableHead>}
                {kind === 'record' && <TableHead className="w-[120px]">项目</TableHead>}
                {kind === 'site' && !expanded && siteCols.icon && <TableHead className="hidden w-[52px] sm:table-cell">图标</TableHead>}
                {kind === 'site' && !expanded && siteCols.risk && <TableHead className="hidden w-[90px] text-right lg:table-cell">风险</TableHead>}
                {kind === 'site' && !expanded && siteCols.status && <TableHead className="hidden w-[90px] text-right sm:table-cell">状态码</TableHead>}
                {kind === 'site' && !expanded && siteCols.title && <TableHead className="hidden md:table-cell">标题</TableHead>}
                {kind === 'site' && !expanded && siteCols.records && <TableHead className="hidden w-[82px] text-right lg:table-cell">记录</TableHead>}
                {kind === 'site' && !expanded && siteCols.project && <TableHead className="hidden w-[120px] lg:table-cell">项目</TableHead>}
                {kind === 'site' && !expanded && siteCols.first_seen && <TableHead className="hidden w-[110px] text-right xl:table-cell">发现时间</TableHead>}
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
                {kind === 'site' && !expanded && siteCols.actions && <TableHead className="hidden w-[150px] sm:table-cell">操作</TableHead>}
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
                      <div className="flex items-start gap-1.5">
                        <div className="break-all text-sm font-medium">
                          {r.value || `${r.protocol}://${r.host}:${r.port}`}
                        </div>
                        {r.is_interface && (
                          <Badge variant="outline" className="shrink-0 text-[11px]">接口</Badge>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {r.host}:{r.port} · {r.protocol}
                      </div>
                    </TableCell>
                    <TableCell className="text-[13px] text-muted-foreground">
                      <div>{r.source || '—'}</div>
                      <div className="text-[11px]">{r.method || 'GET'}</div>
                    </TableCell>
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

      {detailSite && (
        <>
          <button
            type="button"
            aria-label="关闭资产详情"
            className="fixed inset-0 z-40 bg-foreground/20 xl:hidden"
            onClick={() => setDetailSite(null)}
          />
          <aside className="fixed right-0 top-16 bottom-0 z-50 flex w-full max-w-[460px] flex-col border-l bg-background shadow-xl">
            <div className="flex items-start justify-between gap-3 border-b p-4">
              <div className="min-w-0">
                <div className="truncate font-mono text-sm font-semibold">
                  {detailSite.value || detailSite.host}
                </div>
                <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
                  <Badge variant={stateVariant(detailSite.state)}>
                    {stateLabel[detailSite.state] ?? detailSite.state}
                  </Badge>
                  <span>{detailSite.project_name}</span>
                  <span>·</span>
                  <span className="tabular-nums">P{detailSite.priority?.replace(/^p/i, '') || '—'} · {detailSite.risk_score}</span>
                </div>
              </div>
              <Button variant="ghost" size="icon" aria-label="关闭详情" onClick={() => setDetailSite(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="flex gap-1 overflow-x-auto border-b px-3 py-2">
              {([
                ['overview', '概览'],
                ['endpoints', '入口'],
                ['records', '原始记录'],
                ['fingerprints', '指纹'],
                ['verifications', '验证'],
              ] as const).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setDetailTab(id)}
                  className={
                    'shrink-0 rounded-sm px-2.5 py-1.5 text-[13px] transition-colors ' +
                    (detailTab === id
                      ? 'bg-foreground text-background'
                      : 'text-muted-foreground hover:bg-muted')
                  }
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-y-auto p-4">
              {detailQuery.isLoading ? (
                <div className="py-10 text-center text-sm text-muted-foreground">加载资产档案…</div>
              ) : !detail ? (
                <div className="py-10 text-center text-sm text-muted-foreground">详情加载失败</div>
              ) : (
                <>
                  {detailTab === 'overview' && (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-2">
                        {[
                          ['入口', detailSite.endpoint_count ?? 0],
                          ['原始记录', detailSite.record_count ?? 0],
                          ['指纹命中', detailSite.fingerprint_count ?? 0],
                          ['验证记录', detail.verifications.length],
                        ].map(([label, value]) => (
                          <div key={String(label)} className="rounded-md border px-3 py-2">
                            <div className="text-xs text-muted-foreground">{label}</div>
                            <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
                          </div>
                        ))}
                      </div>
                      <div className="divide-y text-sm">
                        {[
                          ['状态', stateLabel[detailSite.state] ?? detailSite.state],
                          ['标题', detailSite.title || '—'],
                          ['IP', detailSite.ip || '—'],
                          ['协议 / 端口', `${detailSite.protocol}:${detailSite.port}`],
                          ['首次发现', formatDate(detailSite.first_seen)],
                          ['最近发现', formatDate(detailSite.last_record_at || detailSite.last_seen)],
                        ].map(([label, value]) => (
                          <div key={label} className="flex items-start justify-between gap-3 py-2">
                            <span className="shrink-0 text-muted-foreground">{label}</span>
                            <span className="min-w-0 break-all text-right">{value}</span>
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="mb-1.5 text-xs text-muted-foreground">技术栈</div>
                        <div className="flex flex-wrap gap-1.5">
                          {(detailSite.technology_stack ?? []).length === 0 ? (
                            <span className="text-sm text-muted-foreground">—</span>
                          ) : detailSite.technology_stack.map((t) => (
                            <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {detailTab === 'endpoints' && (
                    <div className="space-y-2">
                      {(detailSite.endpoints ?? []).length === 0 ? (
                        <p className="text-sm text-muted-foreground">暂无入口。</p>
                      ) : detailSite.endpoints.map((e) => (
                        <div key={`${e.scheme}-${e.port}`} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                          <span className="font-mono">{e.scheme}:{e.port}</span>
                          <Badge variant={e.status_code >= 200 && e.status_code < 400 ? 'default' : 'secondary'}>
                            {e.status_code || '—'}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  )}

                  {detailTab === 'records' && (
                    <div className="space-y-3">
                      <label className="flex items-center gap-2 text-[13px] text-muted-foreground">
                        <Checkbox
                          checked={recordsInterfaceOnly}
                          onCheckedChange={(v) => {
                            setRecordsInterfaceOnly(v === true)
                            setRecordsCursorStack([undefined])
                          }}
                        />
                        只看接口
                      </label>
                      {recordsQuery.isLoading ? (
                        <p className="text-sm text-muted-foreground">加载原始记录…</p>
                      ) : records.length === 0 ? (
                        <p className="text-sm text-muted-foreground">暂无原始记录。</p>
                      ) : (
                        <div className="rounded-md border">
                          <Table>
                            <TableHeader>
                              <TableRow>
                                <TableHead>记录</TableHead>
                                <TableHead className="w-[54px]">来源</TableHead>
                                <TableHead className="w-[54px] text-right">状态</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {records.map((r) => (
                                <TableRow key={r.id}>
                                  <TableCell className="max-w-[270px] break-all font-mono text-xs">
                                    <div className="flex items-start gap-1">
                                      <span>{r.value}</span>
                                      {r.is_interface && (
                                        <Badge variant="outline" className="shrink-0 text-[10px]">接口</Badge>
                                      )}
                                    </div>
                                    <div className="mt-0.5 text-[11px] text-muted-foreground">
                                      {formatDate(r.observed_at)}
                                    </div>
                                  </TableCell>
                                  <TableCell className="text-xs text-muted-foreground">
                                    <div>{r.source}</div>
                                    <div>{r.method || 'GET'}</div>
                                  </TableCell>
                                  <TableCell className="text-right text-xs tabular-nums">{r.status_code || '—'}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      )}
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span>已加载 {records.length} 条</span>
                        <div className="flex gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={recordsCursorStack.length <= 1}
                            onClick={() => setRecordsCursorStack((stack) => stack.slice(0, -1))}
                          >
                            上一页
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={!recordsPage?.has_more || !recordsPage?.next_cursor}
                            onClick={() => setRecordsCursorStack((stack) => [...stack, recordsPage?.next_cursor])}
                          >
                            下一页
                          </Button>
                        </div>
                      </div>
                    </div>
                  )}

                  {detailTab === 'fingerprints' && (
                    <div className="space-y-2">
                      {detail.fingerprints.length === 0 ? (
                        <p className="text-sm text-muted-foreground">暂无指纹命中。</p>
                      ) : detail.fingerprints.map((f) => (
                        <div key={`${f.rule_id}-${f.observed_at}`} className="rounded-md border px-3 py-2 text-sm">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-medium">{f.rule_name || f.rule_id}</span>
                            <span className="text-xs text-muted-foreground">{formatDate(f.observed_at)}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {detailTab === 'verifications' && (
                    <div className="space-y-2">
                      {detail.verifications.length === 0 ? (
                        <p className="text-sm text-muted-foreground">暂无验证记录。</p>
                      ) : detail.verifications.map((v) => (
                        <div key={v.id} className="rounded-md border px-3 py-2 text-sm">
                          <div className="flex items-center justify-between gap-2">
                            <Badge variant={v.status === 'reachable' ? 'success' : 'secondary'}>{v.status}</Badge>
                            <span className="text-xs text-muted-foreground">{formatDate(v.observed_at)}</span>
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            状态码 {v.http_status || '—'} · 尝试 {v.attempts || 0}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="border-t p-3">
              <Button
                className="w-full"
                onClick={() => {
                  const id = detailSite.id
                  setDetailSite(null)
                  navigate(`/assets/${id}`)
                }}
              >
                打开完整详情页
              </Button>
            </div>
          </aside>
        </>
      )}

      <Dialog open={saveViewOpen} onOpenChange={setSaveViewOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>保存当前视图</DialogTitle>
            <DialogDescription>
              保存查询串、粒度、视图、项目、排序与每页条数；不保存页码。
            </DialogDescription>
          </DialogHeader>
          <Input
            autoFocus
            value={viewName}
            placeholder="例如：美团接口资产"
            onChange={(e) => setViewName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') saveCurrentView()
            }}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setSaveViewOpen(false)}>取消</Button>
            <Button onClick={saveCurrentView} disabled={!viewName.trim()}>保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <CreateTaskFromAssetsDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        hosts={[...selectedHosts]}
        projectId={projectId !== '0' ? projectId : undefined}
      />
    </div>
  )
}

import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import { Button, Checkbox, Dropdown, Input, Modal, Pagination, Select, Table, Tag } from 'antd'
import type { MenuProps, TableProps } from 'antd'
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
import EmptyState from '@/components/common/EmptyState'
import CreateTaskFromAssetsDialog from '@/components/tasks/CreateTaskFromAssetsDialog'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import {
  Loader2,
  RefreshCw,
  Search,
  Radar,
  Rocket,
  X,
  Eye,
  Bookmark,
  Download,
  Plus,
  Trash2,
  SlidersHorizontal,
  RotateCcw,
} from 'lucide-react'
import { statusTagClass } from '@/components/ui/StatusTag'
import AssetDetailDrawer, { stateLabel } from './components/AssetDetailDrawer'
import ClusterView from './components/ClusterView'
import {
  DEFAULT_SITE_COLUMNS,
  SITE_COLUMNS,
  SITE_COLUMNS_KEY,
  buildAssetTableParts,
  loadSiteColumns,
  priorityLabel,
  type AssetRow,
  type SiteColumn,
} from './components/columns'


// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass

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
  { value: 'ignored', label: '已忽略' },
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
  const [starredOnly, setStarredOnly] = useState(() => searchParams.get('starred') === '1')
  const [sort, setSort] = useState<AssetSort>(() => (searchParams.get('sort') === 'risk' ? 'risk' : 'first_seen'))
  const [page, setPage] = useState(() => Math.max(1, Number(searchParams.get('page')) || 1))
  const [pageSize, setPageSize] = useState(() => {
    const n = Number(searchParams.get('page_size'))
    return [20, 50, 100, 200, 500].includes(n) ? n : 50
  })
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined])
  const [detailSite, setDetailSite] = useState<Site | null>(null)
  const [detailTab, setDetailTab] = useState<'overview' | 'endpoints' | 'records' | 'fingerprints' | 'verifications'>('overview')
  const [savedViews, setSavedViews] = useState<SavedAssetView[]>(loadSavedViews)
  const [saveViewOpen, setSaveViewOpen] = useState(false)
  const [viewName, setViewName] = useState('')
  const [siteCols, setSiteCols] = useState<Record<SiteColumn, boolean>>(loadSiteColumns)
  const [expandedSiteIDs, setExpandedSiteIDs] = useState<Set<number>>(new Set())
  const cursor = cursorStack[cursorStack.length - 1]
  const clusterView = view === 'icons' || view === 'technologies'
  const riskSort = sort === 'risk' && (kind === 'domain' || kind === 'ip' || (kind === 'site' && siteGroup))
  // 排序适用于：站点归并 / 域名 / IP，且不在聚类视图。工具栏控件常驻渲染、
  // 按需禁用——任何切换都不改变工具栏的几何形状（高度、位置零变化）。
  const sortApplicable = !clusterView && (kind === 'domain' || kind === 'ip' || (kind === 'site' && siteGroup))

  // 聚类下钻：把图标/技术栈变成资产列表的过滤条件，回到站点粒度看命中的资产。
  const drillDown = (expr: string) => {
    setQ(expr)
    setAppliedQ(expr)
    setKind('site')
    setView('')
    setPage(1)
  }
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
  }, [appliedQ, projectId, kind, catalog, view, siteGroup, sort, pageSize, starredOnly])

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
    if (starredOnly) next.set('starred', '1')
    if (sort === 'risk') next.set('sort', 'risk')
    if (pageSize !== 50) next.set('page_size', String(pageSize))
    if (!cursorMode && page > 1) next.set('page', String(page))
    setSearchParams(next, { replace: true })
  }, [appliedQ, urlQ, projectId, kind, catalog, view, siteGroup, sort, pageSize, page, cursorMode, starredOnly, setSearchParams])

  const overview = useQuery({ queryKey: ['asset-overview'], queryFn: () => assetApi.overview() })
  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const hasFilters = !!appliedQ || kind !== 'site' || catalog !== 'all' || !!view

  // 站点默认/域名/IP 用 keyset；风险排序、展开入口和聚类仍走 page。
  const listKey = [
    'assets',
    cursorMode ? `c:${cursor ?? ''}` : `p:${page}`,
    pageSize, appliedQ, projectId, kind, catalog, view, siteGroup, riskSort,
    recentLoaded ? 'recent' : 'plain',
    starredOnly ? 'starred' : 'all',
  ] as const
  const list = useQuery({
    queryKey: listKey,
    enabled: !clusterView,
    staleTime: 30_000,
    // 切粒度/视图/排序时保留上一份数据渲染，列表不塌陷成加载态（消除按钮点击时的页面闪烁）。
    placeholderData: keepPreviousData,
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
        starred: starredOnly || undefined,
      }),
  })


  useEffect(() => {
    setDetailTab('overview')
  }, [detailSite?.id])

  const iconClusters = useQuery({
    queryKey: ['asset-icons', projectId, appliedQ, page],
    enabled: view === 'icons',
    staleTime: 30_000,
    placeholderData: keepPreviousData,
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
    placeholderData: keepPreviousData,
    queryFn: () =>
      assetApi.technologies({
        project_id: Number(projectId) || undefined,
        q: appliedQ || undefined,
        page,
        page_size: 60,
      }),
  })

  // 「按指纹筛选」下拉候选：指纹规则命中与技术栈名并集（低频变化，长缓存）。
  const appOptions = useQuery({
    queryKey: ['asset-app-options'],
    queryFn: () => assetApi.apps({ limit: 500 }),
    staleTime: 5 * 60_000,
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

  // 指纹筛选是 q 里 app="…" 条件的 UI 形态：appliedQ 是唯一事实源——技术栈下钻、
  // 保存视图、手写 DSL 设进去的 app 都会反映到下拉框。
  const activeFp = appliedQ.match(/app\s*=\s*"([^"]*)"/)?.[1] ?? ''
  const changeFp = (v: string) => {
    const rest = appliedQ
      .replace(/\s*&&\s*app\s*=\s*"[^"]*"/g, '')
      .replace(/app\s*=\s*"[^"]*"\s*&&\s*/g, '')
      .replace(/app\s*=\s*"[^"]*"/g, '')
      .trim()
    const nextQ = v ? (rest ? `app="${v}" && ${rest}` : `app="${v}"`) : rest
    setQ(nextQ)
    setAppliedQ(nextQ)
    setPage(1)
    setCursorStack([undefined])
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
        // 只记录真实采到的状态码：人工判定不该伪造 200 污染验证历史
        status_code: reachable ? site.http_status || undefined : 0,
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

  // 星标开关：本地先翻（列表不闪），失败时回滚靠失效重取。
  const star = useMutation({
    mutationFn: ({ site, starred }: { site: Site; starred: boolean }) =>
      assetApi.governance(site.id, { starred }),
    onMutate: ({ site, starred }) => {
      queryClient.setQueryData<any>(listKey, (old: any) => {
        if (!old?.data?.items) return old
        return {
          ...old,
          data: {
            ...old.data,
            items: old.data.items.map((it: any) =>
              it && typeof it === 'object' && 'id' in it && (it as Site).id === site.id ? { ...it, starred } : it,
            ),
          },
        }
      })
    },
    onError: (e: any) => {
      toast({ title: '星标操作失败', description: e?.message, variant: 'destructive' })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
  })

  // 忽略开关：乐观更新 + 失败回滚。「已忽略」视图下取消忽略同理。
  const ignore = useMutation({
    mutationFn: ({ site, ignored }: { site: Site; ignored: boolean }) =>
      assetApi.governance(site.id, { ignored }),
    onSuccess: (_, { ignored }) =>
      toast({ title: ignored ? '已忽略该资产（默认视图不再显示）' : '已恢复显示该资产' }),
    onError: (e: any) => {
      toast({ title: '忽略操作失败', description: e?.message, variant: 'destructive' })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
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
        ...(riskSort ? [['风险分']] : []),
        ['域名', '站点数', '可达', '项目', '最近发现'],
        ...(items as DomainRow[]).map((d) => {
          const risk = riskSort ? (d.risk_score ? `${d.priority} · ${d.risk_score}` : '') : null
          const cells: unknown[] = risk === null ? [] : [risk]
          cells.push(d.host, d.site_count, d.reachable_count, d.project_name, d.last_seen)
          return cells
        }),
      ]
    } else if (kind === 'ip') {
      rows = [
        ...(riskSort ? [['风险分']] : []),
        ['IP', '站点数', '域名数', '最近发现'],
        ...(items as IPRow[]).map((r) => {
          const risk = riskSort ? (r.risk_score ? `${r.priority} · ${r.risk_score}` : '') : null
          const cells: unknown[] = risk === null ? [] : [risk]
          cells.push(r.ip, r.site_count, r.domain_count, r.last_seen)
          return cells
        }),
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

  // 资产多选：选中后可直接对这些资产派新任务（选资产 → 选类型 → 起任务）
  const [selectedHosts, setSelectedHosts] = useState<Set<string>>(new Set())
  const [createOpen, setCreateOpen] = useState(false)

  const toggleSiteExpand = (id: number) => {
    setExpandedSiteIDs((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  // 大页（>=100 行）启用 antd Table 的虚拟滚动：只渲染视口附近的站点行。
  const virtualize = kind === 'site' && !expanded && pageSize >= 100 && !clusterView && expandedSiteIDs.size === 0

  // —— 列定义：四种行形态各自的列集与行键/行事件，在 components/columns.tsx 按粒度构建 ——
  const { columns, rowKey, onRow } = buildAssetTableParts({
    kind,
    expanded,
    riskSort,
    siteCols,
    expandedSiteIDs,
    busy,
    toggleSiteExpand,
    probe,
    verify,
    protect,
    star,
    ignore,
    setDetailSite,
    navigate,
  })

  // 站点归并粒度：行多选（key 与 host/value 对齐），行内展开最近记录。
  const siteMode = kind === 'site' && !expanded
  const rowSelection: TableProps<Site>['rowSelection'] = siteMode
    ? {
        selectedRowKeys: [...selectedHosts],
        // 翻页后保留其它页已选中的资产（原 Set 语义）
        preserveSelectedRowKeys: true,
        onChange: (keys) => setSelectedHosts(new Set(keys as string[])),
      }
    : undefined
  const expandable: TableProps<Site>['expandable'] = siteMode
    ? {
        // 展开入口在「记录」列与行菜单里，antd 自带的展开图标列不显示
        showExpandColumn: false,
        expandedRowKeys: (items as Site[]).filter((s) => expandedSiteIDs.has(s.id)).map((s) => s.value),
        onExpandedRowsChange: (keys) =>
          setExpandedSiteIDs(
            new Set(
              (items as Site[]).filter((s) => (keys as (string | number)[]).includes(s.value)).map((s) => s.id)
            )
          ),
        expandedRowRender: (s) => {
          const recent = s.recent_records ?? []
          return (
            <div className="space-y-2 px-3 py-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>最近 {recent.length} 条采集证据 · 共 {s.record_count} 条</span>
                <Button
                  size="small"
                  type="text"
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
                      <Tag className={`${badgeCls('outline')} shrink-0 text-[10px]`}>{r.method || 'GET'}</Tag>
                      {r.is_interface && (
                        <Tag className={`${badgeCls('secondary')} shrink-0 text-[10px]`}>接口</Tag>
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
          )
        },
      }
    : undefined

  // —— 工具栏菜单 ——
  const savedViewMenuItems: MenuProps['items'] = [
    ...(savedViews.length === 0
      ? [
          {
            key: 'empty',
            disabled: true,
            label: <span className="text-sm text-muted-foreground">还没有保存的视图</span>,
          },
        ]
      : savedViews.map((v) => ({
          key: v.id,
          label: (
            <span className="flex items-center gap-2">
              <span className="flex-1 truncate">{v.name}</span>
              <button
                type="button"
                aria-label={`删除视图 ${v.name}`}
                className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={(e) => {
                  e.stopPropagation()
                  deleteSavedView(v.id)
                }}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </span>
          ),
          onClick: () => applySavedView(v),
        }))),
    { type: 'divider' as const },
    {
      key: 'save',
      label: '保存当前视图',
      icon: <Plus className="h-4 w-4" style={{ fontSize: 0 }} />,
      onClick: () => {
        setViewName('')
        setSaveViewOpen(true)
      },
    },
  ]

  const toggleSiteCol = (key: SiteColumn) => {
    const next = { ...siteCols, [key]: !siteCols[key] }
    setSiteCols(next)
    try {
      localStorage.setItem(SITE_COLUMNS_KEY, JSON.stringify(next))
    } catch { /* 存储不可用时只影响本次会话 */ }
  }

  // 常驻渲染按需禁用：切粒度时工具栏几何形状不变
  const colsApplicable = kind === 'site' && siteGroup
  const columnMenuItems: MenuProps['items'] = [
    { key: '_label', disabled: true, label: <span className="text-xs text-muted-foreground">站点列表列</span> },
    { type: 'divider' as const },
    ...SITE_COLUMNS.map((c) => ({
      key: c.key,
      label: (
        <span className="flex items-center gap-2">
          <Checkbox className="pointer-events-none" checked={siteCols[c.key]} />
          <span>{c.label}</span>
        </span>
      ),
      onClick: () => toggleSiteCol(c.key),
    })),
    { type: 'divider' as const },
    {
      key: 'reset',
      label: '恢复默认列',
      icon: <RotateCcw className="h-4 w-4" style={{ fontSize: 0 }} />,
      onClick: () => {
        setSiteCols({ ...DEFAULT_SITE_COLUMNS })
        try {
          localStorage.removeItem(SITE_COLUMNS_KEY)
        } catch { /* noop */ }
      },
    },
  ]

  // 聚类/偏移两种分页共用 total
  const offsetTotal = clusterView
    ? view === 'icons'
      ? iconClusters.data?.data.total ?? 0
      : techClusters.data?.data.total ?? 0
    : total

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
          <Dropdown
            trigger={['click']}
            menu={{ items: savedViewMenuItems, style: { minWidth: 240 } }}
          >
            <Button>
              <Bookmark className="mr-2 h-4 w-4" /> 保存的视图
            </Button>
          </Dropdown>
          <Button onClick={() => exportCurrent()} disabled={items.length === 0}>
            <Download className="mr-2 h-4 w-4" /> 导出本页
          </Button>
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Dropdown
            trigger={['click']}
            menu={{ items: columnMenuItems, style: { minWidth: 208 } }}
          >
            <Button disabled={!colsApplicable} title={colsApplicable ? undefined : '仅站点归并视图支持自定义列'}>
              <SlidersHorizontal className="mr-2 h-4 w-4" /> 列
            </Button>
          </Dropdown>
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
            onPressEnter={applyQuery}
          />
        </div>
        <Button type="primary" onClick={applyQuery}>查询</Button>
        <Button
          type="text"
          onClick={() => {
            setQ('')
            setAppliedQ('')
            setPage(1)
          }}
        >
          清空
        </Button>
        <Select
          className="w-[200px]"
          value={projectId}
          onChange={changeProject}
          placeholder="全部项目"
          options={[
            { value: '0', label: '全部项目' },
            ...(projects.data?.data ?? []).map((p) => ({
              value: String(p.id),
              label: `${p.name}（${p.asset_count}）`,
            })),
          ]}
        />
        <Select
          className="w-[200px]"
          value={activeFp || undefined}
          onChange={(v) => changeFp(typeof v === 'string' ? v : '')}
          placeholder="按指纹筛选"
          allowClear
          showSearch
          optionFilterProp="value"
          loading={appOptions.isLoading}
          options={(appOptions.data?.data.items ?? []).map((o) => ({
            value: o.name,
            label: `${o.name}（${o.site_count}）`,
          }))}
        />
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
        <span
          className="flex items-center gap-2 text-[13px] text-muted-foreground"
          title={kind === 'site' ? undefined : '仅站点粒度支持按站点归并'}
        >
          <Checkbox
            checked={siteGroup}
            disabled={kind !== 'site'}
            onChange={(e) => { setSiteGroup(e.target.checked); setPage(1) }}
          >
            按站点归并
          </Checkbox>
        </span>
        <span className="flex items-center gap-2 text-[13px] text-muted-foreground">
          <Checkbox checked={starredOnly} onChange={(e) => { setStarredOnly(e.target.checked); setPage(1) }}>
            只看星标
          </Checkbox>
        </span>
        <div className="flex items-center gap-2">
          <span className={'text-[13px] ' + (sortApplicable ? 'text-muted-foreground' : 'text-muted-foreground/50')}>
            排序
          </span>
          <Segmented value={sort} options={SORTS} disabled={!sortApplicable} onChange={(v) => { setSort(v); setPage(1) }} />
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[13px] text-muted-foreground">每页</span>
          <Select
            className="w-[76px]"
            value={String(clusterView ? 60 : pageSize)}
            disabled={clusterView}
            title={clusterView ? '图标/技术栈聚类视图固定每页 60' : undefined}
            onChange={(v) => { setPageSize(Number(v)); setPage(1) }}
            options={[20, 50, 100, 200, 500].map((n) => ({ value: String(n), label: String(n) }))}
          />
        </div>
        <span className="ml-auto flex items-center gap-2 text-sm text-muted-foreground">
          {list.isFetching && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-label="加载中" />}
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

      <ClusterView
        view={view === 'icons' ? 'icons' : 'technologies'}
        iconItems={iconClusters.data?.data.items ?? []}
        iconTotal={iconClusters.data?.data.total ?? 0}
        iconLoading={iconClusters.isLoading}
        techItems={techClusters.data?.data.items ?? []}
        techTotal={techClusters.data?.data.total ?? 0}
        techLoading={techClusters.isLoading}
        drillDown={drillDown}
      />

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
          <Button size="small" type="primary" onClick={() => setCreateOpen(true)}>
            <Rocket className="mr-1 h-4 w-4" />
            用选中资产创建任务
          </Button>
          <Button
            size="small"
            onClick={() => exportCurrent((items as Site[]).filter((s) => selectedHosts.has(s.value)))}
          >
            <Download className="mr-1 h-4 w-4" />
            导出所选
          </Button>
          <Button size="small" onClick={() => setSelectedHosts(new Set())}>
            <X className="mr-1 h-4 w-4" />
            清空选择
          </Button>
        </div>
      )}

      {!clusterView && (!data || data.view_supported !== false) && (
        <div
          className={
            'rounded-md border' +
            // 后台取新数据时整表弱化，代替「塌陷成加载态」的硬切换
            (list.isFetching && !list.isLoading ? ' opacity-60 transition-opacity' : ' transition-opacity')
          }
        >
          <Table<AssetRow>
            columns={columns}
            dataSource={items as AssetRow[]}
            rowKey={rowKey}
            loading={list.isFetching}
            pagination={false}
            virtual={virtualize}
            scroll={virtualize ? { y: '70vh' } : undefined}
            rowSelection={rowSelection as TableProps<AssetRow>['rowSelection']}
            expandable={expandable as TableProps<AssetRow>['expandable']}
            onRow={onRow}
            locale={{
              emptyText: hasFilters ? (
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
                      size="small"
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
                  className="border-0"
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
                      <Button size="small" type="primary" onClick={() => navigate('/tasks/new' + (projectId && projectId !== '0' ? `?project_id=${projectId}` : ''))}>
                        建第一个侦察任务
                      </Button>
                      <Button size="small" onClick={() => navigate('/tasks' + (projectId && projectId !== '0' ? `?project_id=${projectId}` : ''))}>
                        看任务列表
                      </Button>
                    </>
                  }
                  className="border-0"
                />
              ),
            }}
          />
        </div>
      )}

      {cursorMode ? (
        // 游标分页：只有上一页/下一页（keyset 无法跳页），页码即游标栈深度
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            第 {cursorStack.length} 页 · 本页 {items.length} 条
          </span>
          <div className="flex gap-2">
            <Button
              size="small"
              disabled={cursorStack.length <= 1}
              onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
            >
              上一页
            </Button>
            <Button
              size="small"
              disabled={!hasMore || !nextCursor}
              onClick={() => setCursorStack((stack) => [...stack, nextCursor])}
            >
              下一页
            </Button>
          </div>
        </div>
      ) : (
        // 偏移分页：风险排序 / 入口展开 / 聚类视图走 page 参数
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">共 {offsetTotal.toLocaleString()} 条</span>
          <Pagination
            current={page}
            pageSize={clusterView ? 60 : size}
            total={offsetTotal}
            showQuickJumper
            showSizeChanger={false}
            onChange={(p) => setPage(p)}
          />
        </div>
      )}

      {detailSite && (
        <AssetDetailDrawer
          site={detailSite}
          tab={detailTab}
          onTabChange={setDetailTab}
          onClose={() => setDetailSite(null)}
          onOpenFullPage={(id) => navigate(`/assets/${id}`)}
        />
      )}


      <Modal
        open={saveViewOpen}
        onCancel={() => setSaveViewOpen(false)}
        title="保存当前视图"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setSaveViewOpen(false)}>取消</Button>
            <Button type="primary" onClick={saveCurrentView} disabled={!viewName.trim()}>保存</Button>
          </div>
        }
      >
        <p className="mb-3 text-sm text-muted-foreground">
          保存查询串、粒度、视图、项目、排序与每页条数；不保存页码。
        </p>
        <Input
          autoFocus
          value={viewName}
          placeholder="例如：美团接口资产"
          onChange={(e) => setViewName(e.target.value)}
          onPressEnter={saveCurrentView}
        />
      </Modal>

      <CreateTaskFromAssetsDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        hosts={[...selectedHosts]}
        projectId={projectId !== '0' ? projectId : undefined}
      />
    </div>
  )
}

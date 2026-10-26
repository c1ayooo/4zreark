import { type ReactNode, useEffect, useMemo, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge as RFEdge,
  Handle,
  MarkerType,
  MiniMap,
  type Node as RFNode,
  type NodeProps,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Button, Skeleton, Tag } from 'antd'
import {
  Briefcase,
  Globe,
  Link2,
  type LucideIcon,
  MoreHorizontal,
  Network,
  Radio,
  Route,
  Server,
  X,
} from 'lucide-react'

import type {
  AssetGraphData,
  AssetGraphEdge,
  AssetGraphNode,
  AssetGraphRel,
} from '@/api/assets'
import { computeLayout, computeTreeLayout } from '@/lib/graph-layout'
import { cn } from '@/lib/utils'

type Kind = AssetGraphNode['kind']

type KindMeta = { label: string; icon: LucideIcon; hex: string }

const kindMeta: Record<Kind, KindMeta> = {
  project: { label: '项目', icon: Briefcase, hex: '#475569' },
  root_domain: { label: '根域名', icon: Globe, hex: '#2f6b4f' },
  subdomain: { label: '子域名', icon: Network, hex: '#94a3b8' },
  ip: { label: 'IP', icon: Server, hex: '#64748b' },
  service: { label: '服务', icon: Radio, hex: '#64748b' },
  endpoint: { label: '入口', icon: Link2, hex: '#94a3b8' },
  route: { label: '路由', icon: Route, hex: '#94a3b8' },
  // 「还有 N 个」聚合节点：点击加载同层下一批
  more: { label: '更多', icon: MoreHorizontal, hex: '#94a3b8' },
}

// 关系线只保留一个强调色，其余用中性灰；层级由位置和文案表达，不靠彩虹。
const relMeta: Record<AssetGraphRel, { label: string; color: string }> = {
  owns: { label: '归属', color: '#2f6b4f' },
  contains: { label: '包含', color: '#94a3b8' },
  resolves: { label: '解析', color: '#94a3b8' },
  exposes: { label: '暴露', color: '#94a3b8' },
  routes: { label: '路由', color: '#94a3b8' },
}

// 服务/入口的连通状态；其它层级是结构节点，没有测试态。
type ReachState = 'reachable' | 'pending' | 'lost'

function reachState(n: AssetGraphNode): ReachState | null {
  if (n.kind !== 'service' && n.kind !== 'endpoint') return null
  if (n.state === 'reachable') return 'reachable'
  if (n.state === 'lost') return 'lost'
  return 'pending'
}

const stateText: Record<ReachState, string> = {
  reachable: '可达',
  pending: '待确认',
  lost: '失联',
}

// 每层展开最多显示多少个子节点，超出部分收进「还有 N 个」聚合节点。
// 这是概览的性能闸门：同屏节点数 = 已展开路径 × 每层限量，与资产总量无关。
const PER_BATCH = 25

// 把平铺的子域名按 DNS 后缀重建为树：api.dev.meituan.com 挂到已存在的
// dev.meituan.com（或根域名）下。只重定向 root→sub 的 contains 边，
// 中间层不造虚拟节点，节点数始终等于真实资产数。
function withDomainHierarchy(nodes: AssetGraphNode[], edges: AssetGraphEdge[]): AssetGraphEdge[] {
  const known = new Set(nodes.map((n) => n.key))
  const needReroot = nodes.filter((n) => n.kind === 'subdomain')
  if (needReroot.length === 0) return edges

  const parentOverride = new Map<string, string>()
  for (const n of needReroot) {
    const host = (n.host || n.label).toLowerCase().replace(/\.$/, '')
    const parts = host.split('.')
    // 依次去掉最左一段，找已存在的最长后缀父域（子域或根域名）
    for (let i = 1; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.')
      const parentKey = known.has(`h:${candidate}`) ? `h:${candidate}` : known.has(`d:${candidate}`) ? `d:${candidate}` : ''
      if (parentKey) {
        parentOverride.set(n.key, parentKey)
        break
      }
    }
  }
  if (parentOverride.size === 0) return edges

  return edges.map((e) => {
    // 只有 contains 边的 dst 是子域名；service/ip 等边的 src 是子域名本身，不受影响
    const parent = parentOverride.get(e.dst)
    return parent && e.rel === 'contains' ? { ...e, src: parent } : e
  })
}

type ExpandedState = {
  /** 已展开的节点 key：可见性完全由它派生 */
  expanded: Set<string>
  /** 每个节点已展开的批数（key → batch index，0 表示第一批） */
  batches: Map<string, number>
}

// children 索引 + 每节点直接子节点数。按 kind 分层、label 排序，保证展开顺序稳定。
function buildChildrenIndex(nodes: AssetGraphNode[], edges: AssetGraphEdge[]) {
  const nodeByKey = new Map(nodes.map((n) => [n.key, n]))
  const kindOrder: Record<string, number> = {
    root_domain: 0,
    subdomain: 1,
    ip: 2,
    service: 3,
    endpoint: 4,
    route: 5,
  }
  const children = new Map<string, AssetGraphNode[]>()
  for (const e of edges) {
    const child = nodeByKey.get(e.dst)
    if (!child) continue
    const list = children.get(e.src)
    if (list) list.push(child)
    else children.set(e.src, [child])
  }
  for (const list of children.values()) {
    list.sort(
      (a, b) =>
        (kindOrder[a.kind] ?? 9) - (kindOrder[b.kind] ?? 9) || a.label.localeCompare(b.label),
    )
  }
  return children
}

// 某节点子树内各 kind 的节点数。带 memo 占位防环，整体 O(节点数)。
function makeSubtreeTally(children: Map<string, AssetGraphNode[]>) {
  const cache = new Map<string, Record<string, number>>()
  const tallyOf = (key: string): Record<string, number> => {
    const cached = cache.get(key)
    if (cached) return cached
    const tally: Record<string, number> = {}
    cache.set(key, tally) // 先占位防环
    for (const child of children.get(key) ?? []) {
      if (child.kind === 'more') continue
      tally[child.kind] = (tally[child.kind] ?? 0) + 1
      const sub = tallyOf(child.key)
      for (const k in sub) tally[k] = (tally[k] ?? 0) + sub[k]
    }
    return tally
  }
  return tallyOf
}

// 概览 = 从根集合出发的懒展开树。可见节点 = 根集合 ∪ 各已展开节点的子集（每层限量）。
function buildExpandableView(
  nodes: AssetGraphNode[],
  edges: AssetGraphEdge[],
  state: ExpandedState,
) {
  const children = buildChildrenIndex(nodes, edges)
  const tallyOf = makeSubtreeTally(children)

  const visibleNodes: AssetGraphNode[] = []
  const visibleEdges: AssetGraphEdge[] = []

  const walk = (key: string, force = false) => {
    // force：项目/IP 根节点是纯结构层，始终展开其子层
    if (!force && !state.expanded.has(key)) return
    const kids = children.get(key) ?? []
    const batch = state.batches.get(key) ?? 0
    const shown = kids.slice(0, (batch + 1) * PER_BATCH)
    for (const child of shown) {
      visibleNodes.push(child)
      visibleEdges.push({ src: key, dst: child.key, rel: 'contains' })
      walk(child.key)
    }
    if (kids.length > shown.length) {
      // 「还有 N 个」聚合节点：点击向父节点追加下一批
      const remaining = kids.length - shown.length
      const moreKey = `more:${key}:${batch}`
      visibleNodes.push({
        key: moreKey,
        kind: 'more',
        label: `还有 ${remaining} 个…`,
      })
      visibleEdges.push({ src: key, dst: moreKey, rel: 'contains' })
    }
  }

  const projects = nodes.filter((n) => n.kind === 'project')
  const roots = nodes.filter((n) => n.kind === 'root_domain')
  if (roots.length > 0) {
    for (const p of projects) {
      visibleNodes.push(p)
      walk(p.key, true)
    }
  } else {
    // 纯 IP 资产：最多 12 个 IP 做根，同样可展开到服务/入口/路由
    const ips = nodes.filter((n) => n.kind === 'ip').slice(0, 12)
    for (const p of projects) {
      visibleNodes.push(p)
      walk(p.key, true)
    }
    for (const ip of ips) {
      visibleNodes.push(ip)
      walk(ip.key, true)
    }
  }

  const directChildCount = (key: string) => (children.get(key) ?? []).filter((c) => c.kind !== 'more').length
  const counts = new Map<string, Record<string, number>>()
  for (const n of visibleNodes) {
    if (n.kind === 'more') continue
    counts.set(n.key, tallyOf(n.key))
  }

  return { nodes: visibleNodes, edges: visibleEdges, counts, directChildCount }
}

// 全量 = 全部节点 + DNS 层级重定向后的边，一次渲染。返回结构与概览一致。
function buildFullView(nodes: AssetGraphNode[], edges: AssetGraphEdge[]) {
  return {
    nodes,
    edges,
    counts: new Map<string, Record<string, number>>(),
    directChildCount: (_key: string) => 0,
  }
}

function summary(n: AssetGraphNode): string {
  if (n.kind === 'route') return `${n.method || 'GET'} ${n.path || '/'}`
  if (n.kind === 'service') {
    const parts: string[] = []
    if (n.port) parts.push(`:${n.port}`)
    if (n.title) parts.push(n.title)
    if (n.status_code) parts.push(String(n.status_code))
    return parts.length ? parts.join(' · ') : n.label
  }
  return n.label
}

type NodeData = {
  node: AssetGraphNode
  rootLabel: string
  counts?: Record<string, number>
  overview?: boolean
  vertical?: boolean
  /** 概览懒展开：直接子节点数、是否已展开 */
  childCount?: number
  expanded?: boolean
}
type GraphRFNode = RFNode<NodeData, 'asset'>

function AssetNode({ data, selected }: NodeProps<GraphRFNode>) {
  const n = data.node
  const meta = kindMeta[n.kind] ?? kindMeta.subdomain
  const Icon = meta.icon
  const state = reachState(n)
  const label = n.kind === 'project' ? data.rootLabel : meta.label

  const counts = data.counts
  const countText =
    data.overview && counts
      ? [
          counts.subdomain ? `子域 ${counts.subdomain}` : '',
          counts.service ? `服务 ${counts.service}` : '',
          counts.endpoint ? `入口 ${counts.endpoint}` : '',
          counts.route ? `路由 ${counts.route}` : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : ''

  // 展开状态提示：有子节点未展开 → 「+N」；已展开 → 「收起」
  const expandable = data.overview && (data.childCount ?? 0) > 0
  const expandText = expandable ? (data.expanded ? '收起' : `+${data.childCount}`) : ''

  return (
    <div
      className={cn(
        'group w-56 cursor-pointer rounded-md border bg-card transition-colors',
        selected
          ? 'border-primary ring-1 ring-primary/20'
          : state === 'lost'
            ? 'border-dashed border-border opacity-70'
            : 'border-border hover:border-muted-foreground/40'
      )}
    >
      <Handle
        type="target"
        position={data.vertical ? Position.Top : Position.Left}
        className="!size-2 !border !border-border !bg-card opacity-0 transition-opacity group-hover:opacity-100"
      />
      <div className="flex items-center gap-2 px-3 pt-2.5 pb-1">
        <Icon
          className={cn(
            'size-4 shrink-0',
            n.kind === 'root_domain' ? 'text-primary' : 'text-muted-foreground'
          )}
        />
        <span className="grow truncate text-[13px] font-medium text-foreground">{label}</span>
        {state === 'reachable' && <span className="size-1.5 shrink-0 rounded-full bg-primary" />}
      </div>
      <div className="line-clamp-2 px-3 pb-1.5 text-xs leading-snug text-muted-foreground">
        {summary(n) || label}
      </div>
      {countText && (
        <div className="px-3 pb-1.5 text-xs tabular-nums text-muted-foreground">{countText}</div>
      )}
      <div className="flex items-center justify-between gap-2 border-t px-3 py-1.5">
        {expandable ? (
          <span
            className={cn(
              'inline-flex items-center gap-1 rounded-sm px-1 text-xs tabular-nums',
              data.expanded ? 'text-muted-foreground' : 'bg-primary/10 text-primary'
            )}
          >
            {expandText}
          </span>
        ) : (
          <span className={cn('text-xs', state === 'reachable' ? 'text-primary' : 'text-muted-foreground')}>
            {state ? stateText[state] : label}
          </span>
        )}
        <span className="max-w-[8rem] shrink-0 truncate text-xs tabular-nums text-muted-foreground">
          {n.key}
        </span>
      </div>
      <Handle
        type="source"
        position={data.vertical ? Position.Bottom : Position.Right}
        className="!size-2 !border !border-border !bg-card opacity-0 transition-opacity group-hover:opacity-100"
      />
    </div>
  )
}

const nodeTypes = { asset: AssetNode }

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  if (children === undefined || children === null || children === '') return null
  return (
    <div className="flex items-start gap-3 py-1 text-sm">
      <span className="text-muted-foreground w-16 shrink-0">{label}</span>
      <span className="text-foreground min-w-0 flex-1 break-words">{children}</span>
    </div>
  )
}

export interface AssetGraphCanvasProps {
  data: AssetGraphData | null
  loading?: boolean
  /** 根节点的称谓：项目级星图叫「项目」，任务级星图叫「任务」 */
  rootLabel?: string
  emptyTitle?: string
  emptyHint?: string
  /** 详情面板底部说明 */
  note?: ReactNode
  /** 截断提示；缺省按站点数文案 */
  truncatedText?: string
  /** 覆盖画布尺寸，默认 h-[72vh] */
  className?: string
  /** 受控的概览/全量切换；不传则本地切换 */
  showAll?: boolean
  onShowAllChange?: (showAll: boolean) => void
  loadingFull?: boolean
}

export function AssetGraphCanvas({
  data,
  loading = false,
  rootLabel = '项目',
  emptyTitle = '暂无资产',
  emptyHint = '先导入资产或调整筛选条件',
  note = '星图展示资产层级关系，不包含漏洞信息。要看站点的漏洞，去「资产探索」或「漏洞管理」按主机筛选。',
  truncatedText,
  className,
  showAll: showAllProp,
  onShowAllChange,
  loadingFull = false,
}: AssetGraphCanvasProps) {
  const [selected, setSelected] = useState<AssetGraphNode | null>(null)
  const [localShowAll, setLocalShowAll] = useState(false)
  const showAll = showAllProp ?? localShowAll
  const setShowAll = (value: boolean) => {
    if (onShowAllChange) onShowAllChange(value)
    else setLocalShowAll(value)
  }
  // 概览懒展开状态：expanded 是可见性来源，batches 记录每层已展开的批次
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [batches, setBatches] = useState<Map<string, number>>(new Map())
  const [isMobile, setIsMobile] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(max-width: 639px)').matches
  )

  useEffect(() => {
    const media = window.matchMedia('(max-width: 639px)')
    const onChange = () => setIsMobile(media.matches)
    media.addEventListener?.('change', onChange)
    return () => media.removeEventListener?.('change', onChange)
  }, [])

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<GraphRFNode>([])
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<RFEdge>([])

  // 用 useMemo 固定空数组的引用：`?? []` 每次渲染都是新数组，作为 effect 依赖
  // 会自激成无限渲染。
  const allNodes = useMemo(() => data?.nodes ?? [], [data])
  const allEdges = useMemo(() => data?.edges ?? [], [data])
  // 子域名按 DNS 后缀重建父子（summary 数据只有项目/根域名，无需处理）
  const structuredEdges = useMemo(
    () => (data?.summary ? allEdges : withDomainHierarchy(allNodes, allEdges)),
    [data, allNodes, allEdges],
  )
  const graphView = useMemo(() => {
    if (showAll) {
      const view = buildFullView(allNodes, structuredEdges)
      return { ...view, counts: new Map<string, Record<string, number>>() }
    }
    const view = buildExpandableView(allNodes, structuredEdges, { expanded, batches })
    return view
  }, [data, allNodes, allEdges, structuredEdges, showAll, expanded, batches])
  const nodes = graphView.nodes
  const edges = graphView.edges

  const layout = useMemo(() => {
    // 手机概览改成纵向排列，避免两个节点横向撑出屏幕、缩到不可读。
    if (isMobile && !showAll) {
      const pos = new Map<string, { x: number; y: number }>()
      let y = 0
      for (const n of nodes) {
        pos.set(n.key, { x: 0, y })
        y += 180
      }
      return pos
    }
    // 概览是懒展开生成的纯树：树布局让每一层的父节点都垂直居中于自己的
    // 子块（项目→根域名、根域名→子域名同样对称）；全量图有跨层多父边，
    // 仍用分层布局。
    if (!showAll)
      return computeTreeLayout(
        nodes.map((n) => ({ id: n.key })),
        edges.map((e) => ({ src: e.src, dst: e.dst })),
      )
    return computeLayout(
      nodes.map((n) => ({ id: n.key })),
      edges.map((e) => ({ src: e.src, dst: e.dst })),
    )
  }, [isMobile, showAll, nodes, edges])

  // 结构签名：节点集合、状态、展开状态任一变化才重建 React Flow 数据。
  const viewSig = useMemo(
    () =>
      `${showAll ? 'all' : 'overview'}|${isMobile ? 'mobile' : 'desktop'}|${nodes
        .map((n) => `${n.key}:${n.state ?? ''}`)
        .join(',')}|${edges.length}|${[...expanded].sort().join(',')}|${[...batches.entries()]
        .map(([k, v]) => `${k}:${v}`)
        .join(',')}`,
    [showAll, isMobile, nodes, edges, expanded, batches],
  )

  useEffect(() => {
    setRfNodes((prev) => {
      // 保留用户拖过的位置，只在结构变化时用新布局补位。
      const prevPos = new Map(prev.map((p) => [p.id, p.position]))
      return nodes.map((n) => ({
        id: n.key,
        type: 'asset' as const,
        position: prevPos.get(n.key) ?? layout.get(n.key) ?? { x: 0, y: 0 },
        data: {
          node: n,
          rootLabel,
          counts: graphView.counts.get(n.key),
          overview: !showAll,
          vertical: isMobile && !showAll,
          childCount: graphView.directChildCount?.(n.key) ?? 0,
          expanded: n.kind === 'project' || expanded.has(n.key),
        },
        sourcePosition: isMobile && !showAll ? Position.Bottom : Position.Right,
        targetPosition: isMobile && !showAll ? Position.Top : Position.Left,
      }))
    })
    setRfEdges(
      edges.map((e, i) => {
        const meta = relMeta[e.rel] ?? relMeta.contains
        return {
          id: `e${i}-${e.src}-${e.dst}`,
          source: e.src,
          target: e.dst,
          label: meta.label,
          labelShowBg: false,
          labelStyle: { fontSize: 10, fontWeight: 600, fill: meta.color },
          style: { stroke: meta.color, strokeWidth: 2, strokeOpacity: 0.55 },
          markerEnd: { type: MarkerType.ArrowClosed, color: meta.color, width: 14, height: 14 },
        } satisfies RFEdge
      }),
    )
    // viewSig 是刻意的重排触发依赖：nodes/edges 都随它变化。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [viewSig, layout, nodes, edges, rootLabel, graphView.counts, setRfNodes, setRfEdges])

  const stats = useMemo(() => {
    if (data?.totals) return data.totals
    const byKind: Record<string, number> = {}
    for (const n of allNodes) byKind[n.kind] = (byKind[n.kind] ?? 0) + 1
    return byKind
  }, [data, allNodes])

  useEffect(() => {
    if (selected && !nodes.some((n) => n.key === selected.key)) setSelected(null)
  }, [nodes, selected])

  const kindLabel = (k: Kind) => (k === 'project' ? rootLabel : kindMeta[k]?.label ?? k)

  // 概览点击：more 聚合节点 → 父节点追加下一批；普通节点 → 选中详情 + 切换展开
  const handleNodeClick = (node: GraphRFNode) => {
    const n = node.data.node
    if (!showAll && n.kind === 'more') {
      const rest = n.key.slice('more:'.length)
      const idx = rest.lastIndexOf(':')
      const parentKey = idx > 0 ? rest.slice(0, idx) : ''
      if (parentKey) {
        setBatches((prev) => new Map(prev).set(parentKey, (prev.get(parentKey) ?? 0) + 1))
      }
      return
    }
    setSelected(n)
    if (!showAll) {
      setExpanded((prev) => {
        const next = new Set(prev)
        if (next.has(n.key)) next.delete(n.key)
        else next.add(n.key)
        return next
      })
    }
  }

  return (
    <div className={cn('relative w-full overflow-hidden rounded-xl', className ?? 'h-auto min-h-[600px] lg:h-[72vh]')}>
      {data === null && loading ? (
        <div className="p-6">
          <Skeleton active title={false} paragraph={{ rows: 8 }} />
        </div>
      ) : nodes.length === 0 ? (
        <div className="text-muted-foreground flex h-full flex-col items-center justify-center gap-2">
          <Network className="h-10 w-10 opacity-40" />
          <p>{emptyTitle}</p>
          <p className="text-xs">{emptyHint}</p>
        </div>
      ) : (
        <div className="flex h-full flex-col lg:flex-row">
          <aside className="shrink-0 overflow-y-auto border-b bg-card p-3 lg:w-80 lg:border-b-0 lg:border-r">
            <div className="flex flex-col gap-2.5 text-[13px]">
              <div className="flex items-center justify-between gap-3">
                <span className="text-muted-foreground">视图</span>
                <div className="inline-flex overflow-hidden rounded-sm border">
                  <button
                    type="button"
                    aria-pressed={!showAll}
                    onClick={() => setShowAll(false)}
                    className={cn(
                      'px-2.5 py-1 text-[13px] transition-colors',
                      !showAll
                        ? 'bg-foreground text-background'
                        : 'bg-background text-muted-foreground hover:bg-muted'
                    )}
                  >
                    概览
                  </button>
                  <button
                    type="button"
                    aria-pressed={showAll}
                    onClick={() => setShowAll(true)}
                    className={cn(
                      'px-2.5 py-1 text-[13px] transition-colors',
                      showAll
                        ? 'bg-foreground text-background'
                        : 'bg-background text-muted-foreground hover:bg-muted'
                    )}
                  >
                    {loadingFull ? '加载中…' : '全量'}
                  </button>
                </div>
              </div>
              <div className="text-muted-foreground">
                {rootLabel}{' '}
                <span className="text-foreground font-semibold tabular-nums">{stats.project ?? 0}</span>{' '}
                · 子域{' '}
                <span className="text-foreground font-semibold tabular-nums">{stats.subdomain ?? 0}</span>
                {' '}· 服务{' '}
                <span className="text-foreground font-semibold tabular-nums">{stats.service ?? 0}</span>{' '}
                · 入口{' '}
                <span className="text-foreground font-semibold tabular-nums">{stats.endpoint ?? 0}</span>
                {' '}· 路由{' '}
                <span className="text-foreground font-semibold tabular-nums">{stats.route ?? 0}</span>
                {data?.truncated && (
                  <span className="text-amber-600">
                    {' '}· {truncatedText ?? `仅展示最近 ${data.limit} 个站点`}
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-x-3 gap-y-1.5">
                {(Object.keys(kindMeta) as Kind[]).map((k) => {
                  const Icon = kindMeta[k].icon
                  return (
                    <span key={k} className="inline-flex items-center gap-1.5 text-muted-foreground">
                      <Icon
                        className={cn(
                          'size-3.5',
                          k === 'root_domain' ? 'text-primary' : 'text-muted-foreground'
                        )}
                      />
                      {kindLabel(k)}
                    </span>
                  )
                })}
              </div>
              <div className="border-border/60 text-muted-foreground flex flex-wrap gap-x-3 gap-y-1.5 border-t pt-2">
                {(Object.keys(relMeta) as AssetGraphRel[]).map((k) => (
                  <span key={k} className="inline-flex items-center gap-1.5">
                    <span
                      className="h-0.5 w-4 rounded-full"
                      style={{ backgroundColor: relMeta[k].color }}
                    />
                    {relMeta[k].label}
                  </span>
                ))}
              </div>
              <div className="border-border/60 text-muted-foreground flex flex-wrap gap-x-3 gap-y-1.5 border-t pt-2">
                <span className="inline-flex items-center gap-1.5">
                  <span className="size-3 rounded-full bg-primary" /> 可达
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="size-3 rounded-full bg-muted-foreground" /> 待确认
                </span>
                <span className="inline-flex items-center gap-1.5">
                  <span className="size-3 rounded-full border border-dashed border-border bg-muted" />{' '}
                  失联
                </span>
              </div>
              <p className="text-muted-foreground/80 border-border/60 border-t pt-2 leading-relaxed">
                概览点击节点逐层展开（每层最多 {PER_BATCH} 个，超出收进「还有 N 个」）；子域名按
                DNS 层级嵌套。全量用于筛选后的细节排查。可拖拽节点、滚轮缩放。
              </p>
            </div>
          </aside>

          <div className="relative h-[480px] w-full shrink-0 lg:h-full lg:flex-1">
            <ReactFlow
              key={showAll ? 'full' : 'overview'}
              nodes={rfNodes}
              edges={rfEdges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={(_, node) => handleNodeClick(node as GraphRFNode)}
              nodeTypes={nodeTypes}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              proOptions={{ hideAttribution: true }}
              onlyRenderVisibleElements
              minZoom={showAll ? 0.1 : 0.7}
              className="!bg-background"
            >
              <Background
                variant={BackgroundVariant.Dots}
                gap={16}
                size={1}
                className="text-muted-foreground/25"
              />
              <Controls
                showInteractive={false}
                className="!rounded-md !border !shadow-none [&>button]:!border-border [&>button]:!bg-card [&>button:hover]:!bg-accent [&_svg]:!fill-foreground"
              />
              <MiniMap
                pannable
                zoomable
                className="!rounded-md !border !bg-card !shadow-none"
                maskColor="rgb(148 163 184 / 0.14)"
                nodeColor={(node) => {
                  const n = (node.data as NodeData | undefined)?.node
                  if (!n) return '#cbd5e1'
                  const st = reachState(n)
                  if (st === 'pending') return '#94a3b8'
                  if (st === 'lost') return '#cbd5e1'
                  return kindMeta[n.kind]?.hex ?? '#94a3b8'
                }}
                nodeStrokeWidth={0}
                nodeBorderRadius={4}
              />
            </ReactFlow>
          </div>
        </div>
      )}

      {selected && (
        <div className="bg-card text-card-foreground absolute top-3 right-3 z-10 w-80 rounded-xl border shadow">
          <div className="p-4">
            <div className="mb-3 flex items-start justify-between gap-2">
              <div className="flex items-center gap-2.5">
                {(() => {
                  const Icon = kindMeta[selected.kind].icon
                  return (
                    <Icon
                      className={cn(
                        'size-5 shrink-0',
                        selected.kind === 'root_domain'
                          ? 'text-primary'
                          : 'text-muted-foreground'
                      )}
                    />
                  )
                })()}
                <div className="min-w-0">
                  <div className="font-semibold leading-tight">{kindLabel(selected.kind)}</div>
                  <div
                    className="truncate text-xs text-muted-foreground"
                    title={selected.label}
                  >
                    {selected.label}
                  </div>
                </div>
              </div>
              <Button
                type="text"
                className="h-11 w-11 sm:h-7 sm:w-7"
                aria-label="关闭详情"
                onClick={() => setSelected(null)}
                icon={<X className="size-4" />}
              />
            </div>

            <div className="mb-2">
              <DetailRow label="状态">
                {reachState(selected) ? (
                  <Tag
                    color={reachState(selected) === 'reachable' ? 'success' : undefined}
                    className="font-normal"
                  >
                    {stateText[reachState(selected) as ReachState]}
                  </Tag>
                ) : (
                  <span className="text-muted-foreground">结构节点</span>
                )}
              </DetailRow>
              <DetailRow label="主机">{selected.host}</DetailRow>
              <DetailRow label="端口">{selected.port}</DetailRow>
              <DetailRow label="协议">{selected.protocol}</DetailRow>
              <DetailRow label="IP">{selected.ip}</DetailRow>
              <DetailRow label="标题">{selected.title}</DetailRow>
              <DetailRow label="状态码">{selected.status_code}</DetailRow>
              <DetailRow label="技术">
                {selected.tech && selected.tech.length > 0 ? selected.tech.join(', ') : undefined}
              </DetailRow>
              <DetailRow label="站点 ID">{selected.site_id}</DetailRow>
              <DetailRow label="项目 ID">{selected.project_id}</DetailRow>
              <DetailRow label="节点键">
                <span className="text-xs">{selected.key}</span>
              </DetailRow>
            </div>

            <p className="text-muted-foreground border-t pt-2 text-xs leading-relaxed">{note}</p>
          </div>
        </div>
      )}
    </div>
  )
}

export default AssetGraphCanvas

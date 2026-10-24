import { useEffect, useMemo, useRef, useState } from 'react'
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
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Button, Input, Skeleton, Tag } from 'antd'
import { ChevronsDownUp, ChevronsUpDown, Network, Search } from 'lucide-react'

import { assetApi } from '@/api/assets'
import {
  relationTypeColor,
  relationTypeLabel,
  type RelationEdge,
  type RelationGraphData,
  type RelationNode,
} from '@/api/relations'
import { cn } from '@/lib/utils'
import { computeForceLayout, type ForceLayoutLink, type ForceLayoutNode } from './force-layout'
import { RelationDetailDrawer, type RelationSelection } from './RelationDetailDrawer'

// 关系图谱画布：根域折叠簇视图。
//   - 折叠态：站点按根域聚成簇节点，簇间只画跨域边（同 IP/同证书/同 C 段等跨域复用），
//     同簇内部的边不画（展开后自然出现）；
//   - 点簇展开成员站点，跨簇边挂到具体成员；再点工具栏的 ✕ 收起；
//   - 布局用 d3-force：已有位置的节点固定不动，只给新节点补位，展开/收起不整图跳动。

// 常见多段后缀：取三段为根域（a.com.cn 而不是 com.cn）。
const MULTIPART_TLDS = new Set([
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.uk', 'com.hk', 'com.tw', 'com.au', 'co.jp', 'co.kr',
])

export function rootDomainOf(host: string): string {
  const h = (host || '').toLowerCase().trim().replace(/\.$/, '')
  if (!h) return '(未知)'
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(':')) return h // IP 各自成簇
  const parts = h.split('.').filter(Boolean)
  if (parts.length <= 2) return h
  const last2 = parts.slice(-2).join('.')
  if (MULTIPART_TLDS.has(last2)) return parts.slice(-3).join('.')
  return last2
}

// ---------------------------------------------------------------- 展示模型

interface DisplayNode {
  id: string // 'c:<root>' | 's:<siteId>'
  kind: 'cluster' | 'site'
  root: string
  label: string
  icon?: string
  count: number
  radius: number
  site?: RelationNode
  /** 簇节点：成员站点 id（收起时按成员质心补位用） */
  memberIds?: number[]
}

interface DisplayEdge {
  id: string
  source: string
  target: string
  type: string
  /** 聚合边展示用的聚类键（取第一条成员边的） */
  key: string
  confidence: number
  /** 聚合了多少条原始边（簇间同类型同向） */
  count: number
  /** 聚合的原始边，证据抽屉按其中一条取证 */
  members: RelationEdge[]
}

const clusterId = (root: string) => `c:${root}`
const siteId = (site: RelationNode) => `s:${site.id}`

function buildDisplayGraph(
  data: RelationGraphData,
  expanded: Set<string>,
): { nodes: DisplayNode[]; edges: DisplayEdge[]; byType: Map<string, number>; siteDegree: Map<number, number> } {
  const siteRoot = new Map<number, string>()
  const rootMembers = new Map<string, RelationNode[]>()
  for (const n of data.nodes) {
    const root = rootDomainOf(n.host)
    siteRoot.set(n.id, root)
    const list = rootMembers.get(root)
    if (list) list.push(n)
    else rootMembers.set(root, [n])
  }

  const siteDegree = new Map<number, number>()
  const byType = new Map<string, number>()
  const edgeAgg = new Map<string, DisplayEdge>()
  for (const e of data.edges) {
    byType.set(e.type, (byType.get(e.type) ?? 0) + 1)
    siteDegree.set(e.left.id, (siteDegree.get(e.left.id) ?? 0) + 1)
    siteDegree.set(e.right.id, (siteDegree.get(e.right.id) ?? 0) + 1)

    const rootL = siteRoot.get(e.left.id) ?? '(未知)'
    const rootR = siteRoot.get(e.right.id) ?? '(未知)'
    const src = expanded.has(rootL) ? siteId(e.left) : clusterId(rootL)
    const dst = expanded.has(rootR) ? siteId(e.right) : clusterId(rootR)
    if (src === dst) continue // 同簇内部边且簇折叠：展开后自然出现
    const aggKey = `${src}|${dst}|${e.type}`
    const agg = edgeAgg.get(aggKey)
    if (agg) {
      agg.count += 1
      agg.confidence = Math.max(agg.confidence, e.confidence)
      agg.members.push(e)
    } else {
      edgeAgg.set(aggKey, {
        id: `r${e.id}`, source: src, target: dst, type: e.type,
        key: e.key, confidence: e.confidence, count: 1, members: [e],
      })
    }
  }

  const nodes: DisplayNode[] = []
  for (const [root, members] of rootMembers) {
    if (expanded.has(root)) {
      for (const m of members) {
        nodes.push({
          id: siteId(m), kind: 'site', root, label: m.host,
          icon: m.icon_sha256 || undefined, count: siteDegree.get(m.id) ?? 0,
          radius: 14 + Math.min(10, (siteDegree.get(m.id) ?? 0)), site: m,
        })
      }
    } else {
      const icon = members.find((m) => m.icon_sha256)?.icon_sha256
      nodes.push({
        id: clusterId(root), kind: 'cluster', root, label: root, icon,
        count: members.length,
        radius: 22 + Math.sqrt(members.length) * 2.5,
        memberIds: members.map((m) => m.id),
      })
    }
  }
  return { nodes, edges: [...edgeAgg.values()], byType, siteDegree }
}

// ---------------------------------------------------------------- 自定义节点

interface RelNodeData extends Record<string, unknown> {
  disp: DisplayNode
  dim: boolean
}
type RelRFNode = RFNode<RelNodeData>

function NodeChrome({ selected, dim }: { selected?: boolean; dim: boolean }) {
  return (
    <>
      <Handle
        type="target"
        position={Position.Left}
        className="!size-2 !border !border-border !bg-card opacity-0"
      />
      {selected && <span className="pointer-events-none absolute -inset-0.5 rounded-[inherit] ring-2 ring-primary/50" />}
      {dim && <span className="bg-background/60 pointer-events-none absolute -inset-1 rounded-[inherit]" />}
    </>
  )
}

function SiteIcon({ sha, host, size = 16 }: { sha?: string; host: string; size?: number }) {
  if (sha)
    return (
      <img
        src={assetApi.iconURL(sha)}
        alt=""
        width={size}
        height={size}
        className="shrink-0 rounded-sm"
        onError={(e) => {
          ;(e.target as HTMLImageElement).style.visibility = 'hidden'
        }}
      />
    )
  return (
    <span
      className="bg-primary/15 text-primary flex shrink-0 items-center justify-center rounded-sm text-[10px] font-bold uppercase"
      style={{ width: size, height: size }}
    >
      {host.replace(/^www\./, '').charAt(0) || '?'}
    </span>
  )
}

function SiteNodeView({ data, selected }: NodeProps<RelRFNode>) {
  const { disp, dim } = data
  return (
    <div
      title={disp.site ? `${disp.site.title || disp.site.host} · ${disp.site.ip || ''}` : disp.label}
      className={cn(
        'group relative flex cursor-pointer items-center gap-1.5 rounded-full border bg-card py-1 pl-2 pr-2.5 transition-colors',
        selected ? 'border-primary' : 'border-border hover:border-muted-foreground/40',
      )}
    >
      <NodeChrome selected={selected} dim={dim} />
      <SiteIcon sha={disp.icon} host={disp.label} />
      <span className="max-w-[170px] truncate font-mono text-xs">{disp.label}</span>
      {disp.count > 3 && (
        <span className="bg-muted text-muted-foreground rounded-full px-1.5 text-[10px] tabular-nums">
          {disp.count}
        </span>
      )}
    </div>
  )
}

function ClusterNodeView({ data, selected }: NodeProps<RelRFNode>) {
  const { disp, dim } = data
  return (
    <div
      title={`点击展开 ${disp.root} 的 ${disp.count} 个站点`}
      className={cn(
        'relative cursor-pointer rounded-xl border-2 bg-card px-3 py-2 text-center shadow-sm transition-colors',
        selected ? 'border-primary' : 'border-border hover:border-primary/50',
      )}
      style={{ fontSize: Math.min(17, 12 + Math.sqrt(disp.count) * 0.6) }}
    >
      <NodeChrome selected={selected} dim={dim} />
      <div className="flex items-center gap-1.5">
        <SiteIcon sha={disp.icon} host={disp.label} size={18} />
        <span className="font-medium">{disp.label}</span>
      </div>
      <div className="text-muted-foreground text-xs tabular-nums">{disp.count} 站点 · 点击展开</div>
    </div>
  )
}

const nodeTypes = { cluster: ClusterNodeView, site: SiteNodeView }

// ---------------------------------------------------------------- 画布

export interface RelationGraphCanvasProps {
  data: RelationGraphData | null
  loading: boolean
  className?: string
}

function GraphInner({ data, loading, className }: RelationGraphCanvasProps) {
  const rf = useReactFlow()
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<RelationSelection | null>(null)
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [query, setQuery] = useState('')

  const posRef = useRef(new Map<string, { x: number; y: number }>())

  const display = useMemo(
    () => (data ? buildDisplayGraph(data, expanded) : { nodes: [], edges: [], byType: new Map<string, number>(), siteDegree: new Map<number, number>() }),
    [data, expanded],
  )
  const visibleEdges = useMemo(
    () => display.edges.filter((e) => !hiddenTypes.has(e.type)),
    [display.edges, hiddenTypes],
  )

  // 布局：已有位置的节点固定不动（拖拽/展开保留）；新节点补位——
  // 展开簇的成员围绕原簇位置散开，重新收起的簇落回成员质心。
  const layout = useMemo(() => {
    const sitePos = (id: number) => posRef.current.get(`s:${id}`)
    const seeds: ForceLayoutNode[] = display.nodes.map((n) => {
      const p = posRef.current.get(n.id)
      if (p) return { id: n.id, x: p.x, y: p.y, fixed: true, radius: n.radius }
      if (n.kind === 'site') {
        const center = posRef.current.get(clusterId(n.root))
        return {
          id: n.id,
          x: center ? center.x + (Math.random() - 0.5) * 160 : undefined,
          y: center ? center.y + (Math.random() - 0.5) * 160 : undefined,
          radius: n.radius,
        }
      }
      // 新簇节点（收起后重新出现）：成员当前位置的质心。
      const members = (n.memberIds ?? []).map(sitePos).filter((q): q is { x: number; y: number } => !!q)
      if (members.length > 0) {
        const cx = members.reduce((s, q) => s + q.x, 0) / members.length
        const cy = members.reduce((s, q) => s + q.y, 0) / members.length
        return { id: n.id, x: cx, y: cy, fixed: true, radius: n.radius }
      }
      return { id: n.id, radius: n.radius }
    })
    const links: ForceLayoutLink[] = visibleEdges.map((e) => ({
      source: e.source, target: e.target, type: e.type, confidence: e.confidence,
    }))
    return computeForceLayout(seeds, links)
    // displayNodes/visibleEdges 都随 data/expanded/hiddenTypes 变化。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, expanded, hiddenTypes])

  useEffect(() => {
    if (!data) return
    posRef.current = layout
  }, [layout, data])

  const [rfNodes, setRfNodes, onNodesChange] = useNodesState<RelRFNode>([])
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState<RFEdge>([])

  // 邻域高亮：选中节点/边时，其余节点与不相关边淡出。
  const highlight = useMemo(() => {
    if (!data) return null
    if (selected?.kind === 'node' && selected.site) {
      const id = selected.site.id
      const neighbors = new Set<string>([`s:${id}`])
      for (const e of data.edges) {
        if (e.left.id !== id && e.right.id !== id) continue
        // 邻居可能是展开的站点节点，也可能是折叠簇节点——两种形态都加进高亮集，
        // 展示层哪种存在哪种生效。
        const other = e.left.id === id ? e.right : e.left
        neighbors.add(`s:${other.id}`)
        neighbors.add(clusterId(rootDomainOf(other.host)))
      }
      return { center: `s:${id}`, neighbors }
    }
    if (selected?.kind === 'edge' && selected.edge) {
      const e = selected.edge
      return {
        center: '',
        neighbors: new Set([siteId(e.left), siteId(e.right), clusterId(rootDomainOf(e.left.host)), clusterId(rootDomainOf(e.right.host))]),
      }
    }
    return null
  }, [data, selected])

  const nodeSig = display.nodes.map((n) => n.id).join(',') + `|${expanded.size}`
  useEffect(() => {
    if (!data) return
    setRfNodes(
      display.nodes.map((n) => {
        const dim = !!highlight && !highlight.neighbors.has(n.id)
        return {
          id: n.id,
          type: n.kind,
          position: posRef.current.get(n.id) ?? { x: 0, y: 0 },
          data: { disp: n, dim },
          hidden: query !== '' && !n.label.toLowerCase().includes(query.toLowerCase()),
        } satisfies RelRFNode
      }),
    )
    // nodeSig 是刻意的重排触发依赖。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeSig, layout, highlight, data, query, setRfNodes])

  const edgeSig = visibleEdges.map((e) => e.id).join(',') + `|${hiddenTypes.size}|${selected ? selected.kind + (selected.edge?.id ?? selected.site?.id ?? '') : ''}`
  useEffect(() => {
    if (!data) return
    setRfEdges(
      visibleEdges.map((e) => {
        const color = relationTypeColor[e.type] ?? '#94a3b8'
        const active =
          selected?.kind === 'edge' && selected.edge
            ? e.members.some((m) => m.id === selected.edge!.id)
            : !!highlight &&
              ((selected?.kind === 'node' && highlight.neighbors.has(e.source) && highlight.neighbors.has(e.target)) ||
                false)
        const dimmed = !!highlight && !active
        const directed = e.type === 'redirect' || e.type === 'domain_parent'
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.count > 1 ? `${relationTypeLabel[e.type] ?? e.type} ×${e.count}` : undefined,
          labelShowBg: true,
          labelBgPadding: [4, 2],
          labelBgBorderRadius: 3,
          labelStyle: { fontSize: 10, fontWeight: 600, fill: color, opacity: dimmed ? 0.15 : 0.9 },
          style: {
            stroke: color,
            strokeWidth: active ? 2.5 : 1 + e.confidence * 2,
            opacity: dimmed ? 0.08 : 0.45,
          },
          markerEnd: directed
            ? { type: MarkerType.ArrowClosed, color, width: 12, height: 12 }
            : undefined,
          zIndex: active ? 10 : 0,
        } satisfies RFEdge
      }),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edgeSig, highlight, data, visibleEdges, setRfEdges])

  // 结构变化后自适应视野；选中搜索结果时聚焦到该节点。
  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.15, duration: 300 }), 80)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeSig])

  // ------------------------------------------------------------ 交互

  const handleNodeClick = (_: unknown, node: RelRFNode) => {
    const n = node.data.disp
    if (n.kind === 'cluster') {
      setExpanded((prev) => new Set(prev).add(n.root))
      setSelected(null)
      return
    }
    if (!n.site) return
    const incident = new Map<string, number>()
    for (const e of data?.edges ?? []) {
      if (e.left.id === n.site.id || e.right.id === n.site.id) {
        incident.set(e.type, (incident.get(e.type) ?? 0) + 1)
      }
    }
    setSelected({
      kind: 'node',
      site: n.site,
      incident: [...incident.entries()].map(([type, count]) => ({ type, count })),
    })
  }

  const handleEdgeClick = (_: unknown, edge: RFEdge) => {
    const e = display.edges.find((d) => d.id === edge.id)
    if (!e) return
    // 聚合边默认取第一条成员边做证据展示，抽屉里可切换。
    setSelected({ kind: 'edge', edge: e.members[0], members: e.members })
  }

  const toggleType = (type: string) =>
    setHiddenTypes((prev) => {
      const next = new Set(prev)
      if (next.has(type)) next.delete(type)
      else next.add(type)
      return next
    })

  const collapseAll = () => {
    setExpanded(new Set())
    setSelected(null)
  }
  const canExpandAll = (data?.nodes.length ?? 0) > 0 && (data?.nodes.length ?? 0) <= 1500
  const expandAll = () => {
    if (!canExpandAll) return
    setSelected(null)
    setExpanded(new Set(display.nodes.filter((n) => n.kind === 'cluster').map((n) => n.root)))
  }

  const legendTypes = [...display.byType.entries()].sort((a, b) => b[1] - a[1])

  return (
    <div className={cn('relative w-full overflow-hidden rounded-md border', className ?? 'h-[64vh]')}>
      {data === null && loading ? (
        <div className="p-6">
          <Skeleton active title={false} paragraph={{ rows: 8 }} />
        </div>
      ) : display.nodes.length === 0 ? (
        <div className="text-muted-foreground flex h-full flex-col items-center justify-center gap-2">
          <Network className="h-10 w-10 opacity-40" />
          <p>还没有关系边</p>
          <p className="text-xs">导入资产后点右上角「重建图谱」；同 IP/父子域/同图标/同技术栈会生成聚类。</p>
        </div>
      ) : (
        <>
          {/* 顶部工具条 */}
          <div className="absolute inset-x-3 top-3 z-10 flex flex-wrap items-center gap-2">
            <Input
              allowClear
              size="small"
              prefix={<Search className="h-3.5 w-3.5 opacity-50" />}
              placeholder="按域名过滤节点…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-56"
            />
            {expanded.size > 0 && (
              <Button size="small" icon={<ChevronsDownUp className="h-3.5 w-3.5" />} onClick={collapseAll}>
                收起全部
              </Button>
            )}
            {expanded.size < display.nodes.filter((n) => n.kind === 'cluster').length && (
              <Button
                size="small"
                icon={<ChevronsUpDown className="h-3.5 w-3.5" />}
                disabled={!canExpandAll}
                title={canExpandAll ? '展开全部簇' : '节点数过多，请按簇手动展开'}
                onClick={expandAll}
              >
                展开全部
              </Button>
            )}
            {data?.truncated && (
              <Tag color="warning" className="!m-0">
                已截断（上限 5000 条）
              </Tag>
            )}
          </div>

          {/* 图例：点击隐藏/显示对应类型 */}
          <div className="absolute bottom-3 left-3 z-10 flex max-w-[60%] flex-wrap gap-x-3 gap-y-1 rounded-md border bg-card/90 p-2 backdrop-blur">
            {legendTypes.map(([type, count]) => (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                className={cn(
                  'inline-flex items-center gap-1.5 text-xs transition-opacity',
                  hiddenTypes.has(type) ? 'opacity-35' : 'hover:opacity-80',
                )}
                title={hiddenTypes.has(type) ? '点击显示' : '点击隐藏'}
              >
                <span className="h-0.5 w-4 rounded-full" style={{ backgroundColor: relationTypeColor[type] ?? '#94a3b8' }} />
                {relationTypeLabel[type] ?? type}
                <span className="text-muted-foreground tabular-nums">{count}</span>
              </button>
            ))}
          </div>

          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            onEdgeClick={handleEdgeClick}
            onPaneClick={() => setSelected(null)}
            onNodeDragStop={(_, node) => posRef.current.set(node.id, node.position)}
            nodeTypes={nodeTypes}
            onlyRenderVisibleElements
            minZoom={0.02}
            proOptions={{ hideAttribution: true }}
            fitView
            fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} />
            <MiniMap pannable zoomable className="!bottom-12" />
            <Controls showInteractive={false} />
          </ReactFlow>

          <RelationDetailDrawer selection={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  )
}

export function RelationGraphCanvas(props: RelationGraphCanvasProps) {
  return (
    <ReactFlowProvider>
      <GraphInner {...props} />
    </ReactFlowProvider>
  )
}

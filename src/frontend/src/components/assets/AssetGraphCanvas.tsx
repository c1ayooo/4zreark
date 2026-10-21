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
import {
  Briefcase,
  Globe,
  Link2,
  type LucideIcon,
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
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { computeLayout } from '@/lib/graph-layout'
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

// 概览只渲染项目/根域名/IP，子域、服务、入口、路由折叠成计数，避免几千节点挤成一列。
// 全量视图保留全部节点，用于搜索或项目筛选后的细节排查。
function buildGraphView(nodes: AssetGraphNode[], edges: AssetGraphEdge[], showAll: boolean) {
  if (showAll) {
    return { nodes, edges, counts: new Map<string, Record<string, number>>() }
  }

  const nodeByKey = new Map(nodes.map((n) => [n.key, n]))
  const roots = nodes.filter((n) => n.kind === 'root_domain')
  const projects = nodes.filter((n) => n.kind === 'project')
  // 概览是「星座」而不是全量节点图：有根域名时只显示项目和根域名，
  // 根域名节点上给子域/服务/入口计数；没有根域名（纯 IP 资产）时最多显示 12 个 IP。
  const visibleNodes =
    roots.length > 0
      ? [...projects, ...roots]
      : [...projects, ...nodes.filter((n) => n.kind === 'ip').slice(0, 12)]
  const visibleSet = new Set(visibleNodes.map((n) => n.key))

  const children = new Map<string, AssetGraphEdge[]>()
  const parentOf = new Map<string, string>()
  for (const e of edges) {
    const list = children.get(e.src)
    if (list) list.push(e)
    else children.set(e.src, [e])
    if (!parentOf.has(e.dst)) parentOf.set(e.dst, e.src)
  }

  const counts = new Map<string, Record<string, number>>()
  for (const root of visibleNodes) {
    const tally: Record<string, number> = {}
    const stack = [...(children.get(root.key) ?? [])]
    const seen = new Set<string>()
    while (stack.length > 0) {
      const edge = stack.pop()!
      if (seen.has(edge.dst)) continue
      seen.add(edge.dst)
      const child = nodeByKey.get(edge.dst)
      if (child) tally[child.kind] = (tally[child.kind] ?? 0) + 1
      stack.push(...(children.get(edge.dst) ?? []))
    }
    counts.set(root.key, tally)
  }

  const visibleEdges: AssetGraphEdge[] = []
  const edgeSeen = new Set<string>()
  for (const e of edges) {
    if (!visibleSet.has(e.dst)) continue
    let src = e.src
    const guard = new Set<string>()
    while (src && !visibleSet.has(src) && parentOf.has(src) && !guard.has(src)) {
      guard.add(src)
      src = parentOf.get(src)!
    }
    if (!visibleSet.has(src) || src === e.dst) continue
    const key = `${src}|${e.dst}`
    if (edgeSeen.has(key)) continue
    edgeSeen.add(key)
    visibleEdges.push({ src, dst: e.dst, rel: e.rel })
  }

  return { nodes: visibleNodes, edges: visibleEdges, counts }
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
}
type GraphRFNode = RFNode<NodeData, 'asset'>

function AssetNode({ data, selected }: NodeProps<GraphRFNode>) {
  const n = data.node
  const meta = kindMeta[n.kind]
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
        ]
          .filter(Boolean)
          .join(' · ')
      : ''

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
        <span className={cn('text-xs', state === 'reachable' ? 'text-primary' : 'text-muted-foreground')}>
          {state ? stateText[state] : label}
        </span>
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
}: AssetGraphCanvasProps) {
  const [selected, setSelected] = useState<AssetGraphNode | null>(null)
  const [showAll, setShowAll] = useState(false)
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
  const graphView = useMemo(
    () => buildGraphView(allNodes, allEdges, showAll),
    [allNodes, allEdges, showAll]
  )
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
    return computeLayout(
      nodes.map((n) => ({ id: n.key })),
      edges.map((e) => ({ src: e.src, dst: e.dst })),
    )
  }, [isMobile, showAll, nodes, edges])

  // 结构签名：只有节点集合或状态变化才重建 React Flow 数据。
  const viewSig = useMemo(
    () => `${showAll ? 'all' : 'overview'}|${isMobile ? 'mobile' : 'desktop'}|${nodes.map((n) => `${n.key}:${n.state ?? ''}`).join(',')}|${edges.length}`,
    [showAll, isMobile, nodes, edges],
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
    const byKind: Record<string, number> = {}
    for (const n of allNodes) byKind[n.kind] = (byKind[n.kind] ?? 0) + 1
    return byKind
  }, [allNodes])

  useEffect(() => {
    if (selected && !nodes.some((n) => n.key === selected.key)) setSelected(null)
  }, [nodes, selected])

  const kindLabel = (k: Kind) => (k === 'project' ? rootLabel : kindMeta[k].label)

  return (
    <div className={cn('relative w-full overflow-hidden rounded-xl', className ?? 'h-auto min-h-[600px] lg:h-[72vh]')}>
      {data === null && loading ? (
        <div className="space-y-3 p-6">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
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
                    全量
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
                概览把子域、服务、入口折叠为计数；全量用于筛选后的细节排查。可拖拽节点、滚轮缩放。
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
              onNodeClick={(_, node) => setSelected(node.data.node)}
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
        <Card className="absolute top-3 right-3 z-10 w-80">
          <CardContent className="p-4">
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
                variant="ghost"
                size="icon"
                className="h-11 w-11 sm:h-7 sm:w-7"
                aria-label="关闭详情"
                onClick={() => setSelected(null)}
              >
                <X className="size-4" />
              </Button>
            </div>

            <div className="mb-2">
              <DetailRow label="状态">
                {reachState(selected) ? (
                  <Badge
                    variant={reachState(selected) === 'reachable' ? 'success' : 'outline'}
                    className="font-normal"
                  >
                    {stateText[reachState(selected) as ReachState]}
                  </Badge>
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
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default AssetGraphCanvas

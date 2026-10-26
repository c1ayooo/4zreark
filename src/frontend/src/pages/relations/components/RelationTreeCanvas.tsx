import { useEffect, useMemo, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  type Edge as RFEdge,
  Handle,
  MiniMap,
  type Node as RFNode,
  type NodeProps,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Button, Input, Skeleton, Tag } from 'antd'
import { ChevronDown, ChevronRight, FileSearch, ListTree, Search } from 'lucide-react'

import { assetApi } from '@/api/assets'
import {
  relationTypeColor,
  relationTypeLabel,
  type RelationEdge,
  type RelationGraphData,
  type RelationNode,
} from '@/api/relations'
import { cn } from '@/lib/utils'
import { RelationDetailDrawer, type RelationSelection } from './RelationDetailDrawer'

// 关系图谱树形视图：根（项目）→ 关系类型 → 分组值 → 成员站点。
//   - 分组值节点直接展示聚类依据（技术栈名 / IP / 证书 / 图标哈希 / C 段 / 父域 / 跳转目标），
//     解决力导向图「揉在一起、看不出按什么聚的类」的问题；
//   - 默认展开到分组值层，站点层收起（节点上显示成员数）；点分组值展开站点，
//     点分组值上的 🔍 打开该分组的证据抽屉；
//   - 布局为简单的竖排紧树（叶子从上往下排，父节点居中），展开/收起重排并自适应视野。

// ---------------------------------------------------------------- 树模型

type TreeKind = 'root' | 'type' | 'key' | 'site'

interface TreeModelNode {
  id: string
  kind: TreeKind
  label: string
  /** 完整值（证书/图标哈希截断时用于 title 提示） */
  full?: string
  sub?: string
  /** same_icon 分组值 / 站点 favicon 的 sha256 */
  icon?: string
  /** 所属关系类型（决定配色） */
  type?: string
  children: TreeModelNode[]
  /** key 节点：该分组全部原始边（证据抽屉用） */
  edges?: RelationEdge[]
  site?: RelationNode
  /** 布局估算尺寸 */
  w: number
  h: number
}

// 常见多段后缀：证书/图标哈希之外的 key（host 类）截断前保留可读前缀
const SHORT_KEY_LEN = 12

function keyLabelOf(type: string, key: string): { label: string; full: string } {
  if (type === 'same_cert' || type === 'same_icon') {
    const label = key.length > SHORT_KEY_LEN ? `${key.slice(0, SHORT_KEY_LEN)}…` : key
    return { label, full: key }
  }
  if (type === 'same_c_segment') return { label: `${key}0/24`, full: `${key}0/24` }
  return { label: key, full: key }
}

interface RelationGroup {
  type: string
  key: string
  edges: RelationEdge[]
  /** 成员站点（两侧去重） */
  sites: Map<number, RelationNode>
}

function buildTree(data: RelationGraphData, typeFilter: string, rootLabel: string): TreeModelNode {
  // 分组：type + key → 边与去重后的成员站点
  const groups = new Map<string, RelationGroup>()
  for (const e of data.edges) {
    const gk = `${e.type}\x00${e.key}`
    let g = groups.get(gk)
    if (!g) {
      g = { type: e.type, key: e.key, edges: [], sites: new Map() }
      groups.set(gk, g)
    }
    g.edges.push(e)
    for (const n of [e.left, e.right]) g.sites.set(n.id, n)
  }

  const keyNodeOf = (g: RelationGroup): TreeModelNode => {
    const { label, full } = keyLabelOf(g.type, g.key)
    const sites = [...g.sites.values()]
    return {
      id: `k:${g.type}:${g.key}`,
      kind: 'key',
      label,
      full,
      type: g.type,
      icon: g.type === 'same_icon' ? g.key : undefined,
      edges: g.edges,
      w: 250,
      h: 40,
      sub: `${sites.length} 站点`,
      children: sites.map((s) => ({
        id: `s:${g.type}:${g.key}:${s.id}`,
        kind: 'site',
        label: s.host,
        full: `${s.title || s.host}${s.ip ? ` · ${s.ip}` : ''}`,
        icon: s.icon_sha256 || undefined,
        type: g.type,
        site: s,
        w: 230,
        h: 30,
        children: [],
      })),
    }
  }

  const root: TreeModelNode = {
    id: 'r',
    kind: 'root',
    label: rootLabel || '全部站点',
    sub: `${data.nodes.length} 站点 · ${data.edges.length} 条边`,
    w: 170,
    h: 56,
    children: [],
  }

  if (typeFilter) {
    // 单一类型 tab：根下直接挂分组值，跳过类型层
    root.children = [...groups.values()]
      .filter((g) => g.type === typeFilter)
      .sort((a, b) => b.sites.size - a.sites.size)
      .map(keyNodeOf)
    return root
  }

  // 全部 tab：类型层按边数倒序
  const byType = new Map<string, { edges: number; groups: RelationGroup[] }>()
  for (const g of groups.values()) {
    let t = byType.get(g.type)
    if (!t) {
      t = { edges: 0, groups: [] }
      byType.set(g.type, t)
    }
    t.edges += g.edges.length
    t.groups.push(g)
  }
  root.children = [...byType.entries()]
    .sort((a, b) => b[1].edges - a[1].edges || a[0].localeCompare(b[0]))
    .map(([type, t]) => ({
      id: `t:${type}`,
      kind: 'type' as const,
      label: relationTypeLabel[type] ?? type,
      type,
      w: 210,
      h: 46,
      sub: `${t.groups.length} 组 · ${t.edges} 边`,
      children: t.groups
        .sort((a, b) => b.sites.size - a.sites.size)
        .map(keyNodeOf),
    }))
  return root
}

// ---------------------------------------------------------------- 布局

// 每层一列（深度 → x），叶子从上往下排、父节点在子节点垂直中点。
const COL_X = [0, 260, 560, 900]
const ROW_GAP = 10

interface LayoutLink {
  source: string
  target: string
  type: string
}

function computeLayout(root: TreeModelNode, expanded: Set<string>) {
  const pos = new Map<string, { x: number; y: number }>()
  const links: LayoutLink[] = []
  let cursor = 0
  const walk = (n: TreeModelNode, depth: number): number => {
    const kids = expanded.has(n.id) ? n.children : []
    let cy: number
    if (kids.length === 0) {
      cy = cursor + n.h / 2
      cursor += n.h + ROW_GAP
    } else {
      const ys = kids.map((k) => walk(k, depth + 1))
      cy = (ys[0] + ys[ys.length - 1]) / 2
      for (const k of kids) links.push({ source: n.id, target: k.id, type: k.type ?? n.type ?? '' })
    }
    const x = COL_X[Math.min(depth, COL_X.length - 1)]
    pos.set(n.id, { x, y: cy - n.h / 2 })
    return cy
  }
  walk(root, 0)
  return { pos, links }
}

function collectNodes(root: TreeModelNode): TreeModelNode[] {
  const out: TreeModelNode[] = []
  const walk = (n: TreeModelNode) => {
    out.push(n)
    for (const k of n.children) walk(k)
  }
  walk(root)
  return out
}

// ---------------------------------------------------------------- 自定义节点

interface TreeNodeData extends Record<string, unknown> {
  node: TreeModelNode
  expanded: boolean
  selected: boolean
  /** key 节点的 🔍 按钮：打开分组证据抽屉 */
  onOpenGroup?: (id: string) => void
}
type TreeRFNode = RFNode<TreeNodeData>

function Handles() {
  return (
    <>
      <Handle type="target" position={Position.Left} className="!size-2 opacity-0" isConnectable={false} />
      <Handle type="source" position={Position.Right} className="!size-2 opacity-0" isConnectable={false} />
    </>
  )
}

function SelectedRing({ selected }: { selected: boolean }) {
  return selected ? (
    <span className="pointer-events-none absolute -inset-0.5 rounded-[inherit] ring-2 ring-primary/50" />
  ) : null
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

function TypeDot({ type }: { type?: string }) {
  return (
    <span
      className="inline-block size-2.5 shrink-0 rounded-full"
      style={{ backgroundColor: relationTypeColor[type ?? ''] ?? '#94a3b8' }}
    />
  )
}

function RootNodeView({ data }: NodeProps<TreeRFNode>) {
  const { node, selected } = data
  return (
    <div className="bg-card relative flex w-[170px] flex-col justify-center rounded-xl border-2 border-border px-3 py-2 shadow-sm">
      <Handles />
      <SelectedRing selected={selected} />
      <div className="flex items-center gap-1.5 text-sm font-semibold">
        <ListTree className="text-primary h-4 w-4 shrink-0" />
        <span className="truncate">{node.label}</span>
      </div>
      <div className="text-muted-foreground text-xs tabular-nums">{node.sub}</div>
    </div>
  )
}

function TypeNodeView({ data }: NodeProps<TreeRFNode>) {
  const { node, expanded, selected } = data
  return (
    <div
      title={`${node.label}（${node.children.length} 个分组，点击${expanded ? '收起' : '展开'}）`}
      className={cn(
        'bg-card relative flex w-[210px] cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-2 transition-colors',
        selected ? 'border-primary' : 'border-border hover:border-primary/50',
      )}
    >
      <Handles />
      <SelectedRing selected={selected} />
      <TypeDot type={node.type} />
      <span className="min-w-0 flex-1 truncate text-sm font-medium">{node.label}</span>
      <span className="text-muted-foreground text-[11px] tabular-nums">{node.sub}</span>
      {expanded ? (
        <ChevronDown className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
      ) : (
        <ChevronRight className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
      )}
    </div>
  )
}

function KeyNodeView({ data }: NodeProps<TreeRFNode>) {
  const { node, expanded, selected, onOpenGroup } = data
  return (
    <div
      title={`${node.full ?? node.label}（点击${expanded ? '收起' : '展开'} ${node.sub ?? ''}，放大镜按钮看证据）`}
      className={cn(
        'bg-card relative flex w-[250px] cursor-pointer items-center gap-2 rounded-full border py-1.5 pl-2.5 pr-2 transition-colors',
        selected ? 'border-primary' : 'border-border hover:border-primary/50',
      )}
    >
      <Handles />
      <SelectedRing selected={selected} />
      {node.icon ? (
        <SiteIcon sha={node.icon} host={node.label} />
      ) : (
        <TypeDot type={node.type} />
      )}
      <span className="min-w-0 flex-1 truncate font-mono text-xs">{node.label}</span>
      <span className="bg-muted text-muted-foreground shrink-0 rounded-full px-1.5 text-[10px] tabular-nums">
        {node.sub}
      </span>
      {node.edges && node.edges.length > 0 && (
        <button
          type="button"
          title="查看该分组的证据记录"
          className="text-muted-foreground hover:text-primary shrink-0 transition-colors"
          onClick={(e) => {
            e.stopPropagation()
            onOpenGroup?.(node.id)
          }}
        >
          <FileSearch className="h-3.5 w-3.5" />
        </button>
      )}
      {expanded ? (
        <ChevronDown className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
      ) : (
        <ChevronRight className="text-muted-foreground h-3.5 w-3.5 shrink-0" />
      )}
    </div>
  )
}

function SiteNodeView({ data }: NodeProps<TreeRFNode>) {
  const { node, selected } = data
  return (
    <div
      title={node.full ?? node.label}
      className={cn(
        'bg-card relative flex w-[230px] cursor-pointer items-center gap-1.5 rounded-full border py-1 pl-2 pr-2.5 transition-colors',
        selected ? 'border-primary' : 'border-border hover:border-muted-foreground/40',
      )}
    >
      <Handles />
      <SelectedRing selected={selected} />
      <SiteIcon sha={node.icon} host={node.label} />
      <span className="max-w-[170px] truncate font-mono text-xs">{node.label}</span>
    </div>
  )
}

const nodeTypes = { root: RootNodeView, type: TypeNodeView, key: KeyNodeView, site: SiteNodeView }

// ---------------------------------------------------------------- 画布

export interface RelationTreeCanvasProps {
  data: RelationGraphData | null
  loading: boolean
  className?: string
  /** 根节点显示名（项目名 / 全部项目） */
  rootLabel?: string
  /** 当前选中的关系类型（空 = 全部，树里含类型层） */
  typeFilter?: string
  /** 项目/类型切换时重置内部状态的 key */
  resetKey?: string
}

const MAX_EXPAND_SITES = 1500

function TreeInner({ data, loading, className, rootLabel, typeFilter }: RelationTreeCanvasProps) {
  const rf = useReactFlow()
  const [selected, setSelected] = useState<RelationSelection | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [query, setQuery] = useState('')

  const tree = useMemo(
    () => (data ? buildTree(data, typeFilter ?? '', rootLabel ?? '') : null),
    [data, typeFilter, rootLabel],
  )

  // 默认展开到分组值层：根 + 类型层；分组值层收起（站点多时不至于一次全铺开）
  const defaultExpanded = useMemo(() => {
    const s = new Set<string>(['r'])
    if (tree) for (const c of tree.children) if (c.kind === 'type') s.add(c.id)
    return s
  }, [tree])
  const [expanded, setExpanded] = useState<Set<string>>(defaultExpanded)
  useEffect(() => setExpanded(defaultExpanded), [defaultExpanded])

  const layout = useMemo(
    () => (tree ? computeLayout(tree, expanded) : { pos: new Map(), links: [] as LayoutLink[] }),
    [tree, expanded],
  )

  // 搜索：命中节点 + 其全部祖先可见（祖先提供上下文），其余隐藏
  const keepSet = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q || !tree) return null
    const keep = new Set<string>()
    const walk = (n: TreeModelNode, ancestors: string[]): boolean => {
      const self =
        n.label.toLowerCase().includes(q) || (n.full ?? '').toLowerCase().includes(q)
      let descendant = false
      for (const k of n.children) descendant = walk(k, [...ancestors, n.id]) || descendant
      if (self || descendant) {
        keep.add(n.id)
        ancestors.forEach((a) => keep.add(a))
        return true
      }
      return false
    }
    walk(tree, [])
    return keep
  }, [query, tree])

  const isHidden = (id: string) => !!keepSet && !keepSet.has(id)

  // key 节点上的放大镜按钮：打开该分组的证据抽屉
  const openGroup = (id: string) => {
    const found = tree && collectNodes(tree).find((n) => n.id === id)
    if (found?.edges?.length) {
      setSelectedId(found.id)
      setSelected({
        kind: 'group',
        group: { type: found.type ?? '', key: found.full ?? found.label, members: found.edges },
      })
    }
  }

  const rfNodes = useMemo(() => {
    if (!tree) return []
    return collectNodes(tree).map((n) => {
      const p = layout.pos.get(n.id)
      return {
        id: n.id,
        type: n.kind,
        position: p ?? { x: 0, y: 0 },
        data: {
          node: n,
          expanded: expanded.has(n.id) && n.children.length > 0,
          selected: selectedId === n.id,
          onOpenGroup: openGroup,
        },
        hidden: isHidden(n.id),
      } satisfies TreeRFNode
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tree, layout, expanded, selectedId, keepSet])

  const rfEdges = useMemo(() => {
    return layout.links.map((l) => {
      const color = relationTypeColor[l.type] ?? '#94a3b8'
      return {
        id: `${l.source}->${l.target}`,
        source: l.source,
        target: l.target,
        type: 'smoothstep',
        hidden: isHidden(l.source) || isHidden(l.target),
        style: { stroke: color, strokeWidth: 1.4, opacity: 0.55 },
      } satisfies RFEdge
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout, keepSet])

  // 结构变化后自适应视野
  useEffect(() => {
    if (!tree) return
    const t = setTimeout(() => rf.fitView({ padding: 0.12, duration: 250 }), 60)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layout])

  // ------------------------------------------------------------ 交互

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const handleNodeClick = (_: unknown, node: TreeRFNode) => {
    const n = node.data.node
    if (n.kind === 'root') return
    if (n.kind === 'site') {
      if (!n.site) return
      const incident = new Map<string, number>()
      for (const e of data?.edges ?? []) {
        if (e.left.id === n.site.id || e.right.id === n.site.id) {
          incident.set(e.type, (incident.get(e.type) ?? 0) + 1)
        }
      }
      setSelectedId(n.id)
      setSelected({
        kind: 'node',
        site: n.site,
        incident: [...incident.entries()].map(([type, count]) => ({ type, count })),
      })
      return
    }
    // 类型 / 分组值节点：展开收起
    setSelectedId(n.id)
    setSelected(null)
    toggle(n.id)
  }

  const totalSites = useMemo(() => {
    if (!tree) return 0
    return collectNodes(tree).filter((n) => n.kind === 'site').length
  }, [tree])

  const expandableIds = useMemo(() => {
    if (!tree) return [] as string[]
    return collectNodes(tree).filter((n) => n.children.length > 0).map((n) => n.id)
  }, [tree])

  const canExpandAll = totalSites > 0 && totalSites <= MAX_EXPAND_SITES
  const expandAll = () => {
    setSelected(null)
    setExpanded(new Set(expandableIds))
  }
  const collapseAll = () => {
    setSelected(null)
    setExpanded(new Set(['r']))
  }

  if (data === null && loading) {
    return (
      <div className={cn('relative w-full overflow-hidden rounded-md border', className ?? 'h-[64vh]')}>
        <div className="p-6">
          <Skeleton active title={false} paragraph={{ rows: 8 }} />
        </div>
      </div>
    )
  }

  return (
    <div className={cn('relative w-full overflow-hidden rounded-md border', className ?? 'h-[64vh]')}>
      {!tree || tree.children.length === 0 ? (
        <div className="text-muted-foreground flex h-full flex-col items-center justify-center gap-2">
          <ListTree className="h-10 w-10 opacity-40" />
          <p>还没有关系边</p>
          <p className="text-xs">导入资产后点右上角「重建图谱」；同 IP/父子域/同技术栈会生成分组树。</p>
        </div>
      ) : (
        <>
          {/* 顶部工具条 */}
          <div className="absolute inset-x-3 top-3 z-10 flex flex-wrap items-center gap-2">
            <Input
              allowClear
              size="small"
              prefix={<Search className="h-3.5 w-3.5 opacity-50" />}
              placeholder="按域名 / 分组值过滤…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-56"
            />
            <Button
              size="small"
              icon={<ChevronRight className="h-3.5 w-3.5" />}
              onClick={collapseAll}
              disabled={expanded.size <= 1}
            >
              收起全部
            </Button>
            <Button
              size="small"
              icon={<ChevronDown className="h-3.5 w-3.5" />}
              disabled={!canExpandAll}
              title={canExpandAll ? '展开全部分组和站点' : `站点过多（${totalSites}），请按分组手动展开`}
              onClick={expandAll}
            >
              展开全部
            </Button>
            {data?.truncated && (
              <Tag color="warning" className="!m-0">
                已截断（上限 5000 条）
              </Tag>
            )}
          </div>

          <ReactFlow
            nodes={rfNodes}
            edges={rfEdges}
            onNodeClick={handleNodeClick}
            onPaneClick={() => {
              setSelectedId(null)
              setSelected(null)
            }}
            nodeTypes={nodeTypes}
            nodesDraggable={false}
            nodesConnectable={false}
            onlyRenderVisibleElements
            minZoom={0.02}
            proOptions={{ hideAttribution: true }}
            fitView
            fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
          >
            <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} />
            <MiniMap pannable zoomable className="!bottom-3" />
            <Controls showInteractive={false} />
          </ReactFlow>

          <RelationDetailDrawer selection={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  )
}

export function RelationTreeCanvas(props: RelationTreeCanvasProps) {
  // 项目/类型切换时用 key 重置内部状态（展开、搜索、选中）
  return (
    <ReactFlowProvider>
      <TreeInner key={props.resetKey ?? 'r'} {...props} />
    </ReactFlowProvider>
  )
}

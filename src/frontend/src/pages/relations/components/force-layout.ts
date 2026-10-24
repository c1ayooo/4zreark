import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force'

// 关系图谱的力导布局：纯函数，无 React 依赖（对照 lib/graph-layout.ts 的先例）。
// 同步跑固定 tick 数，调用方拿到 Map<id, {x,y}> 后自己管理位置生命周期：
//   - 已有位置的节点以 fx/fy 固定（拖拽/展开保留，不被重排打回）；
//   - 新节点从传入的初始位置出发自由收敛，实现「展开簇只补位、整图不跳动」。

export interface ForceLayoutNode {
  id: string
  /** 初始/已有位置；fixed=true 时固定为 fx/fy 不参与模拟 */
  x?: number
  y?: number
  fixed?: boolean
  /** 碰撞半径，缺省 18 */
  radius?: number
}

export interface ForceLayoutLink {
  source: string
  target: string
  type?: string
  confidence?: number
}

// 类型 → 期望边长：语义越强（父子域/同 IP）拉得越近，弱相关（同技术栈/C 段）推得越远，
// 让「真·同一台机器」的团簇在视觉上先聚起来。
const LINK_DISTANCE: Record<string, number> = {
  domain_parent: 80,
  same_ip: 60,
  redirect: 70,
  same_icon: 90,
  same_cert: 100,
  cname: 100,
  same_fp: 130,
  same_c_segment: 160,
}

const DEFAULT_TICKS = 300

export function computeForceLayout(
  nodes: ForceLayoutNode[],
  links: ForceLayoutLink[],
  ticks = DEFAULT_TICKS,
): Map<string, { x: number; y: number }> {
  const ids = new Set(nodes.map((n) => n.id))
  // 端点不在节点集里的边直接丢弃，否则 d3 会给悬空端点造影子节点。
  const validLinks = links.filter((l) => ids.has(l.source) && ids.has(l.target))

  type SimNode = ForceLayoutNode & SimulationNodeDatum
  const simNodes: SimNode[] = nodes.map((n) => ({
    ...n,
    x: n.x ?? (Math.random() - 0.5) * 400,
    y: n.y ?? (Math.random() - 0.5) * 400,
    // 固定节点用 fx/fy；自由节点把 x/y 当初始位置（d3 不需要额外处理）。
    ...(n.fixed ? { fx: n.x ?? 0, fy: n.y ?? 0 } : {}),
  }))
  type SimLink = SimulationLinkDatum<SimNode> & ForceLayoutLink
  const simLinks: SimLink[] = validLinks.map((l) => ({ ...l }))

  const simulation = forceSimulation<SimNode>(simNodes)
    .force(
      'link',
      forceLink<SimNode, SimLink>(simLinks)
        .id((d) => d.id)
        .distance((l) => LINK_DISTANCE[l.type ?? ''] ?? 110)
        .strength((l) => 0.08 + 0.45 * (l.confidence ?? 0.5)),
    )
    .force('charge', forceManyBody<SimNode>().strength(-380))
    .force(
      'collide',
      forceCollide<SimNode>()
        .radius((d) => d.radius ?? 18)
        .iterations(2),
    )
    .force('x', forceX<SimNode>(0).strength(0.04))
    .force('y', forceY<SimNode>(0).strength(0.04))
    .stop()

  for (let i = 0; i < ticks; i++) simulation.tick()

  const out = new Map<string, { x: number; y: number }>()
  for (const n of simNodes) out.set(n.id, { x: n.x ?? 0, y: n.y ?? 0 })
  return out
}

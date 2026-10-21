// 分层图布局：DFS 破环 → 最长路径分层 → 4 轮 barycenter 排序。
// 资产星图用它把「项目 → 域名 → 子域 → 服务 → 入口」排成左→右。
//
// 泛型只约束布局需要的字段，调用方传任意 {id} / {src,dst} 结构即可。

export const COL_W = 360
export const ROW_H = 140

export type LayoutNode = { id: string }
export type LayoutEdge = { src: string; dst: string }
export type Position = { x: number; y: number }

function pushMap(m: Map<string, string[]>, k: string, v: string) {
  const a = m.get(k)
  if (a) a.push(v)
  else m.set(k, [v])
}

export function computeLayout<N extends LayoutNode, E extends LayoutEdge>(
  nodes: N[],
  edges: E[],
): Map<string, Position> {
  const order = nodes.map((n) => n.id)
  const idset = new Set(order)
  const valid = edges.filter((e) => idset.has(e.src) && idset.has(e.dst))
  const key = (s: string, d: string) => `${s}->${d}`

  const out = new Map<string, string[]>()
  for (const e of valid) pushMap(out, e.src, e.dst)

  // 环检测：DFS 中遇到仍在栈上的后继即标为回边，分层时剔除。
  const seen = new Map<string, 0 | 1 | 2>()
  const back = new Set<string>()
  for (const root of order) {
    if ((seen.get(root) ?? 0) !== 0) continue
    const stack: Array<{ u: string; i: number }> = [{ u: root, i: 0 }]
    seen.set(root, 1)
    while (stack.length) {
      const top = stack[stack.length - 1]
      const nbrs = out.get(top.u) ?? []
      if (top.i >= nbrs.length) {
        seen.set(top.u, 2)
        stack.pop()
        continue
      }
      const v = nbrs[top.i++]
      const s = seen.get(v) ?? 0
      if (s === 1) back.add(key(top.u, v))
      else if (s === 0) {
        seen.set(v, 1)
        stack.push({ u: v, i: 0 })
      }
    }
  }

  // 最长路径分层：拓扑序遍历，层号取所有前驱最大值 + 1。
  const dagSucc = new Map<string, string[]>()
  const indeg = new Map<string, number>(order.map((id) => [id, 0]))
  for (const e of valid) {
    if (back.has(key(e.src, e.dst))) continue
    pushMap(dagSucc, e.src, e.dst)
    indeg.set(e.dst, (indeg.get(e.dst) ?? 0) + 1)
  }
  const layer = new Map<string, number>(order.map((id) => [id, 0]))
  const queue = order.filter((id) => (indeg.get(id) ?? 0) === 0)
  for (let qi = 0; qi < queue.length; qi++) {
    const u = queue[qi]
    for (const v of dagSucc.get(u) ?? []) {
      layer.set(v, Math.max(layer.get(v) ?? 0, (layer.get(u) ?? 0) + 1))
      const d = (indeg.get(v) ?? 0) - 1
      indeg.set(v, d)
      if (d === 0) queue.push(v)
    }
  }

  const maxLayer = Math.max(0, ...layer.values())
  const columns: string[][] = Array.from({ length: maxLayer + 1 }, () => [])
  for (const id of order) columns[layer.get(id) ?? 0].push(id)

  const colIndexOf = new Map<string, number>()
  columns.forEach((ids, c) => {
    ids.forEach((id) => {
      colIndexOf.set(id, c)
    })
  })
  const neighbors = new Map<string, string[]>()
  for (const e of valid) {
    const cs = colIndexOf.get(e.src)
    const cd = colIndexOf.get(e.dst)
    if (cs === undefined || cd === undefined || Math.abs(cs - cd) !== 1) continue
    pushMap(neighbors, e.src, e.dst)
    pushMap(neighbors, e.dst, e.src)
  }

  // barycenter：按相邻层已排序节点的平均位置重排本层，四轮往返收敛上下交叉。
  const sweep = (dir: 1 | -1) => {
    const start = dir === 1 ? 1 : columns.length - 2
    const end = dir === 1 ? columns.length : -1
    for (let c = start; c !== end; c += dir) {
      const ref = c - dir
      const refIndex = new Map(columns[ref].map((id, i) => [id, i]))
      const scored = columns[c].map((id, i) => {
        const ns = (neighbors.get(id) ?? [])
          .map((nid) => refIndex.get(nid))
          .filter((v): v is number => v !== undefined)
        const bary = ns.length ? ns.reduce((a, b) => a + b, 0) / ns.length : i
        return { id, bary, i }
      })
      scored.sort((a, b) => a.bary - b.bary || a.i - b.i)
      columns[c] = scored.map((s) => s.id)
    }
  }
  for (let iter = 0; iter < 4; iter++) {
    sweep(1)
    sweep(-1)
  }

  const maxCount = Math.max(1, ...columns.map((c) => c.length))
  const midline = ((maxCount - 1) * ROW_H) / 2
  const pos = new Map<string, Position>()
  columns.forEach((ids, c) => {
    const startY = midline - ((ids.length - 1) * ROW_H) / 2
    ids.forEach((id, i) => {
      pos.set(id, { x: c * COL_W, y: startY + i * ROW_H })
    })
  })
  return pos
}

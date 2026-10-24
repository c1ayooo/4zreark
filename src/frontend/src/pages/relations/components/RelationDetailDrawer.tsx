import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Drawer, Tag } from 'antd'
import { ExternalLink } from 'lucide-react'
import dayjs from 'dayjs'

import {
  relationApi,
  relationTypeColor,
  relationTypeLabel,
  type RelationEdge,
  type RelationEvidenceItem,
  type RelationNode,
} from '@/api/relations'
import { getErrorMessage } from '@/lib/errors'
import { cn } from '@/lib/utils'

// 关系图谱的详情抽屉：节点 = 站点摘要 + 连边分布；边 = 边信息 + 两侧证据行。
// 证据在点开边时才拉取（GET /relations/evidence）。

export interface RelationSelection {
  kind: 'node' | 'edge'
  site?: RelationNode
  /** 节点模式下：各类型连边计数（画布侧算好传入） */
  incident?: { type: string; count: number }[]
  edge?: RelationEdge
  /** 簇间聚合边携带全部成员，抽屉里可切换看哪条的证据 */
  members?: RelationEdge[]
}

function SideBadge({ side }: { side: string }) {
  return side === 'left' ? (
    <Tag className="shrink-0">站点 A</Tag>
  ) : (
    <Tag className="shrink-0">站点 B</Tag>
  )
}

function EvidenceRow({ ev }: { ev: RelationEvidenceItem }) {
  return (
    <li className="text-xs leading-relaxed">
      <span className="text-muted-foreground">记录 #{ev.record_id}</span>
      <span className="mx-1">·</span>
      <span className="font-mono">{ev.source || '—'}</span>
      <span className="mx-1">·</span>
      <span className="break-all font-mono">{ev.value || ev.note || '—'}</span>
      {ev.observed_at && (
        <span className="text-muted-foreground ml-1">({dayjs(ev.observed_at).format('MM-DD HH:mm')})</span>
      )}
    </li>
  )
}

function EdgeEvidenceList({ edgeId }: { edgeId: number }) {
  const q = useQuery({
    queryKey: ['relation-evidence', edgeId],
    queryFn: () => relationApi.edgeEvidence(edgeId),
    staleTime: 60_000,
  })

  if (q.isLoading) return <p className="text-muted-foreground py-2 text-sm">证据加载中…</p>
  if (q.isError)
    return (
      <p className="text-destructive py-2 text-sm">证据读取失败：{getErrorMessage(q.error)}</p>
    )
  const rows = q.data?.data?.evidence ?? []
  if (rows.length === 0)
    return <p className="text-muted-foreground py-2 text-sm">这条边没有可展示的证据记录</p>

  const groups: { side: 'left' | 'right'; label: string; host: string; rows: RelationEvidenceItem[] }[] = []
  for (const side of ['left', 'right'] as const) {
    const part = rows.filter((r) => r.side === side)
    if (part.length === 0) continue
    groups.push({ side, label: side === 'left' ? '站点 A 的记录' : '站点 B 的记录', host: part[0].host, rows: part })
  }
  return (
    <div className="space-y-3">
      {groups.map((g) => (
        <div key={g.side}>
          <div className="mb-1 flex items-center gap-2">
            <SideBadge side={g.side} />
            <span className="font-mono text-xs">{g.host}</span>
            <span className="text-muted-foreground text-xs tabular-nums">{g.rows.length} 条</span>
          </div>
          <ul className="space-y-1">
            {g.rows.map((ev) => (
              <EvidenceRow key={ev.record_id} ev={ev} />
            ))}
          </ul>
        </div>
      ))}
    </div>
  )
}

function SiteMiniCard({ site, side }: { site: RelationNode; side?: 'left' | 'right' }) {
  return (
    <div className="rounded-md border p-2.5">
      <div className="flex items-center gap-2">
        {side && <SideBadge side={side} />}
        <Link
          to={`/assets/${site.id}`}
          className="text-primary min-w-0 truncate font-mono text-sm hover:underline"
        >
          {site.host}
        </Link>
      </div>
      <div className="text-muted-foreground mt-1 truncate text-xs">
        {site.title || '—'} · {site.ip || '—'}
      </div>
    </div>
  )
}

export function RelationDetailDrawer({
  selection,
  onClose,
}: {
  selection: RelationSelection | null
  onClose: () => void
}) {
  const isEdge = selection?.kind === 'edge'
  // 聚合边的成员切换是抽屉内部状态；换一条边时重置。
  const [activeId, setActiveId] = useState<number | null>(null)
  useEffect(() => setActiveId(null), [selection?.edge?.id])
  const edge =
    isEdge && selection?.edge
      ? selection.members?.find((m) => m.id === activeId) ?? selection.edge
      : undefined
  const site = selection?.site
  const title =
    selection?.kind === 'edge' && edge
      ? `${relationTypeLabel[edge.type] ?? edge.type} · ${edge.left.host} ↔ ${edge.right.host}`
      : selection?.kind === 'node' && site
        ? site.host
        : '详情'

  return (
    <Drawer open={!!selection} onClose={onClose} width={440} title={<span className="font-mono text-sm">{title}</span>}>
      {selection?.kind === 'node' && site && (
        <div className="space-y-4">
          <div className="space-y-1 text-sm">
            <div className="flex items-start gap-3">
              <span className="text-muted-foreground w-14 shrink-0">标题</span>
              <span className="min-w-0 flex-1 break-words">{site.title || '—'}</span>
            </div>
            <div className="flex items-start gap-3">
              <span className="text-muted-foreground w-14 shrink-0">IP</span>
              <span className="min-w-0 flex-1 font-mono break-words">{site.ip || '—'}</span>
            </div>
          </div>
          {selection.incident && selection.incident.length > 0 && (
            <div>
              <p className="text-muted-foreground mb-1.5 text-xs">连边分布</p>
              <div className="flex flex-wrap gap-1.5">
                {selection.incident.map((it) => (
                  <Tag key={it.type}>
                    <span
                      className="mr-1.5 inline-block size-2 rounded-full align-middle"
                      style={{ backgroundColor: relationTypeColor[it.type] ?? '#94a3b8' }}
                    />
                    {relationTypeLabel[it.type] ?? it.type}
                    <span className="ml-1 tabular-nums">{it.count}</span>
                  </Tag>
                ))}
              </div>
            </div>
          )}
          <Link
            to={`/assets/${site.id}`}
            className="text-primary inline-flex items-center gap-1 text-sm hover:underline"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            打开资产详情
          </Link>
        </div>
      )}

      {isEdge && edge && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Tag>
              <span
                className="mr-1.5 inline-block size-2 rounded-full align-middle"
                style={{ backgroundColor: relationTypeColor[edge.type] ?? '#94a3b8' }}
              />
              {relationTypeLabel[edge.type] ?? edge.type}
            </Tag>
            <span className="text-muted-foreground font-mono text-xs">{edge.key || '—'}</span>
            <span className="text-muted-foreground text-xs">置信度 {(edge.confidence * 100).toFixed(0)}%</span>
          </div>
          {selection.members && selection.members.length > 1 && (
            <div>
              <p className="text-muted-foreground mb-1.5 text-xs">
                这条连线聚合了 {selection.members.length} 条同类关系，点选看具体某条的证据：
              </p>
              <EdgeMembers
                members={selection.members}
                activeId={edge.id}
                onPick={(m) => setActiveId(m.id)}
              />
            </div>
          )}
          <div className="grid gap-2">
            <SiteMiniCard site={edge.left} side="left" />
            <SiteMiniCard site={edge.right} side="right" />
          </div>
          <div>
            <p className="text-muted-foreground mb-1.5 text-xs">证据（两侧原始记录）</p>
            <EdgeEvidenceList edgeId={edge.id} />
          </div>
        </div>
      )}
    </Drawer>
  )
}

function EdgeMembers({
  members,
  activeId,
  onPick,
}: {
  members: RelationEdge[]
  activeId: number
  onPick: (e: RelationEdge) => void
}) {
  return (
    <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
      {members.map((m) => (
        <button
          key={m.id}
          type="button"
          onClick={() => onPick(m)}
          className={cn(
            'rounded-full border px-2 py-0.5 font-mono text-xs transition-colors',
            m.id === activeId
              ? 'border-primary bg-primary/10 text-primary'
              : 'text-muted-foreground hover:bg-muted',
          )}
        >
          {m.left.host} ↔ {m.right.host}
        </button>
      ))}
    </div>
  )
}

import { useState } from 'react'
import { Button, Dropdown, Tag, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import {
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  Globe,
  Lock,
  Unlock,
  MoreHorizontal,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Star,
  Trash2,
} from 'lucide-react'
import {
  assetApi,
  type AssetKind,
  type DomainRow,
  type EndpointRow,
  type IPRow,
  type RawRecordRow,
  type Site,
} from '@/api/assets'
import { statusTagClass } from '@/components/ui/StatusTag'
import { stateLabel } from './AssetDetailDrawer'

// 列表行的联合类型：四种粒度共用一张 antd Table，列定义按粒度分支构建。
export type AssetRow = Site | DomainRow | IPRow | EndpointRow | RawRecordRow

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass

const stateVariant = (state: string): BadgeVariant => {
  if (state === 'reachable') return 'default'
  if (state === 'lost') return 'destructive'
  if (state === 'archived') return 'outline'
  return 'secondary'
}

export const priorityLabel = (p: string) => (p ? p.toUpperCase() : '—')

// 生效中的删除保护期：未设置或已过期视为无保护（与后端口径一致，见 service/asset_service.go）。
export const activeProtection = (s: Site): string | null => {
  if (!s.protected_until) return null
  const until = new Date(s.protected_until).getTime()
  return Number.isFinite(until) && until > Date.now() ? s.protected_until : null
}

const priorityVariant = (p: string): BadgeVariant => {
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
// compact 用于「资产」单元格内联（size-3.5），默认独立列尺寸（size-6）。
function SiteIcon({ sha256, alt, compact }: { sha256: string; alt: string; compact?: boolean }) {
  const [failed, setFailed] = useState(false)
  if (!sha256 || failed) {
    return <Globe className={`text-muted-foreground shrink-0 ${compact ? 'size-3.5' : 'size-4'}`} />
  }
  return (
    <img
      src={assetApi.iconURL(sha256)}
      alt={alt}
      loading="lazy"
      className={`shrink-0 rounded-sm object-contain ${compact ? 'size-3.5' : 'size-6'}`}
      onError={() => setFailed(true)}
    />
  )
}

// v2 紧凑化：图标/状态码/项目并入「资产」单元格，不再作为独立列可配。
export type SiteColumn = 'star' | 'risk' | 'title' | 'records' | 'first_seen' | 'actions'

export const SITE_COLUMNS: { key: SiteColumn; label: string }[] = [
  { key: 'star', label: '星标' },
  { key: 'risk', label: '风险' },
  { key: 'title', label: '标题' },
  { key: 'records', label: '记录 / 最近记录' },
  { key: 'first_seen', label: '发现时间' },
  { key: 'actions', label: '操作' },
]

export const DEFAULT_SITE_COLUMNS: Record<SiteColumn, boolean> = {
  star: true, risk: true, title: true,
  records: true, first_seen: false, actions: true,
}

export const SITE_COLUMNS_KEY = 'zre.asset.siteColumns.v2'

export function loadSiteColumns(): Record<SiteColumn, boolean> {
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

const stateTag = (state: string) => (
  <Tag className={badgeCls(stateVariant(state))}>{stateLabel[state] ?? state}</Tag>
)
const statusTag = (code: number) => (
  <Tag className={badgeCls(code >= 200 && code < 400 ? 'default' : 'secondary')}>{code || '—'}</Tag>
)

const riskCell = (priority: string | undefined, score: number | undefined) =>
  score ? (
    <Tag className={`${badgeCls('outline')} tabular-nums`}>
      {priority?.toUpperCase() || `P? · ${score}`} · {score}
    </Tag>
  ) : (
    '—'
  )

export interface AssetTableParts {
  columns: TableProps<AssetRow>['columns']
  rowKey: (row: AssetRow) => string
  onRow: TableProps<AssetRow>['onRow']
}

// —— 列定义：四种行形态各自的列集与行键/行事件，页面每次渲染时按当前粒度构建 ——
export function buildAssetTableParts({
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
  unprotect,
  onDelete,
  star,
  ignore,
  setDetailSite,
  navigate,
}: {
  kind: AssetKind
  expanded: boolean
  riskSort: boolean
  siteCols: Record<SiteColumn, boolean>
  expandedSiteIDs: Set<number>
  busy: boolean
  toggleSiteExpand: (id: number) => void
  probe: { mutate: (site: Site) => void }
  verify: { mutate: (v: { site: Site; reachable: boolean }) => void }
  protect: { mutate: (site: Site) => void }
  unprotect: { mutate: (site: Site) => void }
  onDelete: (site: Site) => void
  star: { mutate: (v: { site: Site; starred: boolean }) => void }
  ignore: { mutate: (v: { site: Site; ignored: boolean }) => void }
  setDetailSite: (site: Site) => void
  navigate: (path: string) => void
}): AssetTableParts {
  const columns: TableProps<AssetRow>['columns'] = []
  let rowKey: (row: AssetRow) => string
  let onRow: TableProps<AssetRow>['onRow']

  if (kind === 'site' && !expanded) {
    // 站点归并：资产 + 可配置列（图标/风险/状态码/标题/记录/项目/发现时间/操作）+ 连通
    const siteColumns: TableProps<Site>['columns'] = [
      {
        title: '资产',
        render: (_, s) => {
          // 单行紧凑：favicon/状态码/项目并入本格，不再占独立列（v2 紧凑化）；
          // 完整入口/技术栈/标签点行看抽屉，表内只留前几项 + 溢出计数
          const eps = s.endpoints ?? []
          const techs = s.technology_stack
          const techExtra = techs.length > 2 ? techs.length - 2 : 0
          const tagExtra = (s.tags?.length ?? 0) > 2 ? s.tags!.length - 2 : 0
          return (
            <div className="flex min-w-0 items-center gap-2">
              <SiteIcon sha256={s.icon_sha256} alt={s.host} compact />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium" title={s.host}>{s.host || s.value}</div>
                <div className="text-muted-foreground mt-0.5 flex items-center gap-1 overflow-hidden whitespace-nowrap text-[13px]">
                  {statusTag(s.http_status)}
                  {/* 端口/协议属于「入口」下一层级，站点行只给入口数，明细 hover 或点抽屉查看 */}
                  <span
                    className="rounded-sm bg-muted px-1.5 py-0.5"
                    title={eps.length > 0
                      ? eps.map((e) => `${e.scheme}:${e.port}`).join('、')
                      : `${s.protocol}:${s.port}`}
                  >
                    入口 {eps.length > 0 ? eps.length : 1}
                  </span>
                  <span className="truncate">{s.ip || '—'}</span>
                  {techs.length > 0 && (
                    <span className="truncate">
                      · {techs.slice(0, 2).join(', ')}
                      {techExtra > 0 && ` +${techExtra}`}
                    </span>
                  )}
                  {tagExtra > 0 && <span className="text-[11px]">· 标签 +{tagExtra}</span>}
                  {s.project_name && <span className="truncate">· {s.project_name}</span>}
                </div>
              </div>
            </div>
          )
        },
      },
    ]
    if (siteCols.star) {
      siteColumns.push({
        title: '星标',
        width: 46,
        render: (_, s) => (
          <button
            type="button"
            aria-label={s.starred ? '取消星标' : '加星标'}
            title={s.starred ? '取消星标' : '加星标'}
            className="rounded p-1 hover:bg-muted"
            onClick={(e) => {
              e.stopPropagation()
              star.mutate({ site: s, starred: !s.starred })
            }}
          >
            <Star
              className={`h-4 w-4 ${s.starred ? 'fill-amber-400 text-amber-400' : 'text-muted-foreground'}`}
            />
          </button>
        ),
      })
    }
    if (siteCols.risk) {
      siteColumns.push({
        title: '风险',
        width: 90,
        align: 'right',
        responsive: ['lg'],
        render: (_, s) => (
          <Tag className={badgeCls(priorityVariant(s.priority))} title={riskTitle(s)}>
            {priorityLabel(s.priority)} · {s.risk_score}
          </Tag>
        ),
      })
    }
    if (siteCols.title) {
      siteColumns.push({
        title: '标题',
        responsive: ['md'],
        render: (_, s) => <span className="block max-w-[200px] truncate text-sm">{s.title || '—'}</span>,
      })
    }
    if (siteCols.records) {
      siteColumns.push({
        title: '记录',
        width: 82,
        align: 'right',
        responsive: ['lg'],
        onCell: (s) => ({ title: `入口 ${s.endpoint_count} · 原始记录 ${s.record_count} · 指纹 ${s.fingerprint_count}` }),
        render: (_, s) => {
          const isOpen = expandedSiteIDs.has(s.id)
          return (
            <div className="flex items-center justify-end gap-1">
              <button
                type="button"
                aria-label={isOpen ? '收起最近记录' : '展开最近记录'}
                className="rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground"
                onClick={(e) => {
                  e.stopPropagation()
                  toggleSiteExpand(s.id)
                }}
              >
                {isOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
              </button>
              <span>{s.record_count}</span>
            </div>
          )
        },
      })
    }
    if (siteCols.first_seen) {
      siteColumns.push({
        title: '发现时间',
        width: 110,
        align: 'right',
        responsive: ['xl'],
        render: (_, s) => (
          <span className="text-[13px] tabular-nums text-muted-foreground">{s.first_seen?.slice(0, 10)}</span>
        ),
      })
    }
    siteColumns.push({
      title: '连通',
      width: 110,
      render: (_, s) => (
        <>
          {stateTag(s.state)}
          {s.consecutive_failures > 0 && (
            <span className="ml-1 text-[13px] text-destructive">×{s.consecutive_failures}</span>
          )}
        </>
      ),
    })
    if (siteCols.actions) {
      siteColumns.push({
        title: '操作',
        width: 104,
        responsive: ['sm'],
        render: (_, s) => {
          const isOpen = expandedSiteIDs.has(s.id)
          return (
            <div className="flex items-center gap-0.5" onClick={(e) => e.stopPropagation()}>
              <Tooltip title="详情">
                <Button
                  size="small"
                  type="text"
                  aria-label="详情"
                  onClick={() => navigate(`/assets/${s.id}`)}
                  disabled={busy}
                  icon={<Eye className="h-3.5 w-3.5" />}
                />
              </Tooltip>
              <Tooltip title="探测">
                <Button
                  size="small"
                  type="text"
                  aria-label="探测"
                  onClick={() => probe.mutate(s)}
                  disabled={busy}
                  icon={<Radar className="h-3.5 w-3.5" />}
                />
              </Tooltip>
              <Dropdown
                trigger={['click']}
                menu={{
                  items: [
                    {
                      key: 'expand',
                      label: isOpen ? '收起最近记录' : '展开最近记录',
                      icon: isOpen ? (
                        <ChevronUp className="h-3.5 w-3.5" style={{ fontSize: 0 }} />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" style={{ fontSize: 0 }} />
                      ),
                      onClick: () => toggleSiteExpand(s.id),
                    },
                    {
                      key: 'star',
                      label: s.starred ? '取消星标' : '加星标',
                      icon: (
                        <Star
                          className={`h-3.5 w-3.5 ${s.starred ? 'fill-amber-400 text-amber-400' : ''}`}
                          style={{ fontSize: 0 }}
                        />
                      ),
                      onClick: () => star.mutate({ site: s, starred: !s.starred }),
                    },
                    {
                      key: 'mark-ok',
                      label: '人工标记可达',
                      icon: <ShieldCheck className="h-3.5 w-3.5" style={{ fontSize: 0 }} />,
                      onClick: () => verify.mutate({ site: s, reachable: true }),
                    },
                    {
                      key: 'mark-fail',
                      label: '人工标记失败',
                      icon: <ShieldAlert className="h-3.5 w-3.5" style={{ fontSize: 0 }} />,
                      onClick: () => verify.mutate({ site: s, reachable: false }),
                    },
                    // 保护期双向 toggle：受保护时改发 unprotect，标签带到期日期
                    {
                      key: 'protect',
                      label: activeProtection(s)
                        ? `解除保护（至 ${s.protected_until!.slice(0, 10)}）`
                        : '保护 90 天',
                      icon: activeProtection(s) ? (
                        <Unlock className="h-3.5 w-3.5" style={{ fontSize: 0 }} />
                      ) : (
                        <Lock className="h-3.5 w-3.5" style={{ fontSize: 0 }} />
                      ),
                      onClick: () =>
                        activeProtection(s) ? unprotect.mutate(s) : protect.mutate(s),
                    },
                    {
                      key: 'ignore',
                      label: s.ignored ? '取消忽略' : '忽略（默认视图隐藏）',
                      icon: <EyeOff className="h-3.5 w-3.5" style={{ fontSize: 0 }} />,
                      onClick: () => ignore.mutate({ site: s, ignored: !s.ignored }),
                    },
                    {
                      type: 'divider' as const,
                    },
                    {
                      key: 'delete',
                      label: '删除',
                      danger: true,
                      icon: <Trash2 className="h-3.5 w-3.5" style={{ fontSize: 0 }} />,
                      onClick: () => onDelete(s),
                    },
                  ],
                }}
              >
                <Tooltip title="更多">
                  <Button size="small" type="text" disabled={busy} aria-label="更多操作" icon={<MoreHorizontal className="h-4 w-4" />} />
                </Tooltip>
              </Dropdown>
            </div>
          )
        },
      })
    }
    columns.push(...(siteColumns as unknown as NonNullable<TableProps<AssetRow>['columns']>))
    // 行键用域名：value 是会被后续证据覆盖的完整 URL，不能当站点身份。
    rowKey = (s) => (s as Site).host
    onRow = (s) => ({
      className: 'cursor-pointer',
      onClick: (e) => {
        // 勾选列的点击不触发
        if ((e.target as HTMLElement).closest('.ant-table-selection-column')) return
        // 详情双轨统一：点行 = 抽屉快速预览；整页档案走操作列的「详情」按钮
        setDetailSite(s as Site)
      },
    })
  } else if (expanded) {
    // 站点展开（入口粒度）
    columns.push(
      {
        title: '入口',
        render: (_, row) => {
          const e = row as EndpointRow
          return (
            <>
              <div className="text-sm font-medium">
                {e.host}:{e.port}
              </div>
              <div className="text-[13px] text-muted-foreground">
                站点 #{e.site_id} · 采集 {e.record_count} 次
              </div>
            </>
          )
        },
      },
      {
        title: '协议',
        width: 90,
        render: (_, row) => <Tag className={badgeCls('outline')}>{(row as EndpointRow).protocol || '—'}</Tag>,
      },
      {
        title: '标题',
        responsive: ['md'],
        render: (_, row) => (
          <span className="block max-w-[260px] truncate text-sm">{(row as EndpointRow).title || '—'}</span>
        ),
      },
      {
        title: '记录数',
        width: 90,
        align: 'right',
        render: (_, row) => <span className="text-sm tabular-nums">{(row as EndpointRow).record_count}</span>,
      },
      {
        title: '连通',
        width: 110,
        render: (_, row) => stateTag((row as EndpointRow).state),
      },
      {
        title: '最近发现',
        width: 110,
        align: 'right',
        render: (_, row) => (
          <span className="text-[13px] tabular-nums text-muted-foreground">
            {(row as EndpointRow).last_seen?.slice(0, 10)}
          </span>
        ),
      },
      {
        title: '项目',
        width: 120,
        responsive: ['lg'],
        render: (_, row) => <span className="text-sm">{(row as EndpointRow).project_name}</span>,
      },
    )
    rowKey = (row) => {
      const e = row as EndpointRow
      return `${e.host}-${e.port}-${e.protocol}`
    }
    onRow = (row) => ({
      className: 'cursor-pointer',
      onClick: () => navigate(`/assets/${(row as EndpointRow).site_id}`),
    })
  } else if (kind === 'record') {
    columns.push(
      {
        title: '原始记录',
        render: (_, row) => {
          const r = row as RawRecordRow
          return (
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <div className="truncate text-sm font-medium">
                  {r.value || `${r.protocol}://${r.host}:${r.port}`}
                </div>
                {r.is_interface && (
                  <Tag className={`${badgeCls('outline')} shrink-0 text-[11px]`}>接口</Tag>
                )}
                {r.is_crawler && (
                  <Tag className={`${badgeCls('outline')} shrink-0 text-[11px]`}>爬虫</Tag>
                )}
              </div>
              <div className="text-muted-foreground truncate text-xs">
                {r.host}:{r.port} · {r.protocol}
              </div>
            </div>
          )
        },
      },
      {
        title: '来源 / 方法',
        width: 110,
        render: (_, row) => {
          const r = row as RawRecordRow
          return (
            <div className="text-[13px] text-muted-foreground">
              <div>{r.collector || r.source || '—'}</div>
              <div className="text-[11px]">{r.method || 'GET'}</div>
            </div>
          )
        },
      },
      {
        title: '状态码',
        width: 90,
        align: 'right',
        render: (_, row) => statusTag((row as RawRecordRow).status_code),
      },
      {
        title: '标题',
        render: (_, row) => (
          <span className="block max-w-[280px] truncate text-sm">{(row as RawRecordRow).title || '—'}</span>
        ),
      },
      {
        title: 'IP / 服务',
        width: 150,
        render: (_, row) => {
          const r = row as RawRecordRow
          return (
            <div className="text-[13px]">
              <div>{r.ip || '—'}</div>
              {r.server && <div className="text-muted-foreground">{r.server}</div>}
            </div>
          )
        },
      },
      {
        title: '观察时间',
        width: 170,
        align: 'right',
        render: (_, row) => (
          <span className="text-[13px] tabular-nums text-muted-foreground">
            {(row as RawRecordRow).observed_at?.replace('T', ' ').slice(0, 19)}
          </span>
        ),
      },
      {
        title: '项目',
        width: 120,
        render: (_, row) => <span className="text-[13px]">{(row as RawRecordRow).project_name || '—'}</span>,
      },
    )
    rowKey = (row) => String((row as RawRecordRow).id)
    onRow = (row) => {
      const r = row as RawRecordRow
      return {
        className: r.site_id > 0 ? 'cursor-pointer' : undefined,
        onClick: () => r.site_id > 0 && navigate(`/assets/${r.site_id}`),
      }
    }
  } else if (kind === 'domain') {
    if (riskSort) {
      columns.push({
        title: '风险',
        width: 90,
        align: 'right',
        render: (_, row) => {
          const d = row as DomainRow
          return riskCell(d.priority, d.risk_score)
        },
      })
    }
    columns.push(
      {
        title: '域名',
        render: (_, row) => <span className="text-sm font-medium">{(row as DomainRow).host}</span>,
      },
      {
        title: '站点数',
        width: 100,
        align: 'right',
        render: (_, row) => <span className="text-sm tabular-nums">{(row as DomainRow).site_count}</span>,
      },
      {
        title: '可达',
        width: 100,
        align: 'right',
        render: (_, row) => <span className="text-sm tabular-nums">{(row as DomainRow).reachable_count}</span>,
      },
      {
        title: '项目',
        width: 120,
        responsive: ['lg'],
        render: (_, row) => <span className="text-sm">{(row as DomainRow).project_name}</span>,
      },
      {
        title: '最近发现',
        align: 'right',
        render: (_, row) => (
          <span className="text-[13px] tabular-nums text-muted-foreground">
            {(row as DomainRow).last_seen?.slice(0, 10)}
          </span>
        ),
      },
    )
    rowKey = (row) => (row as DomainRow).host
  } else {
    // kind === 'ip'
    if (riskSort) {
      columns.push({
        title: '风险',
        width: 90,
        align: 'right',
        render: (_, row) => {
          const r = row as IPRow
          return riskCell(r.priority, r.risk_score)
        },
      })
    }
    columns.push(
      {
        title: 'IP',
        render: (_, row) => <span className="text-sm font-medium">{(row as IPRow).ip}</span>,
      },
      {
        title: '站点数',
        width: 100,
        align: 'right',
        render: (_, row) => <span className="text-sm tabular-nums">{(row as IPRow).site_count}</span>,
      },
      {
        title: '域名数',
        width: 100,
        align: 'right',
        render: (_, row) => <span className="text-sm tabular-nums">{(row as IPRow).domain_count}</span>,
      },
      {
        title: '最近发现',
        width: 110,
        align: 'right',
        render: (_, row) => (
          <span className="text-[13px] tabular-nums text-muted-foreground">
            {(row as IPRow).last_seen?.slice(0, 10)}
          </span>
        ),
      },
      {
        title: '项目',
        width: 110,
        render: (_, row) => <span className="text-[13px] text-muted-foreground">#{(row as IPRow).project_id}</span>,
      },
    )
    rowKey = (row) => (row as IPRow).ip
  }

  return { columns, rowKey, onRow }
}

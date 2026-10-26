import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { dashboardApi, type DashboardPanels, type DashboardStats, type TrendData } from '@/api/dashboard'
import RealTimeMonitor from '@/components/dashboard/RealTimeMonitor'
import { Button, Card, Statistic, Table, Tag } from 'antd'
import { cn, formatDate, formatNumber } from '@/lib/utils'
import { ArrowUpRight } from 'lucide-react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { ReactNode } from 'react'

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const severityColors: Record<string, string> = {
  critical: 'hsl(var(--destructive))',
  high: '#c2410c',
  medium: '#a16207',
  low: '#475569',
  info: '#94a3b8',
}

const assetLabels: Record<string, string> = {
  site: '站点',
  sites: '站点',
  domain: '域名',
  domains: '域名',
  ip: 'IP',
  endpoint: '入口',
  service: '服务',
  url: 'URL',
  active: '可访问',
  other: '其他',
}

// 资产事件类型 → 中文标签 / 颜色
const eventLabels: Record<string, string> = {
  first_seen: '新增',
  attribute_change: '属性变化',
  content_change: '内容变更',
}
const eventTagColors: Record<string, string> = {
  first_seen: 'green',
  attribute_change: 'blue',
  content_change: 'orange',
}

// 站点状态码分桶 → 中文
const httpBucketLabels: Record<string, string> = {
  '2xx': '正常响应',
  '3xx': '跳转',
  auth: '鉴权保护',
  '404': '死链',
  '5xx': '服务异常',
  unknown: '未探测',
}
const siteStateLabels: Record<string, string> = {
  reachable: '可达',
  pending: '待验证',
  lost: '失联',
}

function formatWhen(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return formatDate(date)
}

// 下钻链接基元：q 表达式按资产查询 DSL 编码，落到资产列表的过滤视图
const enc = (s: string) => encodeURIComponent(s)
const assetDrill = (expr: string) => `/assets?q=${enc(expr)}`
const rangeDrill = (field: string, lo: number, hi: number) =>
  assetDrill(`${field}>="${lo}" && ${field}<="${hi}"`)

// ---------------------------------------------------------------------------
// 布局基元：全页面板统一用 Panel（antd Card）做容器，视觉一致、网格对齐。
// ---------------------------------------------------------------------------

function Panel({
  title,
  meta,
  action,
  children,
  className,
}: {
  title: string
  meta?: string
  action?: { to: string; label: string }
  children: ReactNode
  className?: string
}) {
  return (
    <Card
      size="small"
      className={cn('h-full', className)}
      title={
        <div className="flex items-baseline gap-2">
          <span className="text-[15px] font-semibold">{title}</span>
          {meta && <span className="text-[13px] font-normal text-muted-foreground">{meta}</span>}
        </div>
      }
      extra={
        action && (
          <Link
            to={action.to}
            className="inline-flex items-center gap-1 text-[13px] text-muted-foreground hover:text-foreground"
          >
            {action.label}
            <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
        )
      }
    >
      {children}
    </Card>
  )
}

// 横条分布：Panel 内使用的通用 bars（文字 + 值 + 比例条）。
// hrefs[key] 存在时整行可点，用于仪表盘下钻到过滤后的资产/事件列表。
function Bars({
  items,
  labels,
  colors,
  hrefs,
  emptyText = '暂无数据。',
}: {
  items: Array<[string, number]>
  labels?: Record<string, string>
  colors?: Record<string, string>
  hrefs?: Record<string, string>
  emptyText?: string
}) {
  if (items.length === 0) {
    return <p className="text-sm text-muted-foreground">{emptyText}</p>
  }
  const max = Math.max(1, ...items.map(([, value]) => value))
  return (
    <div className="space-y-3">
      {items.map(([key, value]) => {
        const href = hrefs?.[key]
        const row = (
          <div>
            <div className="flex items-baseline justify-between gap-3 text-sm">
              <span className="truncate">{labels?.[key] ?? key}</span>
              <span className="tabular-nums text-muted-foreground">{formatNumber(value)}</span>
            </div>
            <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full rounded-full"
                style={{
                  width: `${Math.max(2, (value / max) * 100)}%`,
                  background: colors?.[key] ?? 'hsl(var(--primary))',
                }}
              />
            </div>
          </div>
        )
        return (
          <div key={key}>
            {href ? (
              <Link to={href} className="block rounded transition-colors hover:text-primary">
                {row}
              </Link>
            ) : (
              row
            )}
          </div>
        )
      })}
    </div>
  )
}

function MetricTile({
  label,
  value,
  meta,
  danger,
  to,
}: {
  label: string
  value: string | number
  meta?: string
  danger?: boolean
  to?: string
}) {
  const body = (
    <>
      <p className="text-[13px] text-muted-foreground">{label}</p>
      <p
        className={cn(
          'mt-1 text-2xl font-semibold tabular-nums leading-8',
          danger && 'text-destructive'
        )}
      >
        {value}
      </p>
      {meta && <p className="mt-0.5 truncate text-[13px] text-muted-foreground">{meta}</p>}
    </>
  )
  if (!to) return <div className="min-w-0">{body}</div>
  return (
    <Link to={to} className="min-w-0 rounded-lg transition-colors hover:text-primary">
      {body}
    </Link>
  )
}

// 统计卡数字：antd Statistic 自带 count-up（动效层）
function CountUp({ value, className }: { value: number; className?: string }) {
  return (
    <div className={cn('mt-2', className)}>
      <Statistic
        value={value}
        formatter={(v) => formatNumber(Number(v))}
        valueStyle={{ fontSize: '1.875rem', fontWeight: 600, lineHeight: '2.25rem', fontVariantNumeric: 'tabular-nums' }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// 看板内容
// ---------------------------------------------------------------------------

function CollectionPanel({ panels }: { panels?: DashboardPanels }) {
  const c = panels?.collection
  const jobs = c?.seed_jobs ?? {}
  const done = jobs['done'] ?? 0
  const active = (jobs['queued'] ?? 0) + (jobs['running'] ?? 0)
  const failed = jobs['error'] ?? 0
  const found = c?.seed_found_24h ?? 0
  const runs = c?.discovery_runs_24h ?? 0
  const newDomains = c?.discovery_new_24h ?? 0
  const last = c?.last_discovery
  const reachable = c?.watch_reachable ?? 0
  const checked = c?.watch_checked_24h ?? 0
  const coverage = reachable > 0 ? Math.min(100, Math.round((checked / reachable) * 100)) : 0
  const changed = c?.watch_changed_24h ?? 0

  return (
    <Panel title="采集管道" meta="近 24 小时" action={{ to: '/cruise', label: '查看巡航' }}>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <MetricTile
          label="种子采集"
          value={formatNumber(done)}
          meta={`队列 ${formatNumber(active)} · 失败 ${formatNumber(failed)} · 展开 ${formatNumber(found)}`}
          to="/cruise"
        />
        <MetricTile
          label="发现轮"
          value={formatNumber(runs)}
          meta={
            last
              ? `新发现 ${formatNumber(newDomains)} · 最近 ${formatWhen(last.ran_at)}`
              : `新发现 ${formatNumber(newDomains)}`
          }
          to="/runs"
        />
        <div className="min-w-0">
          <Link to="/cruise" className="block rounded transition-colors hover:text-primary">
            <p className="text-[13px] text-muted-foreground">巡检覆盖</p>
            <p className="mt-1 text-2xl font-semibold tabular-nums leading-8">{coverage}%</p>
          </Link>
          <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-muted">
            <div
              className={cn('h-full rounded-full', coverage >= 90 ? 'bg-primary' : 'bg-amber-500')}
              style={{ width: `${Math.max(2, coverage)}%` }}
            />
          </div>
          <p className="mt-0.5 truncate text-[13px] text-muted-foreground">
            {formatNumber(checked)} / {formatNumber(reachable)} 可达站点
          </p>
        </div>
        <MetricTile
          label="内容变更站点"
          value={formatNumber(changed)}
          danger={changed > 0}
          meta="24h 内页面内容发生变化"
          to={assetDrill('changed_within="24h"')}
        />
      </div>
    </Panel>
  )
}

function AssetChangesPanel({ panels }: { panels?: DashboardPanels }) {
  const ch = panels?.changes
  const counts = ch?.counts_24h ?? {}
  const firstSeen = counts['first_seen'] ?? 0
  const attrChange = counts['attribute_change'] ?? 0
  const contentChange = counts['content_change'] ?? 0
  const recent = ch?.recent ?? []

  return (
    <Panel title="资产动态" meta="近 24 小时" action={{ to: '/events', label: '全部事件' }}>
      <div className="grid grid-cols-3 gap-4">
        <MetricTile label="新增资产" value={formatNumber(firstSeen)} to={assetDrill('new_within="24h"')} />
        <MetricTile label="属性变化" value={formatNumber(attrChange)} to="/events?type=attribute_change" />
        <MetricTile label="内容变更" value={formatNumber(contentChange)} danger={contentChange > 0} to="/events?type=content_change" />
      </div>
      <div className="mt-4 divide-y border-t">
        {recent.length === 0 ? (
          <p className="pt-3 text-sm text-muted-foreground">暂无资产变化事件。</p>
        ) : (
          recent.map((e, i) => (
            <Link
              key={i}
              to={`/assets/${e.site_id}`}
              className="flex items-center gap-2 py-2.5 text-sm hover:text-primary"
            >
              <Tag
                color={eventTagColors[e.event_type] ?? 'default'}
                className="mr-0 shrink-0"
              >
                {eventLabels[e.event_type] ?? e.event_type}
              </Tag>
              <span className="truncate font-medium">{e.host}</span>
              <span className="hidden shrink-0 text-[13px] text-muted-foreground sm:inline">
                {e.project}
              </span>
              <time className="ml-auto shrink-0 text-[13px] tabular-nums text-muted-foreground">
                {formatWhen(e.created_at)}
              </time>
            </Link>
          ))
        )}
      </div>
    </Panel>
  )
}

function RecentSitesPanel() {
  const { data } = useQuery({
    queryKey: ['dashboard-recent-assets'],
    queryFn: () => dashboardApi.getRecentAssets(8),
  })
  const rows = data?.data ?? []

  return (
    <Panel title="新发现站点" meta="最近入库" action={{ to: '/assets', label: '查看资产' }}>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">暂无新站点，跑一轮采集后来看。</p>
      ) : (
        <div className="divide-y">
          {rows.map((s) => (
            <Link
              key={s.id}
              to={`/assets/${s.id}`}
              className="flex items-baseline gap-2 py-2.5 text-sm hover:text-primary"
            >
              <span className="truncate font-medium">{s.value}</span>
              {s.http_status >= 400 && (
                <span className="shrink-0 text-[13px] text-destructive">{s.http_status}</span>
              )}
              <span className="ml-auto hidden shrink-0 text-[13px] text-muted-foreground sm:inline">
                {s.project_name}
              </span>
              <time className="shrink-0 text-[13px] tabular-nums text-muted-foreground">
                {formatWhen(s.first_seen)}
              </time>
            </Link>
          ))}
        </div>
      )}
    </Panel>
  )
}

function ProjectBreakdownPanel({ panels }: { panels?: DashboardPanels }) {
  const rows = panels?.projects ?? []

  const numLink = (href: string, v: number, cls?: string) => (
    <Link
      to={href}
      className={cn('tabular-nums transition-colors hover:text-primary hover:underline', cls)}
    >
      {formatNumber(v)}
    </Link>
  )

  const columns = [
    {
      title: '项目',
      key: 'name',
      render: (_: unknown, row: { id: number; name: string; code: string }) => (
        <Link to={`/projects/${row.id}`} className="hover:text-primary">
          {row.name}
          {row.code && <span className="ml-1.5 text-[13px] text-muted-foreground">{row.code}</span>}
        </Link>
      ),
    },
    {
      title: '种子',
      key: 'seeds',
      align: 'right' as const,
      render: (_: unknown, row: { id: number; seeds: number }) =>
        numLink(`/seeds?project_id=${row.id}`, row.seeds),
    },
    {
      title: '站点 / 可达',
      key: 'sites',
      align: 'right' as const,
      render: (_: unknown, row: { id: number; sites: number; reachable: number }) => (
        <span className="tabular-nums">
          {numLink(`/assets?project_id=${row.id}`, row.sites)}
          <span className="text-muted-foreground">
            {' / '}
            {numLink(`/assets?project_id=${row.id}`, row.reachable)}
          </span>
        </span>
      ),
    },
    {
      title: '24h 巡检',
      key: 'checked',
      align: 'right' as const,
      render: (_: unknown, row: { id: number; checked_24h: number }) =>
        numLink(`/assets?project_id=${row.id}`, row.checked_24h),
    },
    {
      title: '内容变更',
      key: 'changed',
      align: 'right' as const,
      render: (_: unknown, row: { changed_24h: number }) => (
        <Link
          to="/events?type=content_change"
          className={cn('tabular-nums transition-colors hover:text-primary hover:underline', row.changed_24h > 0 && 'text-amber-500')}
        >
          {formatNumber(row.changed_24h)}
        </Link>
      ),
    },
    {
      title: '接口路由',
      key: 'routes',
      align: 'right' as const,
      render: (_: unknown, row: { id: number; routes: number }) =>
        numLink(`/assets?project_id=${row.id}`, row.routes),
    },
    {
      title: '待确认候选',
      key: 'pending',
      align: 'right' as const,
      render: (_: unknown, row: { id: number; pending_candidates: number }) =>
        numLink(`/projects/${row.id}`, row.pending_candidates, row.pending_candidates > 0 ? 'font-medium text-amber-500' : undefined),
    },
    {
      title: '最近发现轮',
      dataIndex: 'last_discovery_at',
      render: (v?: string) => (
        <span className="tabular-nums text-muted-foreground">{formatWhen(v)}</span>
      ),
    },
  ]

  return (
    <Panel
      title="项目资产分布"
      meta="种子 → 站点 → 巡检 → 接口面"
      action={{ to: '/projects', label: '查看项目' }}
    >
      <div className="overflow-x-auto">
        <Table
          size="small"
          rowKey="id"
          columns={columns}
          dataSource={rows}
          pagination={false}
          locale={{ emptyText: '暂无项目' }}
        />
      </div>
    </Panel>
  )
}

function RouteSurfacePanel({ panels }: { panels?: DashboardPanels }) {
  const r = panels?.routes
  const items: Array<[string, number]> = (r?.top_hosts ?? []).map((h) => [h.host, h.routes])
  const hrefs = Object.fromEntries(
    (r?.top_hosts ?? []).map((h) => [h.host, assetDrill(`host=="${h.host}"`)])
  )
  const methods = Object.entries(r?.methods ?? {})
  const total = r?.total ?? 0

  return (
    <Panel
      title="接口面 TOP"
      meta={total > 0 ? `共 ${formatNumber(total)} 条 · 去重 ${formatNumber(r?.distinct_paths ?? 0)}` : undefined}
      action={{ to: '/assets', label: '查看资产' }}
    >
      <div className="flex flex-wrap items-center gap-2">
        {methods.map(([method, n]) => (
          <span
            key={method}
            className="rounded-md border bg-muted/40 px-2 py-0.5 text-[13px] tabular-nums"
          >
            {method} <span className="text-muted-foreground">{formatNumber(n)}</span>
          </span>
        ))}
        {methods.length === 0 && <span className="text-sm text-muted-foreground">暂无路由数据。</span>}
      </div>
      <div className="mt-4">
        <Bars items={items} hrefs={hrefs} emptyText="跑一轮爬虫后这里会出现接口最多的站点。" />
      </div>
    </Panel>
  )
}

function JSSecretPanel({ panels }: { panels?: DashboardPanels }) {
  const js = panels?.js_secrets
  const total = js?.total ?? 0
  const recent = js?.recent ?? []

  return (
    <Panel
      title="JS 密钥审计命中"
      meta="不发攻击性请求"
      action={{ to: '/vulnerabilities', label: '查看漏洞' }}
    >
      {total === 0 ? (
        <p className="text-sm text-muted-foreground">
          暂无命中。审计在爬虫拿到 JS 产物后自动进行（AK/SK、token 泄露规则），漏洞扫描保持默认关闭。
        </p>
      ) : (
        <>
          <p className="text-sm">
            累计命中 <span className="font-semibold tabular-nums">{formatNumber(total)}</span> 条
          </p>
          <div className="mt-2 divide-y">
            {recent.map((hit, i) => (
              <div
                key={`${hit.target}-${i}`}
                className="flex flex-col gap-1 py-2.5 sm:flex-row sm:items-baseline sm:justify-between"
              >
                <p className="min-w-0 text-sm">
                  <span className="font-medium">{hit.name}</span>{' '}
                  <span className="break-all text-muted-foreground">{hit.target}</span>
                </p>
                <time className="shrink-0 text-[13px] tabular-nums text-muted-foreground">
                  {formatWhen(hit.created_at)}
                </time>
              </div>
            ))}
          </div>
        </>
      )}
    </Panel>
  )
}

function SiteStatusPanel({ panels }: { panels?: DashboardPanels }) {
  const ss = panels?.site_status
  const httpItems: Array<[string, number]> = Object.entries(ss?.http_buckets ?? {}).sort(
    (a, b) => b[1] - a[1]
  )
  const stateItems: Array<[string, number]> = Object.entries(ss?.states ?? {}).sort(
    (a, b) => b[1] - a[1]
  )

  // 分桶 → 资产列表过滤视图（DSL 范围/精确查询）
  const httpHrefs: Record<string, string> = {
    '2xx': rangeDrill('status_code', 200, 299),
    '3xx': rangeDrill('status_code', 300, 399),
    auth: assetDrill('status_code="401" || status_code="403"'),
    '404': assetDrill('status_code="404"'),
    '5xx': rangeDrill('status_code', 500, 599),
    unknown: assetDrill('status_code="0"'),
  }
  const stateHrefs: Record<string, string> = Object.fromEntries(
    stateItems.map(([s]) => [s, assetDrill(`state=="${s}"`)])
  )

  return (
    <Panel title="站点状态" meta="状态码 / 巡检状态">
      <p className="mb-3 text-[13px] font-medium text-muted-foreground">HTTP 状态码</p>
      <Bars items={httpItems} labels={httpBucketLabels} hrefs={httpHrefs} />
      <p className="mb-3 mt-5 text-[13px] font-medium text-muted-foreground">巡检状态</p>
      <Bars items={stateItems} labels={siteStateLabels} hrefs={stateHrefs} />
    </Panel>
  )
}

function TechPanel({ panels }: { panels?: DashboardPanels }) {
  const items: Array<[string, number]> = (panels?.tech_top ?? []).map((t) => [t.name, t.count])
  const hrefs = Object.fromEntries(
    (panels?.tech_top ?? []).map((t) => [t.name, assetDrill(`app=="${t.name}"`)])
  )
  return (
    <Panel title="技术栈 TOP" meta="指纹命中" action={{ to: '/fingerprints', label: '指纹库' }}>
      <Bars items={items} hrefs={hrefs} emptyText="指纹命中后这里会出现技术栈分布。" />
    </Panel>
  )
}

function PortPanel({ panels }: { panels?: DashboardPanels }) {
  const items: Array<[string, number]> = (panels?.port_top ?? []).map((p) => [
    `:${p.port}`,
    p.count,
  ])
  const hrefs = Object.fromEntries(
    (panels?.port_top ?? []).map((p) => [`:${p.port}`, assetDrill(`port=="${p.port}"`)])
  )
  return (
    <Panel title="端口分布" meta="暴露面" action={{ to: '/assets', label: '资产列表' }}>
      <Bars items={items} hrefs={hrefs} emptyText="端口扫描后这里会出现端口分布。" />
    </Panel>
  )
}

function EnginePanel({ panels }: { panels?: DashboardPanels }) {
  const items: Array<[string, number]> = (panels?.engine_usage ?? []).map((e) => [
    e.engine,
    e.queries,
  ])
  return (
    <Panel title="测绘引擎用量" meta="近 7 天" action={{ to: '/sources', label: '采集源' }}>
      <Bars items={items} emptyText="近 7 天没有引擎查询记录。" />
    </Panel>
  )
}

function CapabilitiesPanel({ panels }: { panels?: DashboardPanels }) {
  const c = panels?.capabilities
  if (!c) return null

  const tiles: Array<{ label: string; value: string; meta?: string; to?: string }> = [
    {
      label: '扫描字典',
      value: `${formatNumber(c.dict_sets)} 套`,
      meta: `词条 ${formatNumber(c.dict_words)} · 待晋升 ${formatNumber(c.dict_learning_pending)}`,
      to: '/dictionaries',
    },
    {
      label: '指纹规则',
      value: formatNumber(c.fingerprint_rules),
      meta: `来源 ${formatNumber(c.fingerprint_sources)} · 24h 命中 ${formatNumber(c.fingerprint_hits_24h)}`,
      to: '/fingerprints',
    },
    {
      label: 'POC 库',
      value: formatNumber(c.pocs_total),
      meta: `启用 ${formatNumber(c.pocs_enabled)} · 扫描默认关闭`,
      to: '/pocs',
    },
    {
      label: '漏洞情报',
      value: formatNumber(c.intel_total),
      meta: `近 7 天入库 ${formatNumber(c.intel_7d)}`,
      to: '/vuln-intel',
    },
    {
      label: 'GitHub 泄露监控',
      value: `${formatNumber(c.github_leak_rules)} 条规则`,
      meta: `命中 ${formatNumber(c.github_leak_findings)}`,
    },
    {
      label: '站点验证',
      value: `${formatNumber(c.verifications_24h)} 次`,
      meta: '近 24h 存活复核',
      to: '/verifications',
    },
    {
      label: '资产关联',
      value: formatNumber(c.relations),
      meta: '证据链',
      to: '/relations',
    },
    {
      label: '数字资产',
      value: formatNumber(c.digital_assets),
      meta: 'App / 小程序 / 公众号',
      to: '/digital-assets',
    },
    {
      label: '企业实体',
      value: formatNumber(c.enterprise_entities),
      meta: '股权穿透',
      to: '/enterprise',
    },
  ]

  return (
    <Panel title="平台内置能力" meta="字典 / 指纹 / POC / 情报 / 泄露监控盘点">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
        {tiles.map((t) => {
          const body = (
            <>
              <p className="text-[13px] text-muted-foreground">{t.label}</p>
              <p className="mt-1 truncate text-xl font-semibold tabular-nums leading-7">{t.value}</p>
              {t.meta && <p className="mt-0.5 truncate text-[13px] text-muted-foreground">{t.meta}</p>}
            </>
          )
          return t.to ? (
            <Link
              key={t.label}
              to={t.to}
              className="min-w-0 rounded-lg border p-3 transition-colors hover:bg-muted/40"
            >
              {body}
            </Link>
          ) : (
            <div key={t.label} className="min-w-0 rounded-lg border p-3">
              {body}
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const { data: statsData, isLoading: statsLoading, isError: statsError, refetch: refetchStats } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => dashboardApi.getStats(),
  })

  const { data: trendsData } = useQuery({
    queryKey: ['dashboard-trends'],
    queryFn: () => dashboardApi.getTrends(7),
  })

  const { data: activitiesData } = useQuery({
    queryKey: ['dashboard-activities'],
    queryFn: () => dashboardApi.getRecentActivities(5),
  })

  const { data: panelsData } = useQuery({
    queryKey: ['dashboard-panels'],
    queryFn: () => dashboardApi.getPanels(),
  })

  const stats: DashboardStats | undefined = statsData?.data
  const trends: TrendData[] = trendsData?.data || []
  const activities = activitiesData?.data || []
  const panels = panelsData?.data

  const running = stats?.tasks?.running ?? 0
  const openVulns = stats?.vulnerabilities?.open ?? 0
  const offlineNodes = stats?.nodes?.offline ?? 0
  const totalAssets = stats?.assets?.total ?? 0
  const recentAssets = stats?.assets?.recentlyAdded ?? 0
  const onlineNodes = stats?.nodes?.online ?? 0
  const totalNodes = stats?.nodes?.total ?? 0

  const finding = [
    running > 0 ? `${running} 个任务正在运行` : '当前没有运行中的任务',
    openVulns > 0 ? `${openVulns} 个漏洞待修复` : '暂无待修复漏洞',
    offlineNodes > 0 ? `${offlineNodes} 个节点离线` : null,
  ]
    .filter(Boolean)
    .join('，')

  const vulnBySeverity = stats?.vulnerabilities?.bySeverity
    ? Object.entries(stats.vulnerabilities.bySeverity).sort(
        (a, b) => b[1] - a[1]
      )
    : []
  const assetTypeEntries = stats?.assets?.byType ? Object.entries(stats.assets.byType) : []
  const activeAssets = stats?.assets?.active ?? 0
  const assetDistribution: Array<[string, number]> =
    assetTypeEntries.length > 0
      ? assetTypeEntries
      : totalAssets > 0
        ? [
            ['active', activeAssets],
            ['other', Math.max(0, totalAssets - activeAssets)],
          ]
        : []
  const trendHasData = trends.some(
    (point) => (point.assets || 0) + (point.vulnerabilities || 0) + (point.tasks || 0) > 0
  )

  if (statsLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 w-40 animate-pulse rounded bg-muted" />
        <div className="h-28 animate-pulse rounded bg-muted" />
        <div className="h-64 animate-pulse rounded bg-muted" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">仪表盘</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{finding}。</p>
        </div>
        <div className="flex items-center gap-3">
          {/* 统计接口失败时数字全为 0：必须显式告警，不能让「挂了」看起来像「没有」 */}
          {statsError && (
            <span className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-1.5 text-sm text-destructive">
              统计加载失败，数字不可信
              <Button type="link" size="small" onClick={() => refetchStats()}>重试</Button>
            </span>
          )}
          <Link to="/tasks/new">
            <Button type="primary">
              新建侦察任务
              <ArrowUpRight className="ml-1.5 h-4 w-4" />
            </Button>
          </Link>
        </div>
      </div>

      {/* 概览卡：整卡可点下钻 */}
      <section aria-label="当前概览" className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
        <Link to="/projects" className="rounded-lg transition-shadow hover:shadow-md">
          <Card className="h-full">
            <p className="text-[13px] text-muted-foreground">监控项目</p>
            <CountUp value={panels?.projects?.length ?? 0} />
            <p className="mt-1 text-[13px] text-muted-foreground">采集与巡检对象</p>
          </Card>
        </Link>
        <Link to="/tasks" className="rounded-lg transition-shadow hover:shadow-md">
          <Card className="h-full">
            <p className="text-[13px] text-muted-foreground">运行中任务</p>
            <CountUp value={running} />
            <p className="mt-1 text-[13px] text-muted-foreground">
              共 {formatNumber(stats?.tasks?.total ?? 0)} 个任务
            </p>
          </Card>
        </Link>
        <Link to="/vulnerabilities" className="rounded-lg transition-shadow hover:shadow-md">
          <Card className="h-full">
            <p className="text-[13px] text-muted-foreground">待修复漏洞</p>
            <CountUp value={openVulns} className={openVulns > 0 ? 'text-destructive' : undefined} />
            <p className="mt-1 text-[13px] text-muted-foreground">
              近期新增 {formatNumber(stats?.vulnerabilities?.recentlyFound ?? 0)} 个
            </p>
          </Card>
        </Link>
        <Link to="/nodes" className="rounded-lg transition-shadow hover:shadow-md">
          <Card className="h-full">
            <p className="text-[13px] text-muted-foreground">在线节点</p>
            <div className="mt-2 flex items-baseline gap-1">
              <CountUp value={onlineNodes} />
              <span className="text-base font-normal text-muted-foreground">
                / {formatNumber(totalNodes)}
              </span>
            </div>
            <p className="mt-1 text-[13px] text-muted-foreground">
              {offlineNodes > 0 ? `${offlineNodes} 个离线` : '全部在线'}
            </p>
          </Card>
        </Link>
        <Link to="/assets" className="rounded-lg transition-shadow hover:shadow-md">
          <Card className="h-full">
            <p className="text-[13px] text-muted-foreground">资产总量</p>
            <CountUp value={totalAssets} />
            <p className="mt-1 text-[13px] text-muted-foreground">
              7 天新增 {formatNumber(recentAssets)} 个
            </p>
          </Card>
        </Link>
      </section>

      {/* 趋势 + 需要处理 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel
          title="资产增长"
          meta="最近 7 天"
          action={{ to: '/assets', label: '查看资产' }}
          className="lg:col-span-2"
        >
          <div className="mb-2 flex flex-wrap items-center gap-4 text-[13px] text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 rounded-full bg-primary" />
              资产
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 rounded-full bg-muted-foreground" />
              任务
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 rounded-full bg-destructive" />
              漏洞
            </span>
          </div>
          <div className="h-[220px]" role="img" aria-label="最近 7 天资产、任务和漏洞趋势">
            {trendHasData ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trends} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid vertical={false} stroke="hsl(var(--border))" strokeDasharray="2 4" />
                  <XAxis
                    dataKey="date"
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
                  />
                  <YAxis
                    width={36}
                    tickLine={false}
                    axisLine={false}
                    tick={{ fontSize: 12, fill: 'hsl(var(--muted-foreground))' }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: 4,
                      fontSize: 12,
                    }}
                  />
                  <Line type="monotone" dataKey="assets" name="资产" stroke="hsl(var(--primary))" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="tasks" name="任务" stroke="hsl(var(--muted-foreground))" strokeWidth={1.5} dot={false} />
                  <Line type="monotone" dataKey="vulnerabilities" name="漏洞" stroke="hsl(var(--destructive))" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                最近 7 天还没有资产变化。
              </div>
            )}
          </div>
        </Panel>

        <Panel title="需要处理">
          <div className="divide-y">
            {running > 0 && (
              <Link to="/tasks" className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary">
                <span>运行中的任务</span>
                <span className="tabular-nums">{running}</span>
              </Link>
            )}
            {openVulns > 0 && (
              <Link to="/vulnerabilities" className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary">
                <span>待修复漏洞</span>
                <span className="tabular-nums text-destructive">{openVulns}</span>
              </Link>
            )}
            {offlineNodes > 0 && (
              <Link to="/nodes" className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary">
                <span>离线节点</span>
                <span className="tabular-nums text-destructive">{offlineNodes}</span>
              </Link>
            )}
            {running === 0 && openVulns === 0 && offlineNodes === 0 && (
              <p className="py-3 text-sm text-muted-foreground">目前没有需要立即处理的事项。</p>
            )}
          </div>
        </Panel>
      </div>

      {/* 资产动态 + 新发现站点 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <AssetChangesPanel panels={panels} />
        </div>
        <RecentSitesPanel />
      </div>

      {/* 采集管道 */}
      <CollectionPanel panels={panels} />

      {/* 项目资产分布 */}
      <ProjectBreakdownPanel panels={panels} />

      {/* 站点状态 / 端口 / 技术栈 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <SiteStatusPanel panels={panels} />
        <PortPanel panels={panels} />
        <TechPanel panels={panels} />
      </div>

      {/* 接口面 + JS 密钥 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <RouteSurfacePanel panels={panels} />
        </div>
        <JSSecretPanel panels={panels} />
      </div>

      {/* 漏洞 / 资产构成 / 引擎用量 */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="漏洞严重程度" action={{ to: '/vulnerabilities', label: '查看漏洞' }}>
          <Bars
            items={vulnBySeverity}
            labels={severityLabels}
            colors={severityColors}
            hrefs={Object.fromEntries(
              vulnBySeverity.map(([sev]) => [sev, `/vulnerabilities?severity=${sev}`])
            )}
            emptyText="暂无漏洞记录。"
          />
        </Panel>
        <Panel title="资产构成" action={{ to: '/assets', label: '查看资产' }}>
          <Bars
            items={assetDistribution}
            labels={assetLabels}
            colors={{ active: 'hsl(var(--primary))', other: '#cbd5e1' }}
            hrefs={{ active: '/assets', other: '/assets' }}
            emptyText="暂无资产数据。"
          />
        </Panel>
        <EnginePanel panels={panels} />
      </div>

      {/* 平台内置能力 */}
      <CapabilitiesPanel panels={panels} />

      <RealTimeMonitor />

      {/* 最近活动 */}
      <Panel title="最近活动" action={{ to: '/audit', label: '查看审计' }}>
        {activities.length === 0 ? (
          <p className="text-sm text-muted-foreground">暂无活动记录。</p>
        ) : (
          <div className="divide-y">
            {activities.map((activity) => (
              <div
                key={activity.id}
                className="flex flex-col gap-1 py-3 sm:flex-row sm:items-baseline sm:justify-between"
              >
                <p className="min-w-0 text-sm">
                  <span className="font-medium">{activity.username}</span>{' '}
                  <span>{activity.action}</span>{' '}
                  <span className="break-all text-muted-foreground">{activity.target}</span>
                </p>
                <time className="shrink-0 text-[13px] tabular-nums text-muted-foreground">
                  {formatWhen(activity.createdAt)}
                </time>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}

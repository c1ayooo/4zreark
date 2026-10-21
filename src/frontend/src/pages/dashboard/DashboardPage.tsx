import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { dashboardApi, type DashboardStats, type TrendData } from '@/api/dashboard'
import RealTimeMonitor from '@/components/dashboard/RealTimeMonitor'
import { Button } from '@/components/ui/button'
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

function formatWhen(value?: string) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return formatDate(date)
}

function PanelHeading({
  title,
  meta,
  action,
}: {
  title: string
  meta?: string
  action?: { to: string; label: string }
}) {
  return (
    <div className="flex items-baseline justify-between gap-4">
      <div className="flex items-baseline gap-3">
        <h2 className="text-[15px] font-semibold">{title}</h2>
        {meta && <span className="text-[13px] text-muted-foreground">{meta}</span>}
      </div>
      {action && (
        <Link
          to={action.to}
          className="inline-flex items-center gap-1 text-[13px] text-muted-foreground hover:text-foreground"
        >
          {action.label}
          <ArrowUpRight className="h-3.5 w-3.5" />
        </Link>
      )}
    </div>
  )
}

function Distribution({
  title,
  items,
  labels,
  colors,
}: {
  title: string
  items: Array<[string, number]>
  labels?: Record<string, string>
  colors?: Record<string, string>
}) {
  const max = Math.max(1, ...items.map(([, value]) => value))
  return (
    <section className="border-t pt-5">
      <PanelHeading title={title} />
      {items.length === 0 ? (
        <p className="mt-4 text-sm text-muted-foreground">暂无数据，任务跑完后再看。</p>
      ) : (
        <div className="mt-4 max-w-2xl space-y-3">
          {items.map(([key, value]) => (
            <div key={key}>
              <div className="flex items-baseline justify-between gap-3 text-sm">
                <span>{labels?.[key] ?? key}</span>
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
          ))}
        </div>
      )}
    </section>
  )
}

export default function DashboardPage() {
  const { data: statsData, isLoading: statsLoading } = useQuery({
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

  const stats: DashboardStats | undefined = statsData?.data
  const trends: TrendData[] = trendsData?.data || []
  const activities = activitiesData?.data || []

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
  const vulnBySeverity = stats?.vulnerabilities?.bySeverity
    ? Object.entries(stats.vulnerabilities.bySeverity)
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
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">仪表盘</h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">{finding}。</p>
        </div>
        <Button asChild>
          <Link to="/tasks/new">
            新建侦察任务
            <ArrowUpRight className="ml-1.5 h-4 w-4" />
          </Link>
        </Button>
      </div>

      <section
        aria-label="当前概览"
        className="grid grid-cols-2 gap-px overflow-hidden border-y bg-border md:grid-cols-4"
      >
        <div className="bg-background px-0 py-5 md:px-6">
          <p className="text-[13px] text-muted-foreground">运行中任务</p>
          <p className="mt-2 text-3xl font-semibold tabular-nums">{formatNumber(running)}</p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            共 {formatNumber(stats?.tasks?.total ?? 0)} 个任务
          </p>
        </div>
        <div className="bg-background px-4 py-5 md:px-6">
          <p className="text-[13px] text-muted-foreground">待修复漏洞</p>
          <p
            className={cn(
              'mt-2 text-3xl font-semibold tabular-nums',
              openVulns > 0 && 'text-destructive'
            )}
          >
            {formatNumber(openVulns)}
          </p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            近期新增 {formatNumber(stats?.vulnerabilities?.recentlyFound ?? 0)} 个
          </p>
        </div>
        <div className="bg-background px-0 py-5 md:px-6">
          <p className="text-[13px] text-muted-foreground">在线节点</p>
          <p className="mt-2 text-3xl font-semibold tabular-nums">
            {formatNumber(onlineNodes)}
            <span className="ml-1 text-base font-normal text-muted-foreground">
              / {formatNumber(totalNodes)}
            </span>
          </p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            {offlineNodes > 0 ? `${offlineNodes} 个离线` : '全部在线'}
          </p>
        </div>
        <div className="bg-background px-4 py-5 md:px-6">
          <p className="text-[13px] text-muted-foreground">资产总量</p>
          <p className="mt-2 text-3xl font-semibold tabular-nums">{formatNumber(totalAssets)}</p>
          <p className="mt-1 text-[13px] text-muted-foreground">
            新增 {formatNumber(recentAssets)} 个
          </p>
        </div>
      </section>

      <div className="grid gap-8 lg:grid-cols-[minmax(0,1.7fr)_minmax(0,1fr)]">
        <section className="min-w-0">
          <PanelHeading
            title="资产增长"
            meta="最近 7 天"
            action={{ to: '/assets', label: '查看资产' }}
          />
          <div className="mt-4 flex flex-wrap items-center gap-4 text-[13px] text-muted-foreground">
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
          <div className="mt-3 h-[240px]" role="img" aria-label="最近 7 天资产、任务和漏洞趋势">
            {trendHasData ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trends} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid
                    vertical={false}
                    stroke="hsl(var(--border))"
                    strokeDasharray="2 4"
                  />
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
                  <Line
                    type="monotone"
                    dataKey="assets"
                    name="资产"
                    stroke="hsl(var(--primary))"
                    strokeWidth={2}
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="tasks"
                    name="任务"
                    stroke="hsl(var(--muted-foreground))"
                    strokeWidth={1.5}
                    dot={false}
                  />
                  <Line
                    type="monotone"
                    dataKey="vulnerabilities"
                    name="漏洞"
                    stroke="hsl(var(--destructive))"
                    strokeWidth={1.5}
                    dot={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center border-t text-sm text-muted-foreground">
                最近 7 天还没有资产变化。
              </div>
            )}
          </div>
        </section>

        <section>
          <PanelHeading title="需要处理" />
          <div className="mt-3 divide-y">
            {running > 0 && (
              <Link
                to="/tasks"
                className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary"
              >
                <span>运行中的任务</span>
                <span className="tabular-nums">{running}</span>
              </Link>
            )}
            {openVulns > 0 && (
              <Link
                to="/vulnerabilities"
                className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary"
              >
                <span>待修复漏洞</span>
                <span className="tabular-nums text-destructive">{openVulns}</span>
              </Link>
            )}
            {offlineNodes > 0 && (
              <Link
                to="/nodes"
                className="flex items-baseline justify-between gap-3 py-3 text-sm hover:text-primary"
              >
                <span>离线节点</span>
                <span className="tabular-nums text-destructive">{offlineNodes}</span>
              </Link>
            )}
            {running === 0 && openVulns === 0 && offlineNodes === 0 && (
              <p className="py-3 text-sm text-muted-foreground">目前没有需要立即处理的事项。</p>
            )}
          </div>
        </section>
      </div>

      <div
        className={cn(
          'grid gap-8',
          vulnBySeverity.length > 0 && assetDistribution.length > 0 && 'lg:grid-cols-2'
        )}
      >
        <Distribution
          title="漏洞严重程度"
          items={vulnBySeverity}
          labels={severityLabels}
          colors={severityColors}
        />
        <Distribution
          title="资产构成"
          items={assetDistribution}
          labels={assetLabels}
          colors={{ active: 'hsl(var(--primary))', other: '#cbd5e1' }}
        />      </div>

      <RealTimeMonitor />

      <section className="border-t pt-5">
        <PanelHeading title="最近活动" action={{ to: '/audit', label: '查看审计' }} />
        {activities.length === 0 ? (
          <p className="mt-4 text-sm text-muted-foreground">暂无活动记录。</p>
        ) : (
          <div className="mt-2 divide-y">
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
      </section>
    </div>
  )
}

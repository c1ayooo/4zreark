import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Activity, Globe2, Layers, RefreshCw, Server, TrendingUp } from 'lucide-react'
import { Button, Card, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { assetApi, type AssetProject, type OverviewData } from '@/api/assets'
import EmptyState from '@/components/common/EmptyState'
import { statusTagClass } from '@/components/ui/StatusTag'

const nf = new Intl.NumberFormat('zh-CN')

// shadcn Badge variant → antd Tag 主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass
export default function AssetOverviewPage() {
  const overview = useQuery({
    queryKey: ['asset-overview'],
    queryFn: () => assetApi.overview(),
    refetchInterval: 60_000,
  })
  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const d: OverviewData | undefined = overview.data?.data
  const tech = (d?.technology_counts || []).slice(0, 8)
  const maxTech = tech.reduce((m, t) => Math.max(m, t.site_count ?? 0), 0) || 1
  const projectList: AssetProject[] = projects.data?.data || []

  const projectColumns: TableProps<AssetProject>['columns'] = [
    {
      title: '项目',
      key: 'name',
      render: (_, p) => (
        <div>
          <Link to={`/projects/${p.id}`} className="font-medium hover:underline">
            {p.name}
          </Link>
          <div className="text-muted-foreground font-mono text-[11px]">{p.code}</div>
        </div>
      ),
    },
    {
      title: '资产',
      dataIndex: 'asset_count',
      key: 'asset_count',
      width: 96,
      align: 'right',
      render: (v: number) => <span className="font-mono tabular-nums">{nf.format(v ?? 0)}</span>,
    },
    {
      title: '记录',
      dataIndex: 'record_count',
      key: 'record_count',
      width: 96,
      align: 'right',
      render: (v: number) => <span className="font-mono tabular-nums">{nf.format(v ?? 0)}</span>,
    },
    {
      title: '丢失',
      dataIndex: 'lost_count',
      key: 'lost_count',
      width: 80,
      align: 'right',
      render: (v: number) => <span className="font-mono tabular-nums">{nf.format(v ?? 0)}</span>,
    },
    {
      title: '采集周期',
      dataIndex: 'cycle_interval_days',
      key: 'cycle_interval_days',
      width: 96,
      render: (v: number) => (
        <span className="text-muted-foreground text-xs">{v ? `${v} 天` : '—'}</span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'collection_paused',
      key: 'collection_paused',
      width: 88,
      render: (v: boolean) =>
        v ? (
          <Tag className={badgeCls('secondary')}>已暂停</Tag>
        ) : (
          <Tag className={badgeCls('default')}>采集中</Tag>
        ),
    },
  ]

  const cards = [
    { icon: Layers, label: '资产总数', value: d?.assets, hint: `去重后的站点与 IP` },
    { icon: Globe2, label: '域名', value: d?.domains, hint: '按 host 归并' },
    { icon: Server, label: '站点', value: d?.sites, hint: `已验证 ${nf.format(d?.verified_sites ?? 0)}` },
    { icon: Activity, label: '资产记录', value: d?.record_count, hint: '含历史与多来源' },
    { icon: TrendingUp, label: '今日新增', value: d?.new_today, hint: '按首次发现时间' },
  ]

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">资产总览</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            全部项目的资产规模、技术栈分布与产出节奏。要按条件筛具体资产，去「资产探索」。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-muted-foreground text-xs">
            {overview.dataUpdatedAt ? new Date(overview.dataUpdatedAt).toLocaleTimeString() : '—'} 更新 · 每分钟自动刷新
          </span>
          <Button size="small" onClick={() => overview.refetch()} disabled={overview.isFetching}>
            <RefreshCw className={overview.isFetching ? 'mr-1 h-4 w-4 animate-spin' : 'mr-1 h-4 w-4'} />
            刷新
          </Button>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {cards.map((c) => (
          <Card key={c.label} styles={{ body: { padding: 16 } }}>
            <div className="text-muted-foreground flex items-center gap-1.5 text-xs">
              <c.icon className="h-3.5 w-3.5" />
              {c.label}
            </div>
            <div className="mt-2 font-mono text-2xl font-semibold tabular-nums">
              {overview.isLoading ? '—' : nf.format(c.value ?? 0)}
            </div>
            <div className="text-muted-foreground mt-1 text-[11px]">{c.hint}</div>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          className="lg:col-span-2"
          title={<span className="text-sm">项目产出</span>}
          styles={{ body: { paddingTop: 4, paddingBottom: 4 } }}
        >
          <Table
            columns={projectColumns}
            dataSource={projectList}
            rowKey="id"
            pagination={false}
            locale={{
              emptyText: (
                <EmptyState title="还没有项目，先在「项目管理」里建一个。" className="border-0" />
              ),
            }}
          />
        </Card>

        <Card title={<span className="text-sm">技术栈 Top 8</span>}>
          <div className="space-y-2.5">
            {tech.length === 0 ? (
              <p className="text-muted-foreground py-6 text-center text-sm">还没有识别出技术栈</p>
            ) : (
              tech.map((t) => (
                <div key={t.key} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="truncate">{t.name || t.key}</span>
                    <span className="text-muted-foreground ml-2 font-mono tabular-nums">{t.site_count}</span>
                  </div>
                  <div className="bg-muted h-1.5 overflow-hidden rounded-full">
                    <div
                      className="bg-primary/70 h-full rounded-full"
                      style={{ width: `${Math.max(4, ((t.site_count ?? 0) / maxTech) * 100)}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      <Card title={<span className="text-sm">最近变更</span>}>
        <div className="space-y-2">
          {(d?.recent_events || []).length === 0 ? (
            <p className="text-muted-foreground py-4 text-center text-sm">最近没有变更事件</p>
          ) : (
            (d?.recent_events || []).slice(0, 8).map((e: any, i: number) => (
              <div key={`${e.id ?? i}`} className="flex items-start gap-2 text-sm">
                <span className="bg-primary/60 mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" />
                <span className="flex-1 truncate">
                  {e.title || e.event_type || '变更'}
                  {e.asset_value ? (
                    <span className="text-muted-foreground ml-2 font-mono text-[11px]">{e.asset_value}</span>
                  ) : null}
                </span>
                <span className="text-muted-foreground shrink-0 font-mono text-[11px]">
                  {e.created_at ? new Date(e.created_at).toLocaleString() : ''}
                </span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  )
}

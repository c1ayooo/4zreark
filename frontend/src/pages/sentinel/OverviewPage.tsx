import { useQuery } from '@tanstack/react-query'
import { Button, Card, Progress, Statistic, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Activity, GitBranch, ShieldAlert, Timer } from 'lucide-react'
import { Link } from 'react-router-dom'
import { sentinelApi, SentinelCommit } from '@/api/sentinel'
import { formatDate } from '@/lib/utils'

const severityColor: Record<string, string> = {
  critical: 'magenta',
  high: 'red',
  medium: 'orange',
  low: 'gold',
  info: 'default',
}

export default function SentinelOverviewPage() {
  const overviewQuery = useQuery({
    queryKey: ['sentinel-overview'],
    queryFn: sentinelApi.overview,
    refetchInterval: 30_000,
  })
  const hitsQuery = useQuery({
    queryKey: ['sentinel-recent-hits'],
    queryFn: () => sentinelApi.listCommits({ security_fix: true, size: 8, page: 1 }),
  })

  const overview = overviewQuery.data
  const hits = hitsQuery.data?.list ?? []

  const cards = [
    {
      key: 'repos',
      title: '纳管仓库',
      value: overview?.repo_count ?? 0,
      icon: GitBranch,
      hint: '已登记并参与采集的公开仓库',
    },
    {
      key: 'today',
      title: '今日提交',
      value: overview?.today_commits ?? 0,
      icon: Activity,
      hint: '当日入库的提交数量',
    },
    {
      key: 'hits',
      title: '判定命中',
      value: overview?.security_fixes ?? 0,
      icon: ShieldAlert,
      hint: '被判为安全修复的提交',
    },
    {
      key: 'pending',
      title: '待判定',
      value: overview?.pending_commits ?? 0,
      icon: Timer,
      hint: '仍在队列中等待模型判定',
    },
  ]

  const columns: TableProps<SentinelCommit>['columns'] = [
    {
      title: '提交',
      dataIndex: 'sha',
      width: 150,
      render: (_, row) => (
        <Link to={`/sentinel/commits/${row.id}`} className="font-mono text-xs text-primary hover:underline">
          {row.sha.slice(0, 8)}
        </Link>
      ),
    },
    {
      title: '仓库',
      dataIndex: 'repo_full_name',
      width: 220,
      ellipsis: true,
      render: (value: string) => <span className="text-xs text-muted-foreground">{value}</span>,
    },
    { title: '主题', dataIndex: 'subject', ellipsis: true },
    {
      title: '类型',
      dataIndex: 'vuln_class',
      width: 150,
      render: (value: string) => (
        <Tag color="blue" className="font-mono text-[11px]">
          {value || 'OTHER'}
        </Tag>
      ),
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      width: 90,
      render: (value: string) => <Tag color={severityColor[value] ?? 'default'}>{value || 'info'}</Tag>,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 140,
      render: (value: number) => (
        <Progress percent={Math.round((value ?? 0) * 100)} size="small" strokeColor="hsl(var(--primary))" />
      ),
    },
    {
      title: '时间',
      dataIndex: 'committed_at',
      width: 160,
      render: (value: string) => <span className="text-xs text-muted-foreground">{formatDate(value)}</span>,
    },
  ]

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">哨兵总览</h1>
          <p className="text-sm text-muted-foreground">
            采集公开仓库提交，用模型判断「这个提交是不是安全漏洞修复」。规则只做噪音过滤，判定权只属于模型。
          </p>
        </div>
        <Link to="/sentinel/audit/tasks">
          <Button>分析任务</Button>
        </Link>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map((card) => {
          const Icon = card.icon
          return (
            <Card key={card.key} loading={overviewQuery.isLoading} className="overflow-hidden border-border/60">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <Statistic title={card.title} value={card.value} />
                  <p className="mt-2 text-xs text-muted-foreground">{card.hint}</p>
                </div>
                <span className="rounded-lg bg-muted p-2.5 text-muted-foreground">
                  <Icon className="h-5 w-5" />
                </span>
              </div>
            </Card>
          )
        })}
      </div>

      <Card
        title="最近命中"
        extra={
          <Link to="/sentinel/commits?security_fix=true" className="text-xs text-primary hover:underline">
            查看全部
          </Link>
        }
        className="border-border/60"
      >
        <div className="mb-4 flex items-center gap-3 text-xs text-muted-foreground">
          <span>队列积压</span>
          <Progress
            percent={Math.min(100, overview?.queue_backlog ?? 0)}
            size="small"
            showInfo={false}
            strokeColor="hsl(var(--primary))"
            className="max-w-[220px]"
          />
          <span className="font-mono">{overview?.queue_backlog ?? 0}</span>
        </div>
        <Table<SentinelCommit>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={hits}
          loading={hitsQuery.isLoading}
          pagination={false}
          locale={{ emptyText: '还没有命中记录：先添加仓库并触发一次采集' }}
          scroll={{ x: 960 }}
        />
      </Card>
    </div>
  )
}

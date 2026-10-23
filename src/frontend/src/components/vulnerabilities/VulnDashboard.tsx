import { useQuery } from '@tanstack/react-query'
import { vulnApi, VulnStatistics } from '@/api/vulnerabilities'
import { Card, Skeleton, Statistic, Tag } from 'antd'
import { cn, formatDate, getSeverityColor, getStatusColor } from '@/lib/utils'
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Shield,
  TrendingUp,
  Bug,
  Eye,
} from 'lucide-react'
import { Link } from 'react-router-dom'

interface VulnDashboardProps {
  workspaceId?: string
}

export default function VulnDashboard({ workspaceId }: VulnDashboardProps) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['vulnStatistics', workspaceId],
    queryFn: () => vulnApi.getStatistics(workspaceId),
  })

  const stats: VulnStatistics | null = data?.data || null

  if (error) {
    return (
      <div className="text-center py-8 text-destructive">
        加载统计数据失败
      </div>
    )
  }

  const severityCards = [
    {
      key: 'critical',
      label: '严重',
      icon: ShieldX,
      color: 'text-red-500',
    },
    {
      key: 'high',
      label: '高危',
      icon: ShieldAlert,
      color: 'text-orange-500',
    },
    {
      key: 'medium',
      label: '中危',
      icon: AlertTriangle,
      color: 'text-yellow-500',
    },
    {
      key: 'low',
      label: '低危',
      icon: Shield,
      color: 'text-blue-500',
    },
    {
      key: 'info',
      label: '信息',
      icon: ShieldCheck,
      color: 'text-muted-foreground',
    },
  ]

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    }
    return labels[severity] || severity
  }

  const getStatusLabel = (status: string) => {
    const labels: Record<string, string> = {
      open: '待处理',
      confirmed: '已确认',
      fixed: '已修复',
      ignored: '已忽略',
      false_positive: '误报',
    }
    return labels[status] || status
  }

  return (
    <div className="space-y-6">
      {/* 总览卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <Card key={i}>
              <Skeleton loading active title={{ width: 48 }} paragraph={{ rows: 1 }} />
            </Card>
          ))
        ) : (
          severityCards.map((item) => {
            const Icon = item.icon
            const count = stats?.severityCounts?.[item.key as keyof typeof stats.severityCounts] || 0
            const total = stats?.total || 0
            const ratio = total ? Math.round((count / total) * 100) : 0
            return (
              <Card
                key={item.key}
                title={
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">{item.label}漏洞</span>
                    <Icon className={cn('h-4 w-4', item.color)} />
                  </div>
                }
              >
                <Statistic value={count} valueStyle={{ fontSize: '1.5rem', fontWeight: 700 }} />
                <p className="text-xs text-muted-foreground">占比 {ratio}%</p>
              </Card>
            )
          })
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 状态分布 */}
        <Card
          title={
            <div className="flex flex-col gap-1">
              <span className="flex items-center gap-2 text-lg font-semibold">
                <Bug className="h-5 w-5" />
                漏洞状态分布
              </span>
              <span className="text-xs font-normal text-muted-foreground">
                按处理状态统计漏洞数量
              </span>
            </div>
          }
        >
          {isLoading ? (
            <Skeleton loading active title={false} paragraph={{ rows: 5 }} />
          ) : (
            <div className="space-y-3">
              {Object.entries(stats?.statusCounts || {}).map(([status, count]) => {
                const percentage = stats?.total ? Math.round((count / stats.total) * 100) : 0
                return (
                  <div key={status} className="flex items-center gap-4">
                    <Tag
                      className={cn('inline-flex w-20 justify-center', getStatusColor(status))}
                    >
                      {getStatusLabel(status)}
                    </Tag>
                    <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                      <div
                        className={cn(
                          'h-full transition-all',
                          status === 'open' && 'bg-yellow-500',
                          status === 'confirmed' && 'bg-red-500',
                          status === 'fixed' && 'bg-green-500',
                          status === 'ignored' && 'bg-gray-500',
                          status === 'false_positive' && 'bg-blue-500'
                        )}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                    <span className="text-sm font-medium w-12 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          )}
        </Card>

        {/* 最近漏洞 */}
        <Card
          title={
            <div className="flex flex-col gap-1">
              <span className="flex items-center gap-2 text-lg font-semibold">
                <TrendingUp className="h-5 w-5" />
                最新发现
              </span>
              <span className="text-xs font-normal text-muted-foreground">
                最近发现的漏洞
              </span>
            </div>
          }
        >
          {isLoading ? (
            <Skeleton loading active title={false} paragraph={{ rows: 5 }} />
          ) : (
            <div className="space-y-2">
              {(stats?.recentVulnerabilities || []).slice(0, 5).map((vuln) => (
                <Link
                  key={vuln.id}
                  to={`/vulnerabilities/${vuln.id}`}
                  className="flex items-center gap-3 p-2 rounded hover:bg-muted transition-colors"
                >
                  <Tag className={cn('text-xs', getSeverityColor(vuln.severity))}>
                    {getSeverityLabel(vuln.severity)}
                  </Tag>
                  <span className="flex-1 truncate text-sm">{vuln.name}</span>
                  <span className="text-xs text-muted-foreground">
                    {formatDate(vuln.createdAt)}
                  </span>
                  <Eye className="h-4 w-4 text-muted-foreground" />
                </Link>
              ))}
              {(!stats?.recentVulnerabilities || stats.recentVulnerabilities.length === 0) && (
                <div className="text-center py-4 text-muted-foreground">
                  暂无漏洞数据
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* 漏洞趋势图 */}
      {stats?.trend && stats.trend.length > 0 && (
        <Card
          title={
            <div className="flex flex-col gap-1">
              <span className="text-lg font-semibold">漏洞趋势</span>
              <span className="text-xs font-normal text-muted-foreground">最近30天漏洞发现趋势</span>
            </div>
          }
        >
          <div className="h-[200px] flex items-end gap-1">
            {stats.trend.map((item, index) => {
              const maxTotal = Math.max(...stats.trend.map(t => t.total), 1)
              const height = (item.total / maxTotal) * 100
              return (
                <div
                  key={index}
                  className="flex-1 flex flex-col items-center gap-1 group relative"
                >
                  <div
                    className="w-full bg-primary/80 rounded-t hover:bg-primary transition-colors"
                    style={{ height: `${Math.max(height, 2)}%` }}
                  />
                  {/* Tooltip */}
                  <div className="absolute bottom-full mb-2 hidden group-hover:block z-10">
                    <div className="bg-popover text-popover-foreground text-xs p-2 rounded shadow-lg whitespace-nowrap">
                      <div className="font-medium">{item.date}</div>
                      <div>总计: {item.total}</div>
                      {item.critical > 0 && <div className="text-red-500">严重: {item.critical}</div>}
                      {item.high > 0 && <div className="text-orange-500">高危: {item.high}</div>}
                      {item.medium > 0 && <div className="text-yellow-500">中危: {item.medium}</div>}
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
          <div className="flex justify-between text-xs text-muted-foreground mt-2">
            <span>{stats.trend[0]?.date}</span>
            <span>{stats.trend[stats.trend.length - 1]?.date}</span>
          </div>
        </Card>
      )}

      {/* 漏洞类型分布 */}
      {stats?.typeCounts && Object.keys(stats.typeCounts).length > 0 && (
        <Card
          title={
            <div className="flex flex-col gap-1">
              <span className="text-lg font-semibold">漏洞类型分布</span>
              <span className="text-xs font-normal text-muted-foreground">按漏洞类型统计</span>
            </div>
          }
        >
          <div className="flex flex-wrap gap-2">
            {Object.entries(stats.typeCounts)
              .sort((a, b) => b[1] - a[1])
              .slice(0, 20)
              .map(([type, count]) => (
                <Tag key={type} className="text-sm">
                  {type}
                  <span className="ml-1 bg-background px-1.5 py-0.5 rounded text-xs">
                    {count}
                  </span>
                </Tag>
              ))}
          </div>
        </Card>
      )}
    </div>
  )
}

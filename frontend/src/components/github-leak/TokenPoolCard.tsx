import { useQuery } from '@tanstack/react-query'
import { Button, Progress, Table, Tag } from 'antd'
import { KeyRound, RefreshCw } from 'lucide-react'
import { githubTokensApi, type GitHubToken } from '@/api/githubTokens'
import { cn, formatDate } from '@/lib/utils'
import { LEAK_OPS_KEY } from './shared'

/**
 * Token 池配额（只读）：数据源与「系统设置 → GitHub Token 池」完全同源
 * （GET /github-monitor/tokens → service.GitHubTokenStore()），这里只展示
 * 消耗情况，不提供任何配置/写操作；配置入口唯一保留在设置页。
 */
export function TokenPoolCard() {
  const tokensQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'tokens-readonly'],
    queryFn: () => githubTokensApi.listReadOnly(),
    refetchInterval: 60000,
  })
  const tokens = tokensQuery.data?.data?.items ?? []

  const columns = [
    {
      title: '账号',
      key: 'label',
      width: 170,
      render: (_: unknown, t: GitHubToken) => (
        <div className="text-xs">
          <div className="font-medium">{t.label || '未命名'}</div>
          <div className="font-mono text-[10px] text-muted-foreground">{t.masked}</div>
        </div>
      ),
    },
    {
      title: '状态',
      key: 'enabled',
      width: 70,
      render: (_: unknown, t: GitHubToken) => (
        <Tag color={t.enabled ? 'success' : 'default'} className="m-0">
          {t.enabled ? '启用' : '停用'}
        </Tag>
      ),
    },
    {
      title: '剩余配额',
      key: 'rate',
      width: 180,
      render: (_: unknown, t: GitHubToken) => {
        if (!t.enabled || t.rate_remaining < 0) {
          return <span className="text-xs text-muted-foreground">{t.enabled ? '未采集' : '—'}</span>
        }
        return (
          <div className="flex items-center gap-2">
            <Progress
              percent={t.rate_limit ? Math.round((t.rate_remaining / t.rate_limit) * 100) : 0}
              size="small"
              className="w-20 [&_.ant-progress-text]:text-[10px]"
              strokeColor={t.rate_remaining <= 0 ? '#ef4444' : undefined}
            />
            <span className="font-mono text-[10px] text-muted-foreground">
              {t.rate_remaining}/{t.rate_limit}
            </span>
          </div>
        )
      },
    },
    {
      title: '已用',
      key: 'used',
      width: 80,
      render: (_: unknown, t: GitHubToken) => (
        <span className={cn('font-mono text-[11px]', t.rate_used > 0 && 'text-amber-500')}>
          {t.rate_used}
        </span>
      ),
    },
    {
      title: '额度重置',
      key: 'reset',
      width: 135,
      render: (_: unknown, t: GitHubToken) => (
        <span className="text-[10px] text-muted-foreground">
          {t.rate_reset_at ? formatDate(t.rate_reset_at) : '—'}
        </span>
      ),
    },
    {
      title: '最近采集',
      key: 'checked',
      width: 135,
      render: (_: unknown, t: GitHubToken) => (
        <span className="text-[10px] text-muted-foreground">
          {t.last_checked_at ? formatDate(t.last_checked_at) : '—'}
        </span>
      ),
    },
  ]

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4">
      <div className="mb-1 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <KeyRound className="size-4 text-primary" /> Token 池配额（只读）
          <span className="text-xs font-normal text-muted-foreground">共 {tokens.length} 个账号</span>
        </div>
        <Button
          size="small"
          icon={<RefreshCw className="size-3" />}
          loading={tokensQuery.isFetching}
          onClick={() => tokensQuery.refetch()}
        >
          刷新展示
        </Button>
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        平台统一池的配额消耗视图（与系统设置、监控巡查、情报检索共用一份数据）；每 60 秒自动更新，此处不提供配置。
      </p>
      {tokensQuery.isError && (
        <p className="mb-2 text-xs text-destructive">读取配额失败：{(tokensQuery.error as Error)?.message}</p>
      )}
      <Table<GitHubToken>
        rowKey="id"
        size="small"
        tableLayout="fixed"
        columns={columns}
        dataSource={tokens}
        loading={tokensQuery.isLoading}
        pagination={false}
        scroll={{ x: 770 }}
        locale={{ emptyText: '池为空——请到「系统设置 → GitHub Token 池」添加' }}
      />
    </div>
  )
}

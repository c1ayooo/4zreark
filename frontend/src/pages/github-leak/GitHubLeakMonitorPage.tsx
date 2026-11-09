import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Alert, Skeleton, Tag } from 'antd'
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Clock3,
  Gauge,
  Github,
  Inbox,
  ShieldCheck,
} from 'lucide-react'
import { githubMonitorApi } from '@/api/githubMonitor'
import { GlobalFindingsTable } from '@/components/github-leak/GlobalFindingsTable'
import { OpsBar } from '@/components/github-leak/OpsBar'
import { SuppressionCard } from '@/components/github-leak/SuppressionCard'
import { TokenPoolCard } from '@/components/github-leak/TokenPoolCard'
import { LEAK_OPS_KEY } from '@/components/github-leak/shared'
import { useAuthStore } from '@/store/auth'
import { cn, formatDate } from '@/lib/utils'

/**
 * 敏感信息监控（全局）：对应旧项目 4zreco 的「泄露持续监控」。
 * 作用域是全平台一套监控内核，与项目详情页里按项目绑定的「GitHub 监控」是两回事；
 * 两者共用 internal/githubleak，但这里的命中、Token 池、抑制、运维都不过滤项目。
 */
export default function GitHubLeakMonitorPage() {
  // 设置页 /github/tokens 要求 settings:read（operator 无此权限），
  // 故只有 admin 展示「前往配置」链接；operator 只读查看配额消耗。
  const canConfigureTokens = useAuthStore((s) => s.user?.role === 'admin')

  const runtimeQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'runtime'],
    queryFn: () => githubMonitorApi.runtime(),
    refetchInterval: 60000,
  })
  const statsQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'stats'],
    queryFn: () => githubMonitorApi.stats(),
    refetchInterval: 60000,
  })

  const runtime = runtimeQuery.data?.data
  const stats = statsQuery.data?.data
  const loading = runtimeQuery.isLoading || statsQuery.isLoading

  const cards = [
    { label: '命中总数', value: stats?.total ?? 0, icon: Inbox, tone: 'text-sky-500', hint: '全库' },
    { label: '待研判', value: stats?.new ?? 0, icon: AlertOctagon, tone: 'text-amber-500', hint: '需要处理' },
    { label: '已研判', value: stats?.triaged ?? 0, icon: Activity, tone: 'text-indigo-500', hint: '已确认方向' },
    { label: '误报', value: stats?.false_positive ?? 0, icon: ShieldCheck, tone: 'text-orange-500', hint: '已自动静默' },
    { label: '已处置', value: stats?.resolved ?? 0, icon: CheckCircle2, tone: 'text-emerald-500', hint: '闭环' },
    { label: '搜索配额', value: runtime?.rate_remaining ?? 0, icon: Gauge, tone: 'text-cyan-500', hint: runtime?.rate_reset_at ? `重置 ${formatDate(runtime.rate_reset_at)}` : '未采集' },
  ]

  return (
    <div className="space-y-4 p-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <Github className="size-6 text-primary" /> 敏感信息监控
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            全局持续监控 GitHub 公开仓库的凭据泄露；项目维度的开关、Token 与关键词仍在各项目详情页配置。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Tag color={runtime?.running ? 'processing' : runtime?.enabled ? 'success' : 'default'} className="m-0">
            {runtime?.running ? '巡查中' : runtime?.enabled ? '监控中' : '未启用'}
          </Tag>
          <span className="text-xs text-muted-foreground">
            {runtime?.last_run_at ? `上轮 ${formatDate(runtime.last_run_at)}` : '尚未运行'}
            {runtime?.next_run_at ? ` · 下轮 ${formatDate(runtime.next_run_at)}` : ''}
          </span>
        </div>
      </div>

      {(runtime?.last_error || runtime?.last_warning) && (
        <Alert
          type={runtime?.last_error ? 'error' : 'warning'}
          showIcon
          message={runtime?.last_error || runtime?.last_warning}
          className="text-xs"
        />
      )}

      {loading ? (
        <Skeleton active paragraph={{ rows: 4 }} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            {cards.map((c) => (
              <div
                key={c.label}
                className="rounded-xl border border-border bg-gradient-to-br from-card to-card/40 p-3 shadow-sm transition-transform duration-150 hover:-translate-y-0.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">{c.label}</span>
                  <c.icon className={cn('size-4', c.tone)} />
                </div>
                <div className="mt-2 font-mono text-2xl font-semibold tabular-nums">{c.value}</div>
                <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{c.hint}</div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-1 rounded-xl border border-border bg-card/40 px-3 py-2 text-[11px] text-muted-foreground">
            <span className="flex items-center gap-1 font-medium text-foreground">
              <Clock3 className="size-3" /> 运行态
            </span>
            <span>规则 {runtime?.rules?.length ?? 0} 条</span>
            <span>轮询 {runtime?.interval_seconds ?? 0}s</span>
            <span>请求间隔 {runtime?.request_interval_seconds ?? 0}s</span>
            <span>回溯 {runtime?.lookback_days ?? 0} 天</span>
            <span>仓库时效 {runtime?.repo_max_age_days ?? 0} 天</span>
            <span>上轮处理 {runtime?.last_processed ?? 0} / 命中 {runtime?.last_detected ?? 0}</span>
            <span>通知 {runtime?.notify_enabled ? '开' : '关'}</span>
            {runtime?.query && <span className="truncate font-mono">查询：{runtime.query}</span>}
          </div>

          <OpsBar />

          <GlobalFindingsTable />

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border bg-card/40 px-3 py-2 text-[11px] text-muted-foreground">
            <span>
              Token 池为平台统一池，此处仅展示配额消耗；添加、启停与删除统一在「系统设置 → GitHub Token 池」完成。
            </span>
            {canConfigureTokens ? (
              <Link to="/settings?tab=github-tokens" className="text-primary hover:underline">
                前往系统设置配置 →
              </Link>
            ) : (
              <span>配置需管理员权限，当前角色仅可查看</span>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <TokenPoolCard />
            <SuppressionCard />
          </div>
        </>
      )}
    </div>
  )
}

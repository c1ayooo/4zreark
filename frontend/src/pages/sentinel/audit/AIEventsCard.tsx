/**
 * AI 分析过程时间线：把「只有结果」的判定还原成事件流。
 *
 * 数据源 GET /api/sentinel/commits/:id/ai-events，聚合两类批次：
 *   - run_type=judge：判定过程（模型就绪 → 模型判定 → 生成发现 → 判定完成）；
 *   - run_type=artifacts：高危产物流水线（深审 → python-poc → 利用文档 → 自动排队靶场验证）。
 * 事件正序返回；终态（_done/_failed/_skipped）出现后停止轮询。
 * 与靶场验证时间线（PocVerifyCard）同一套样式。
 */
import { useQuery } from '@tanstack/react-query'
import { sentinelApi, type SentinelRunEvent } from '@/api/sentinel'

const STEP_TITLES: Record<string, string> = {
  judge_start: '开始判定',
  judge_model: '判定模型就绪',
  judge_llm_done: '模型判定完成',
  judge_finding: '生成发现',
  judge_done: '判定完成',
  judge_skipped: '跳过判定',
  judge_failed: '判定失败',
  artifacts_start: '高危产物流水线开始',
  artifacts_deep_analysis: '深审报告',
  artifacts_python_poc: 'python-poc',
  artifacts_exploit_guide: '利用方法文档',
  artifacts_poc_verify_enqueued: '自动排队靶场验证',
  artifacts_done: '流水线完成',
  artifacts_failed: '流水线失败',
}

const TERMINAL_RE = /_(done|failed|skipped)$/

function stepState(e: SentinelRunEvent): 'done' | 'fail' | 'info' {
  if (e.level === 'error' || e.kind.endsWith('_failed')) return 'fail'
  if (TERMINAL_RE.test(e.kind) || e.kind === 'judge_finding') return 'done'
  return 'info'
}

function fmtClock(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString()
}

export default function AIEventsCard({ commitId }: { commitId: number }) {
  const q = useQuery({
    queryKey: ['sentinel', 'commit-ai-events', commitId],
    queryFn: () => sentinelApi.commitAIEvents(commitId),
    enabled: commitId > 0,
    refetchInterval: (query) => {
      const events = query.state.data?.events ?? []
      const last = events[events.length - 1]
      return events.length && last && TERMINAL_RE.test(last.kind) ? false : 5000
    },
  })

  const events = q.data?.events ?? []
  if (!events.length) return null

  return (
    <div className="rounded-xl border border-border bg-card px-3 py-2.5">
      <div className="mb-1.5 flex items-center gap-2">
        <span className="text-[12px] font-semibold text-foreground">AI 分析过程</span>
        {q.isFetching && <span className="text-[10px] text-muted-foreground">刷新中…</span>}
      </div>
      <ol className="relative space-y-2 pl-6 before:absolute before:left-[7px] before:top-1.5 before:bottom-1.5 before:w-px before:bg-border">
        {events.map((e, i) => {
          const state = stepState(e)
          return (
            <li key={e.id} className="relative">
              <span
                className={`absolute -left-6 top-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full text-[9px] text-white ${
                  state === 'fail' ? 'bg-destructive' : state === 'done' ? 'bg-primary' : 'bg-muted-foreground/50'
                }`}
              >
                {i + 1}
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-[12px] text-foreground">{STEP_TITLES[e.kind] ?? e.kind}</span>
                <span className="font-mono text-[10px] text-muted-foreground">{fmtClock(e.created_at)}</span>
              </div>
              {e.message && (
                <div className="text-[11px] leading-relaxed text-secondary-foreground">{e.message}</div>
              )}
            </li>
          )
        })}
      </ol>
    </div>
  )
}

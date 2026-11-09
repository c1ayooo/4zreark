/**
 * 代码审计 · 三页共用展示单元
 *
 * 数据全部来自 /api/sentinel/*（api/sentinel.ts），不再有 mock 分支：
 *   分析任务 = 监控仓库 + 采集调度（repo 表）
 *   分析结果 = 提交判定（commit + judgment）
 *   分析产物 = 判定落地的发现（finding）
 */
import type { ReactNode } from 'react'
import { Button, Dropdown } from 'antd'
import { AlertTriangle, ChevronDown, Loader2, RefreshCw } from 'lucide-react'
import type {
  SentinelArtifactStatus,
  SentinelFindingStatus,
  SentinelRepo,
} from '@/api/sentinel'

/* ---------------- 时间 / 数字 ---------------- */

export const fmtTime = (v?: string | null) => {
  if (!v) return '—'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return '—'
  return d.toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export const fmtRelative = (v?: string | null) => {
  if (!v) return '—'
  const t = new Date(v).getTime()
  if (Number.isNaN(t)) return '—'
  const m = Math.round((Date.now() - t) / 60000)
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟前`
  const h = Math.round(m / 60)
  if (h < 24) return `${h} 小时前`
  return `${Math.round(h / 24)} 天前`
}

export const fmtNumber = (n?: number) => (typeof n === 'number' ? n.toLocaleString('zh-CN') : '—')

/* ---------------- 页面骨架 ---------------- */

export function PageHeader({
  title,
  desc,
  actions,
}: {
  title: string
  desc: string
  actions?: ReactNode
}) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-3">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{desc}</p>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  )
}

export function Metric({
  label,
  value,
  hint,
  tone,
}: {
  label: string
  value: string
  hint: string
  tone?: string
}) {
  return (
    <div className="rounded-xl border border-border bg-card px-4 py-3.5">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div
        className={`mt-1.5 text-2xl font-semibold leading-8 tabular-nums ${tone ?? 'text-foreground'}`}
      >
        {value}
      </div>
      <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
    </div>
  )
}

export function EmptyBlock({ children }: { children: ReactNode }) {
  return (
    <div className="rounded-xl border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
      {children}
    </div>
  )
}

/** 接口层面的错误态：区分「没登录 / 后端没起 / 功能未启用」，别只扔一句 failed。 */
export function ErrorPanel({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const err = error as { message?: string; code?: number } | undefined
  const msg = err?.message || '请求失败'
  const disabled = msg.includes('未启用') || msg.includes('sentinel.enabled')
  return (
    <div className="flex flex-wrap items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3.5 py-2.5 dark:border-amber-900/70 dark:bg-amber-950/40">
      <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" />
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-amber-900 dark:text-amber-200">
          {disabled ? '提交哨兵未启用' : '后端不可用'}
        </div>
        <div className="mt-0.5 break-words text-xs text-amber-900/80 dark:text-amber-200/80">{msg}</div>
        <div className="mt-1 text-[11px] text-amber-900/60 dark:text-amber-200/60">
          {disabled
            ? '在 config.yaml 里把 sentinel.enabled 设为 true 并重启 master。'
            : '确认已登录、master（:8080）已启动、数据库可连。'}
        </div>
      </div>
      {onRetry && (
        <Button size="small" icon={<RefreshCw size={12} />} onClick={onRetry} className="!px-2 text-xs">
          重试
        </Button>
      )}
    </div>
  )
}

/* ---------------- 标签 ---------------- */

type Tone = { label: string; cls: string }

const SEVERITY: Record<string, Tone> = {
  critical: { label: 'critical', cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300' },
  high: { label: 'high', cls: 'border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950/50 dark:text-orange-300' },
  medium: { label: 'medium', cls: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-300' },
  low: { label: 'low', cls: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/50 dark:text-sky-300' },
  info: { label: 'info', cls: 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300' },
}

export function SeverityTag({ severity }: { severity: string }) {
  if (!severity) return <span className="text-[10.5px] text-muted-foreground">—</span>
  const m = SEVERITY[severity.toLowerCase()] ?? {
    label: severity,
    cls: 'border-slate-200 bg-slate-50 text-slate-600',
  }
  return (
    <span className={`inline-flex shrink-0 rounded-full border px-1.5 py-0.5 text-[11px] font-medium ${m.cls}`}>
      {m.label}
    </span>
  )
}

const COMMIT_STATUS: Record<string, Tone> = {
  pending: { label: '待判定', cls: 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300' },
  judged: { label: '已判定', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300' },
  skipped: { label: '已跳过', cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400' },
  failed: { label: '失败', cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300' },
}

export function CommitStatusTag({ status }: { status: string }) {
  const m = COMMIT_STATUS[status] ?? {
    label: status || '未知',
    cls: 'border-slate-200 bg-slate-50 text-slate-600',
  }
  return (
    <span className={`inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium ${m.cls}`}>
      {m.label}
    </span>
  )
}

/** 判定结论：安全修复只认后端 is_security_fix，不在这里二次推断。 */
export function VerdictTag({ judged, isSecurityFix }: { judged: boolean; isSecurityFix: boolean }) {
  if (!judged) {
    return (
      <span className="inline-flex shrink-0 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400">
        待判定
      </span>
    )
  }
  return isSecurityFix ? (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-sky-200 bg-sky-50 px-2 py-0.5 text-[11px] font-medium text-sky-700 dark:border-sky-900 dark:bg-sky-950/50 dark:text-sky-300">
      安全修复
    </span>
  ) : (
    <span className="inline-flex shrink-0 rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-medium text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300">
      非安全修复
    </span>
  )
}

const FINDING_STATUS: Record<string, Tone> = {
  open: { label: '待处理', cls: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-300' },
  confirmed: { label: '已确认', cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300' },
  ignored: { label: '已忽略', cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400' },
  resolved: { label: '已处置', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300' },
}

export function FindingStatusTag({ status }: { status: string }) {
  const m = FINDING_STATUS[status] ?? {
    label: status || '未知',
    cls: 'border-slate-200 bg-slate-50 text-slate-600',
  }
  return (
    <span className={`inline-flex shrink-0 rounded-full border px-1.5 py-0.5 text-[11px] font-medium ${m.cls}`}>
      {m.label}
    </span>
  )
}

/** 发现状态流转：当前状态渲染 FindingStatusTag，点开切换到其余三个状态（合法性由后端校验） */
export function FindingStatusSelect({
  status,
  onChange,
  loading,
}: {
  status: string
  onChange: (next: SentinelFindingStatus) => void
  loading?: boolean
}) {
  const items = Object.entries(FINDING_STATUS)
    .filter(([value]) => value !== status)
    .map(([value, tone]) => ({ key: value, label: tone.label }))
  return (
    <Dropdown
      menu={{ items, onClick: ({ key }) => onChange(key as SentinelFindingStatus) }}
      disabled={loading}
      trigger={['click']}
    >
      <button
        type="button"
        disabled={loading}
        className="inline-flex shrink-0 cursor-pointer items-center gap-0.5 disabled:cursor-default disabled:opacity-60"
      >
        <FindingStatusTag status={status} />
        {loading ? (
          <Loader2 size={11} className="animate-spin text-muted-foreground" />
        ) : (
          <ChevronDown size={11} className="text-muted-foreground" />
        )}
      </button>
    </Dropdown>
  )
}

const ARTIFACT_STATUS: Record<string, Tone> = {
  draft: { label: '草稿', cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400' },
  pending_review: { label: '待审核', cls: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/50 dark:text-sky-300' },
  verified: { label: '已验证', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300' },
  rejected: { label: '已驳回', cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300' },
  deprecated: { label: '已废弃', cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400' },
}

export const ARTIFACT_STATUS_LABELS: Record<string, string> = Object.fromEntries(
  Object.entries(ARTIFACT_STATUS).map(([value, tone]) => [value, tone.label]),
)

/** 产物状态机的合法流向（前端选项口径，后端仍做枚举校验） */
export const ARTIFACT_NEXT: Record<string, SentinelArtifactStatus[]> = {
  draft: ['pending_review'],
  pending_review: ['verified', 'rejected'],
  verified: ['deprecated'],
  rejected: ['deprecated'],
  deprecated: [],
}

export function ArtifactStatusTag({ status }: { status: string }) {
  const m = ARTIFACT_STATUS[status] ?? {
    label: status || '未知',
    cls: 'border-slate-200 bg-slate-50 text-slate-600',
  }
  return (
    <span className={`inline-flex shrink-0 rounded-full border px-1.5 py-0.5 text-[11px] font-medium ${m.cls}`}>
      {m.label}
    </span>
  )
}

/** 产物状态流转：当前状态渲染 ArtifactStatusTag，点开只给合法流向选项 */
export function ArtifactStatusSelect({
  status,
  onChange,
  loading,
}: {
  status: string
  onChange: (next: SentinelArtifactStatus) => void
  loading?: boolean
}) {
  const items = (ARTIFACT_NEXT[status] ?? []).map((value) => ({
    key: value,
    label: ARTIFACT_STATUS_LABELS[value] ?? value,
  }))
  return (
    <Dropdown
      menu={{ items, onClick: ({ key }) => onChange(key as SentinelArtifactStatus) }}
      disabled={loading || items.length === 0}
      trigger={['click']}
    >
      <button
        type="button"
        disabled={loading}
        className="inline-flex shrink-0 cursor-pointer items-center gap-0.5 disabled:cursor-default disabled:opacity-60"
      >
        <ArtifactStatusTag status={status} />
        {loading ? (
          <Loader2 size={11} className="animate-spin text-muted-foreground" />
        ) : (
          <ChevronDown size={11} className="text-muted-foreground" />
        )}
      </button>
    </Dropdown>
  )
}

/** 仓库健康：优先暴露 last_error，其次区分「从未采集」和「正常」。 */
export function repoHealth(repo: SentinelRepo): { label: string; cls: string; hint: string } {
  if (repo.last_error) {
    return {
      label: '采集失败',
      cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300',
      hint: repo.last_error,
    }
  }
  if (!repo.enabled) {
    return {
      label: '已停用',
      cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400',
      hint: '停用后不再进入调度',
    }
  }
  if (!repo.last_checked_at) {
    return {
      label: '待首次采集',
      cls: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/50 dark:text-amber-300',
      hint: '已入调度，等待 worker 拉取',
    }
  }
  return {
    label: '正常',
    cls: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300',
    hint: `上次采集 ${fmtRelative(repo.last_checked_at)}`,
  }
}

export function RepoHealthTag({ repo }: { repo: SentinelRepo }) {
  const h = repoHealth(repo)
  return (
    <span
      className={`inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-medium ${h.cls}`}
      title={h.hint}
    >
      {h.label}
    </span>
  )
}

/** 置信度：数字 + 细条，避免 0.62 这种数字靠脑补。 */
export function ConfidenceBar({ value }: { value?: number }) {
  if (typeof value !== 'number' || Number.isNaN(value)) {
    return <span className="text-[10.5px] text-muted-foreground">—</span>
  }
  const pct = Math.max(0, Math.min(100, Math.round(value * 100)))
  const tone = pct >= 80 ? 'bg-emerald-500' : pct >= 50 ? 'bg-amber-500' : 'bg-rose-500'
  return (
    <div className="flex min-w-[72px] items-center gap-1.5">
      <span className="h-1 w-10 overflow-hidden rounded-full bg-border">
        <span className={`block h-full ${tone}`} style={{ width: `${pct}%` }} />
      </span>
      <span className="font-mono text-[10.5px] tabular-nums text-secondary-foreground">{pct}%</span>
    </div>
  )
}

export const RUN_STATUS_META: Record<string, Tone> = {
  running: { label: '运行中', cls: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/50 dark:text-sky-300' },
  succeeded: { label: '成功', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/50 dark:text-emerald-300' },
  failed: { label: '失败', cls: 'border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/50 dark:text-rose-300' },
  pending: { label: '排队中', cls: 'border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-300' },
}

const GRADE_TAG: Record<string, { label: string; cls: string }> = {
  S: { label: 'S', cls: 'border-fuchsia-300 bg-fuchsia-50 text-fuchsia-700 dark:border-fuchsia-900 dark:bg-fuchsia-950/50 dark:text-fuchsia-300' },
  A: { label: 'A', cls: 'border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950/50 dark:text-orange-300' },
  B: { label: 'B', cls: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/50 dark:text-sky-300' },
  C: { label: 'C', cls: 'border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-700 dark:bg-slate-800/60 dark:text-slate-400' },
}

export function FindingGradeTag({ grade }: { grade: string }) {
  if (!grade) return null
  const m = GRADE_TAG[grade] ?? { label: grade, cls: 'border-slate-200 bg-slate-50 text-slate-600' }
  return (
    <span className={`inline-flex shrink-0 rounded-full border px-1.5 py-0.5 text-[11px] font-medium ${m.cls}`}>
      {m.label}
    </span>
  )
}

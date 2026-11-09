/**
 * 对话页共享渲染层：块推导 + 各风格共用的块组件
 *
 * 所有配色只使用项目 token（src/index.css）：
 *   bg-background / bg-card / bg-secondary / bg-muted / bg-accent
 *   text-foreground / text-muted-foreground / text-primary / text-destructive
 *   border-border / ring-ring
 * 不出现任何具体色值，明暗主题随 .dark 变量自动切换。
 */
import { useState } from 'react'
import type { RunEvent } from './mockRuns'
import { formatSize } from './mockRuns'
import type { PlaybackStatus } from './useRunPlayback'
import {
  Activity, Bot, Brain, ChevronDown, Database, FileArchive, FileText, Search,
  ShieldAlert, ShieldCheck, ShieldX, Sparkles, Terminal, Zap,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

/* ================= 块推导（与协议无关的展示模型） ================= */

export type Block =
  | { kind: 'text'; key: string; text: string; done: boolean }
  | { kind: 'thinking'; key: string; text: string }
  /** 上下文注入行：上传附件 / 加载 skill（不是模型输出，属于 run 的输入侧） */
  | { kind: 'notice'; key: string; text: string; tone: 'file' | 'skill' }
  | {
      kind: 'tool'
      key: string
      callId: string
      name: string
      args: Record<string, unknown>
      status: 'running' | 'ok' | 'error' | 'awaiting' | 'approved' | 'rejected'
      result?: Record<string, unknown>
    }
  | { kind: 'done'; key: string; usage?: { in: number; out: number } }
  | { kind: 'finished'; key: string; status: string; tokens?: { in: number; out: number } }

export function deriveBlocks(events: RunEvent[]): Block[] {
  const blocks: Block[] = []
  const toolIdx = new Map<string, number>()
  for (const ev of events) {
    const p = ev.payload
    switch (ev.type) {
      case 'file.uploaded': {
        blocks.push({
          kind: 'notice',
          key: `n${ev.seq}`,
          tone: 'file',
          text: `已接收附件 ${String(p.name)} · ${formatSize(Number(p.size))}${p.files ? ` · 解析出 ${p.files} 个文件` : ''}`,
        })
        break
      }
      case 'skill.loaded': {
        blocks.push({
          kind: 'notice',
          key: `n${ev.seq}`,
          tone: 'skill',
          text: `已加载 skill ${String(p.name)} ${String(p.version)} · 注入 ${p.checks} 项检查`,
        })
        break
      }
      case 'thinking.delta': {
        const last = blocks[blocks.length - 1]
        if (last && last.kind === 'thinking') last.text += String(p.delta)
        else blocks.push({ kind: 'thinking', key: `t${ev.seq}`, text: String(p.delta) })
        break
      }
      case 'message.delta': {
        const last = blocks[blocks.length - 1]
        if (last && last.kind === 'text' && !last.done) last.text += String(p.delta)
        else blocks.push({ kind: 'text', key: `m${ev.seq}`, text: String(p.delta), done: false })
        break
      }
      case 'tool.call':
      case 'approval.required': {
        const b: Block = {
          kind: 'tool',
          key: `c${String(p.call_id)}`,
          callId: String(p.call_id),
          name: String(p.name),
          args: (p.args ?? {}) as Record<string, unknown>,
          status: ev.type === 'approval.required' ? 'awaiting' : 'running',
        }
        toolIdx.set(String(p.call_id), blocks.length)
        blocks.push(b)
        break
      }
      case 'approval.resolved': {
        const i = toolIdx.get(String(p.call_id))
        if (i !== undefined && blocks[i].kind === 'tool') blocks[i].status = p.decision === 'approved' ? 'approved' : 'rejected'
        break
      }
      case 'tool.result': {
        const i = toolIdx.get(String(p.call_id))
        if (i !== undefined && blocks[i].kind === 'tool') {
          blocks[i].status = p.ok ? 'ok' : 'error'
          blocks[i].result = p
        }
        break
      }
      case 'message.done': {
        const last = blocks[blocks.length - 1]
        if (last && last.kind === 'text') last.done = true
        blocks.push({ kind: 'done', key: `d${ev.seq}`, usage: p.usage as { in: number; out: number } | undefined })
        break
      }
      case 'run.finished':
        blocks.push({ kind: 'finished', key: `f${ev.seq}`, status: String(p.status), tokens: p.tokens as { in: number; out: number } | undefined })
        break
    }
  }
  return blocks
}

/* ================= 事件类型元数据（token 类名，无硬编码色值） ================= */

export const TYPE_META: Record<string, { label: string; cls: string; dot: string; icon: LucideIcon }> = {
  'run.started': { label: '运行开始', cls: 'text-muted-foreground', dot: 'bg-muted-foreground', icon: Activity },
  'file.uploaded': { label: '附件接收', cls: 'text-foreground', dot: 'bg-primary', icon: FileArchive },
  'skill.loaded': { label: 'Skill 注入', cls: 'text-accent-foreground', dot: 'bg-accent-foreground', icon: Sparkles },
  'thinking.delta': { label: '思考', cls: 'text-muted-foreground', dot: 'bg-muted-foreground/60', icon: Brain },
  'message.delta': { label: '回复', cls: 'text-foreground', dot: 'bg-foreground', icon: Bot },
  'tool.call': { label: '工具调用', cls: 'text-foreground', dot: 'bg-primary', icon: Terminal },
  'tool.result': { label: '工具结果', cls: 'text-primary', dot: 'bg-primary', icon: Terminal },
  'approval.required': { label: '待审批', cls: 'text-accent-foreground', dot: 'bg-accent-foreground', icon: ShieldAlert },
  'approval.resolved': { label: '审批决策', cls: 'text-primary', dot: 'bg-primary', icon: ShieldCheck },
  'message.done': { label: '回复完成', cls: 'text-muted-foreground', dot: 'bg-muted-foreground/50', icon: Bot },
  'run.finished': { label: '运行结束', cls: 'text-primary', dot: 'bg-primary', icon: Activity },
  heartbeat: { label: '心跳', cls: 'text-muted-foreground/60', dot: 'bg-muted-foreground/30', icon: Zap },
}

export const TOOL_ICON: Record<string, LucideIcon> = {
  read_file: FileText,
  grep: Search,
  list_files: Database,
  run_bash: Terminal,
  submit_finding: ShieldCheck,
}

export function eventSummary(ev: RunEvent): string {
  const p = ev.payload as Record<string, string | number | boolean | undefined>
  if (ev.type === 'tool.call' || ev.type === 'approval.required') {
    const args = (p.args ?? {}) as Record<string, unknown>
    const parts = Object.entries(args).map(([k, v]) =>
      `${k}=${typeof v === 'string' ? `"${v.length > 44 ? v.slice(0, 44) + '…' : v}"` : v}`)
    return `${String(p.name)}(${parts.join(', ')})`
  }
  if (ev.type === 'tool.result') {
    if (p.ok) return `ok · ${p.duration_ms}ms${p.preview ? ` · ${String(p.preview).split('\n')[0].slice(0, 48)}` : ''}`
    return `失败 · ${String(p.error)}`
  }
  if (ev.type === 'approval.resolved') return `${String(p.call_id)} → ${p.decision === 'approved' ? '通过' : '拒绝'}`
  if (ev.type === 'message.delta') return String(p.delta ?? '').slice(0, 56)
  if (ev.type === 'run.started') return `run ${String(p.run_id)} · conv ${String(p.conversation_id)}`
  if (ev.type === 'file.uploaded') return `${String(p.name)} · ${formatSize(Number(p.size))}${p.files ? ` · ${p.files} files` : ''}`
  if (ev.type === 'skill.loaded') return `${String(p.name)} ${String(p.version)} · ${p.checks} 项检查`
  if (ev.type === 'run.finished') return `status=${String(p.status)}`
  if (ev.type === 'heartbeat') return 'keep-alive'
  return JSON.stringify(p).slice(0, 56)
}

/* ================= 状态 ================= */

export const STATUS_META: Record<PlaybackStatus, { label: string; cls: string; dot: string }> = {
  idle: { label: '准备中', cls: 'text-muted-foreground bg-muted', dot: 'bg-muted-foreground' },
  running: { label: '运行中', cls: 'text-primary bg-accent', dot: 'bg-primary animate-pulse' },
  'awaiting-approval': { label: '待审批', cls: 'text-accent-foreground bg-accent', dot: 'bg-accent-foreground animate-pulse' },
  finished: { label: '已完成', cls: 'text-secondary-foreground bg-secondary', dot: 'bg-primary' },
}

export function StatusPill({ status, compact = false }: { status: PlaybackStatus; compact?: boolean }) {
  const m = STATUS_META[status]
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${m.cls} ${compact ? 'px-1.5' : ''}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  )
}

/* ================= 消息块：tone 决定视觉语言 ================= */

export type Tone = 'card' | 'plain' | 'mono' | 'dense' | 'axis'

export function ThinkingBlock({ text, tone }: { text: string; tone: Tone }) {
  const [open, setOpen] = useState(true)
  const head = (
    <button className="flex w-full items-center gap-1.5 text-left" onClick={() => setOpen((o) => !o)}>
      <Brain size={12} className="text-muted-foreground" />
      <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">thinking</span>
      <ChevronDown size={12} className={`ml-auto text-muted-foreground/60 transition-transform ${open ? 'rotate-180' : ''}`} />
    </button>
  )
  const body = open && (
    <p className={`mt-1.5 text-[12.5px] leading-relaxed text-muted-foreground ${tone === 'mono' ? 'font-mono' : ''}`}>
      {text}
      <span className="ml-0.5 inline-block h-3 w-1 animate-pulse bg-muted-foreground/40 align-middle" />
    </p>
  )
  if (tone === 'plain' || tone === 'axis') {
    return <div className="border-l border-border pl-3">{head}{body}</div>
  }
  if (tone === 'mono') {
    return <div className="border-l-2 border-border pl-3">{head}{body}</div>
  }
  return (
    <div className={`rounded-xl border border-border bg-muted/40 ${tone === 'dense' ? 'px-2.5 py-1.5' : 'px-3 py-2'}`}>
      {head}{body}
    </div>
  )
}

export function TextBlock({ text, done, tone }: { text: string; done: boolean; tone: Tone }) {
  const caret = !done && <span className="ml-0.5 inline-block h-3.5 w-1 animate-pulse bg-primary align-middle" />
  if (tone === 'plain') {
    return <p className="whitespace-pre-wrap text-[14px] leading-[1.8] text-foreground">{text}{caret}</p>
  }
  if (tone === 'mono') {
    return <p className="whitespace-pre-wrap font-mono text-[13px] leading-relaxed text-foreground">{text}{caret}</p>
  }
  if (tone === 'axis') {
    return <p className="whitespace-pre-wrap text-[14px] leading-[1.8] text-foreground">{text}{caret}</p>
  }
  return (
    <div className={`border border-border bg-card text-[13.5px] leading-relaxed text-card-foreground ${tone === 'dense' ? 'rounded-md px-3 py-2' : 'rounded-2xl rounded-tl-sm px-4 py-2.5'}`}>
      {text}{caret}
    </div>
  )
}

export function UserBubble({ text, tone }: { text: string; tone: Tone }) {
  if (tone === 'plain' || tone === 'axis') {
    return <div className="text-[14px] leading-relaxed text-foreground">{text}</div>
  }
  if (tone === 'mono') {
    return <div className="border-l-2 border-primary pl-3 font-mono text-[13px] leading-relaxed text-foreground">{text}</div>
  }
  return (
    <div className={`bg-primary text-[13.5px] leading-relaxed text-primary-foreground ${tone === 'dense' ? 'rounded-md px-3 py-2' : 'rounded-2xl rounded-br-sm px-4 py-2.5'}`}>
      {text}
    </div>
  )
}

/* ================= 工具卡 ================= */

const TOOL_STATUS: Record<string, { label: string; cls: string }> = {
  running: { label: '执行中', cls: 'bg-secondary text-secondary-foreground' },
  ok: { label: '完成', cls: 'bg-accent text-accent-foreground' },
  error: { label: '失败', cls: 'bg-destructive/10 text-destructive' },
  awaiting: { label: '待审批', cls: 'bg-accent text-accent-foreground' },
  approved: { label: '已批准', cls: 'bg-accent text-accent-foreground' },
  rejected: { label: '已拒绝', cls: 'bg-destructive/10 text-destructive' },
}

export function ToolCard({
  block, pending, onApprove, tone,
}: {
  block: Extract<Block, { kind: 'tool' }>
  pending: boolean
  onApprove: (d: 'approved' | 'rejected') => void
  tone: Tone
}) {
  const [open, setOpen] = useState(false)
  const Icon = TOOL_ICON[block.name] ?? Terminal
  const sm = TOOL_STATUS[block.status]
  const awaiting = block.status === 'awaiting'

  const shell =
    tone === 'plain' || tone === 'axis'
      ? 'border-l border-border pl-3'
      : tone === 'mono'
        ? 'border-l-2 border-border pl-3'
        : tone === 'dense'
          ? `rounded-md border bg-card px-2.5 py-2 ${awaiting ? 'border-accent-foreground/30' : 'border-border'}`
          : `rounded-xl border bg-card px-3 py-2 ${awaiting ? 'border-accent-foreground/30' : 'border-border'}`

  return (
    <div className={shell}>
      <button className="flex w-full items-center gap-2 text-left" onClick={() => setOpen((o) => !o)}>
        <Icon size={13} className="shrink-0 text-muted-foreground" />
        <span className={`text-[12px] font-medium text-foreground ${tone === 'mono' ? 'font-mono' : ''}`}>{block.name}</span>
        <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium ${sm.cls}`}>{sm.label}</span>
        {block.result?.duration_ms != null && (
          <span className="font-mono text-[10px] text-muted-foreground">{Number(block.result.duration_ms)}ms</span>
        )}
        <ChevronDown size={12} className={`ml-auto text-muted-foreground/60 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="mt-2 space-y-1.5">
          <pre className="m-0 max-h-24 overflow-auto rounded-md bg-muted px-2 py-1.5 font-mono text-[10.5px] leading-relaxed text-muted-foreground whitespace-pre-wrap">
            {JSON.stringify(block.args, null, 2)}
          </pre>
          {block.result && (block.result.preview || block.result.error) ? (
            <pre className={`m-0 max-h-36 overflow-auto rounded-md px-2 py-1.5 font-mono text-[10.5px] leading-relaxed whitespace-pre-wrap ${block.result.error ? 'bg-destructive/5 text-destructive' : 'bg-muted text-secondary-foreground'}`}>
              {block.result.error ? String(block.result.error) : String(block.result.preview)}
            </pre>
          ) : null}
        </div>
      )}

      {awaiting && pending && (
        <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-border pt-2">
          <span className="text-[11px] text-muted-foreground">run 已挂起：</span>
          <button onClick={() => onApprove('approved')} className="inline-flex items-center gap-1 rounded-full bg-primary px-2.5 py-1 text-[11px] font-medium text-primary-foreground hover:opacity-90">
            <ShieldCheck size={12} /> 通过
          </button>
          <button onClick={() => onApprove('rejected')} className="inline-flex items-center gap-1 rounded-full border border-border bg-card px-2.5 py-1 text-[11px] font-medium text-destructive hover:bg-destructive/5">
            <ShieldX size={12} /> 拒绝
          </button>
        </div>
      )}
    </div>
  )
}

/* ================= 事件流列表 ================= */

export function EventList({
  played, tone, className = '',
}: {
  played: RunEvent[]
  tone: 'rows' | 'dense' | 'mono'
  className?: string
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [filter, setFilter] = useState<string | null>(null)

  const types = Array.from(new Set(played.map((e) => e.type)))
  const shown = filter ? played.filter((e) => e.type === filter) : played

  return (
    <div className={`flex min-h-0 flex-col ${className}`}>
      <div className="flex flex-wrap gap-1 border-b border-border px-3 py-2">
        <button
          onClick={() => setFilter(null)}
          className={`rounded-full px-1.5 py-0.5 text-[10px] ${filter === null ? 'bg-secondary text-secondary-foreground' : 'text-muted-foreground hover:bg-muted'}`}
        >
          全部 ×{played.length}
        </button>
        {types.map((t) => {
          const meta = TYPE_META[t]
          return (
            <button
              key={t}
              onClick={() => setFilter(filter === t ? null : t)}
              className={`flex items-center gap-1 rounded-full px-1.5 py-0.5 text-[10px] ${filter === t ? 'bg-secondary text-secondary-foreground' : 'text-muted-foreground hover:bg-muted'}`}
            >
              <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
              {meta.label} ×{played.filter((e) => e.type === t).length}
            </button>
          )
        })}
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {shown.map((e, i) => {
          const meta = TYPE_META[e.type] ?? TYPE_META.heartbeat
          const isErr = e.type === 'tool.result' && e.payload.ok === false
          const key = `${e.seq}-${i}`
          const open = expanded.has(i)
          return (
            <div key={key} className={tone === 'mono' ? 'border-b border-border/60 px-2 py-1' : 'border-b border-border/50 px-3 py-1.5'}>
              <button
                className="flex w-full items-center gap-2 text-left"
                onClick={() => setExpanded((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n })}
              >
                <span className="w-8 shrink-0 font-mono text-[10px] text-muted-foreground/70">#{e.seq}</span>
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${isErr ? 'bg-destructive' : meta.dot}`} />
                <span className={`shrink-0 text-[10.5px] font-medium ${isErr ? 'text-destructive' : meta.cls}`}>{isErr ? '工具失败' : meta.label}</span>
                <span className="truncate font-mono text-[10.5px] text-muted-foreground">{eventSummary(e)}</span>
              </button>
              {open && (
                <pre className="mt-1 max-h-32 overflow-auto rounded-md bg-muted px-2 py-1.5 font-mono text-[10px] leading-relaxed text-muted-foreground whitespace-pre-wrap">
                  {JSON.stringify(e.payload, null, 2)}
                </pre>
              )}
            </div>
          )
        })}
        {shown.length === 0 && <div className="px-3 py-6 text-center text-[11px] text-muted-foreground">暂无事件</div>}
      </div>
    </div>
  )
}

/**
 * 对话页 5 种视觉风格（同一份事件流内容，仅视觉语言不同）
 *
 * 全部配色取自项目 token（src/index.css）：primary 为绿色强调，border 为发丝线，
 * 卡片圆角默认 1rem（--radius），暗色风格通过 .dark 变量组切换。
 */
import { useEffect, useRef } from 'react'
import type { Scenario, RunEvent } from './mockRuns'
import type { PlaybackStatus } from './useRunPlayback'
import type { Block, Tone } from './parts'
import { EventList, StatusPill, TextBlock, ThinkingBlock, ToolCard, UserBubble } from './parts'
import {
  Boxes, Brain, FileArchive, FileText, Network, Play, Send, ShieldCheck, Sparkles, Terminal,
} from 'lucide-react'

export interface StyleProps {
  scenario: Scenario
  blocks: Block[]
  played: RunEvent[]
  status: PlaybackStatus
  pendingApproval: string | null
  onResolve: (d: 'approved' | 'rejected') => void
  tokens?: { in: number; out: number }
}

function useAutoScroll(dep: unknown) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: 'smooth' })
  }, [dep])
  return ref
}

function Blocks({ blocks, tone, pending, onResolve }: { blocks: Block[]; tone: Tone; pending: string | null; onResolve: StyleProps['onResolve'] }) {
  return (
    <>
      {blocks.map((b) => {
        if (b.kind === 'notice') {
          return (
            <div key={b.key} className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
              {b.tone === 'skill' ? <Sparkles size={11} className="text-accent-foreground" /> : <FileArchive size={11} className="text-primary" />}
              {b.text}
            </div>
          )
        }
        if (b.kind === 'thinking') return <ThinkingBlock key={b.key} text={b.text} tone={tone} />
        if (b.kind === 'text') return <TextBlock key={b.key} text={b.text} done={b.done} tone={tone} />
        if (b.kind === 'tool') {
          return (
            <div key={b.key} className={tone === 'plain' || tone === 'axis' ? '' : 'ml-7 max-w-[92%]'}>
              <ToolCard block={b} pending={pending === b.callId} onApprove={onResolve} tone={tone} />
            </div>
          )
        }
        if (b.kind === 'done') {
          return (
            <div key={b.key} className="flex items-center gap-2 text-[10.5px] text-muted-foreground/70">
              <span className="h-px w-6 bg-border" />
              message.done{b.usage ? ` · in ${b.usage.in} / out ${b.usage.out}` : ''}
            </div>
          )
        }
        return (
          <div key={b.key} className="flex items-center gap-2">
            <span className="rounded-full bg-accent px-2 py-0.5 text-[10.5px] font-medium text-accent-foreground">
              run.finished · {b.status}
            </span>
            {b.tokens && <span className="font-mono text-[10.5px] text-muted-foreground">in {b.tokens.in} / out {b.tokens.out}</span>}
          </div>
        )
      })}
    </>
  )
}

function TokenBadge({ tokens }: { tokens?: { in: number; out: number } }) {
  if (!tokens) return null
  return <span className="font-mono text-[10.5px] text-muted-foreground">{(tokens.in / 1000).toFixed(1)}k in / {(tokens.out / 1000).toFixed(1)}k out</span>
}

/* ================================================================
 * 风格 1 · 轻线卡片（项目默认语言：白卡 + 发丝线 + 绿色仅作强调）
 * ================================================================ */
export function StyleClassic(p: StyleProps) {
  const scrollRef = useAutoScroll(p.played.length)
  return (
    <div className="flex h-full min-h-0 bg-background">
      <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-card md:flex">
        <div className="border-b border-border px-4 py-3">
          <div className="text-[13px] font-semibold text-card-foreground">{p.scenario.title}</div>
          <div className="mt-1 flex items-center gap-1.5">
            <span className="rounded-full bg-accent px-1.5 py-0.5 text-[10px] font-medium text-accent-foreground">{p.scenario.modeLabel}</span>
            <StatusPill status={p.status} />
          </div>
        </div>
        <div className="space-y-4 overflow-auto px-4 py-3">
          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">上下文</div>
            <div className="rounded-xl border border-border bg-background px-2.5 py-2">
              <div className="text-[11.5px] font-medium text-foreground">{p.scenario.context.label}</div>
              <pre className="m-0 mt-1 whitespace-pre-wrap font-mono text-[10.5px] leading-relaxed text-muted-foreground">{p.scenario.context.summary}</pre>
            </div>
          </section>
          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">工具权限</div>
            {[['read_file / grep', true], ['run_bash（审批）', true], ['submit_finding', true]].map(([label, on]) => (
              <div key={String(label)} className="flex items-center gap-2 py-0.5 text-[11.5px] text-secondary-foreground">
                <span className={`h-3 w-3 rounded ${on ? 'bg-primary' : 'bg-muted'}`} />{label}
              </div>
            ))}
          </section>
          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">执行环境</div>
            <pre className="m-0 rounded-xl border border-border bg-background px-2.5 py-2 font-mono text-[10px] leading-relaxed text-muted-foreground">{`sentinel/agent:1
--network none
--memory 2g --cpus 2`}</pre>
          </section>
        </div>
      </aside>

      <main className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b border-border px-5 py-2.5">
          <span className="text-[13px] font-medium text-foreground">{p.scenario.title}</span>
          <span className="text-[11px] text-muted-foreground">{p.scenario.desc}</span>
          <div className="ml-auto flex items-center gap-2">
            <TokenBadge tokens={p.tokens} />
            <StatusPill status={p.status} />
          </div>
        </div>
        <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-auto px-5 py-4">
          <div className="rounded-xl border border-dashed border-border px-3 py-2">
            <div className="text-[10px] text-muted-foreground">系统上下文 · {p.scenario.context.label}</div>
          </div>
          <div className="flex justify-end"><div className="max-w-[78%]"><UserBubble text={p.scenario.question} tone="card" /></div></div>
          <Blocks blocks={p.blocks} tone="card" pending={p.pendingApproval} onResolve={p.onResolve} />
        </div>
        <div className="border-t border-border px-5 py-3">
          <div className="flex items-center gap-2 rounded-full border border-border bg-card px-4 py-2">
            <input disabled placeholder="Demo 回放 · 生产环境支持多轮对话与附件" className="min-w-0 flex-1 bg-transparent text-[13px] text-muted-foreground outline-none" />
            <button disabled className="flex h-7 w-7 items-center justify-center rounded-full bg-primary/40 text-primary-foreground"><Send size={13} /></button>
          </div>
        </div>
      </main>

      <aside className="hidden w-[360px] shrink-0 flex-col border-l border-border bg-card lg:flex">
        <div className="border-b border-border px-3 py-2 text-[11px] font-medium text-card-foreground">
          事件流 <span className="ml-1 font-mono text-[10px] text-muted-foreground">{p.played.length}</span>
        </div>
        <EventList played={p.played} tone="rows" />
      </aside>
    </div>
  )
}

/* ================================================================
 * 风格 2 · 终端（暗色 token 组 + 全等宽 + 单色层级）
 * ================================================================ */
export function StyleTerminal(p: StyleProps) {
  const scrollRef = useAutoScroll(p.played.length)
  return (
    <div className="dark flex h-full min-h-0 bg-background font-mono text-foreground">
      <main className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-3 border-b border-border px-4 py-2 text-[11px]">
          <span className="text-primary">●</span>
          <span className="text-foreground">sentinel@{`{agent}`}</span>
          <span className="text-muted-foreground">run 1031 · audit</span>
          <StatusPill status={p.status} compact />
          <span className="ml-auto text-muted-foreground"><TokenBadge tokens={p.tokens} /></span>
        </div>

        <div ref={scrollRef} className="min-h-0 flex-1 space-y-2.5 overflow-auto px-4 py-3 text-[13px]">
          <div className="text-muted-foreground">
            <span className="text-primary">#</span> context · {p.scenario.context.label}
          </div>
          <div className="pl-2"><UserBubble text={p.scenario.question} tone="mono" /></div>
          <Blocks blocks={p.blocks} tone="mono" pending={p.pendingApproval} onResolve={p.onResolve} />
        </div>

        <div className="flex items-center gap-2 border-t border-border px-4 py-2.5 text-[13px]">
          <span className="text-primary">❯</span>
          <input disabled placeholder="等待输入（demo 回放）" className="min-w-0 flex-1 bg-transparent text-muted-foreground outline-none" />
          <span className="text-[10px] text-muted-foreground">manual · 30 calls · 10m</span>
        </div>
      </main>

      <aside className="hidden w-[340px] shrink-0 flex-col border-l border-border bg-card md:flex">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-[10.5px] text-muted-foreground">
          <Terminal size={12} /><span className="text-foreground">event stream</span>
          <span className="ml-auto">{p.played.length} ev</span>
        </div>
        <EventList played={p.played} tone="mono" />
      </aside>
    </div>
  )
}

/* ================================================================
 * 风格 3 · 极简（去卡片、去边框、大留白，只靠排版与留白分层）
 * ================================================================ */
export function StyleMinimal(p: StyleProps) {
  const scrollRef = useAutoScroll(p.played.length)
  return (
    <div className="flex h-full min-h-0 flex-col bg-background">
      <div className="mx-auto flex w-full max-w-6xl items-center gap-3 px-8 py-5">
        <span className="text-[15px] font-medium tracking-tight text-foreground">{p.scenario.title}</span>
        <span className="text-[11px] text-muted-foreground">{p.scenario.modeLabel} · {p.scenario.context.kind}</span>
        <div className="ml-auto flex items-center gap-3">
          <TokenBadge tokens={p.tokens} />
          <StatusPill status={p.status} />
        </div>
      </div>

      <div className="mx-auto flex min-h-0 w-full max-w-6xl flex-1">
        <main className="flex min-w-0 flex-1 flex-col">
          <div ref={scrollRef} className="min-h-0 flex-1 space-y-7 overflow-auto px-8 pb-8 pt-2">
            <p className="text-[12px] leading-relaxed text-muted-foreground">{p.scenario.context.summary}</p>
            <div className="border-t border-border pt-6">
              <UserBubble text={p.scenario.question} tone="plain" />
            </div>
            <Blocks blocks={p.blocks} tone="plain" pending={p.pendingApproval} onResolve={p.onResolve} />
          </div>
          <div className="px-8 pb-6">
            <div className="flex items-center gap-3 border-t border-border pt-3">
              <input disabled placeholder="继续追问…" className="min-w-0 flex-1 bg-transparent py-1 text-[13px] text-muted-foreground outline-none" />
              <button disabled className="text-primary/40"><Send size={15} /></button>
            </div>
          </div>
        </main>

        <aside className="hidden w-[260px] shrink-0 flex-col border-l border-border pl-5 pr-6 lg:flex">
          <div className="pb-1 pt-2 text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground">events</div>
          <EventList played={p.played} tone="dense" className="pt-1" />
        </aside>
      </div>
    </div>
  )
}

/* ================================================================
 * 风格 4 · 分屏 IDE（工具轨道 + 紧凑网格 + 直角）
 * ================================================================ */
export function StyleSplit(p: StyleProps) {
  const scrollRef = useAutoScroll(p.played.length)
  return (
    <div className="flex h-full min-h-0 bg-background">
      <nav className="flex w-11 shrink-0 flex-col items-center gap-1 border-r border-border bg-card py-2">
        {[Terminal, FileText, Network, ShieldCheck, Boxes, Sparkles].map((I, i) => (
          <button key={i} className={`flex h-8 w-8 items-center justify-center rounded-sm ${i === 0 ? 'bg-accent text-accent-foreground' : 'text-muted-foreground hover:bg-muted'}`}>
            <I size={15} />
          </button>
        ))}
      </nav>

      <main className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b border-border bg-card px-3 py-1.5 font-mono text-[10.5px]">
          <span className="rounded-sm bg-secondary px-2 py-0.5 text-secondary-foreground">run.log</span>
          <span className="text-muted-foreground">{p.scenario.context.label}</span>
          <div className="ml-auto flex items-center gap-2">
            <TokenBadge tokens={p.tokens} />
            <StatusPill status={p.status} compact />
          </div>
        </div>

        <div ref={scrollRef} className="min-h-0 flex-1 space-y-2 overflow-auto px-3 py-2.5">
          <div className="rounded-sm border border-dashed border-border px-2 py-1 font-mono text-[10.5px] text-muted-foreground">
            ctx · {p.scenario.context.kind} · {p.scenario.context.label}
          </div>
          <div className="rounded-sm border border-border bg-card px-2.5 py-1.5">
            <UserBubble text={p.scenario.question} tone="dense" />
          </div>
          <Blocks blocks={p.blocks} tone="dense" pending={p.pendingApproval} onResolve={p.onResolve} />
        </div>

        <div className="flex items-center gap-1.5 border-t border-border bg-card px-3 py-1.5 font-mono text-[11px]">
          <span className="text-primary">❯</span>
          <input disabled placeholder="shell / chat" className="min-w-0 flex-1 bg-transparent text-muted-foreground outline-none" />
          <kbd className="rounded-sm border border-border px-1 text-[9.5px] text-muted-foreground">⏎</kbd>
        </div>
      </main>

      <aside className="hidden w-[360px] shrink-0 flex-col border-l border-border bg-card md:flex">
        <div className="flex items-center gap-2 border-b border-border px-2.5 py-1.5 font-mono text-[10.5px]">
          <Brain size={11} className="text-muted-foreground" />
          <span className="text-foreground">EVENTS</span>
          <span className="text-muted-foreground">{p.played.length}</span>
          <span className="ml-auto text-muted-foreground">seq ↑</span>
        </div>
        <EventList played={p.played} tone="dense" />
      </aside>
    </div>
  )
}

/* ================================================================
 * 风格 5 · 时间轴（事件即主轴，消息沿轴展开）
 * ================================================================ */
const DOT: Record<Block['kind'], string> = {
  notice: 'bg-primary/60',
  thinking: 'bg-muted-foreground/50',
  text: 'bg-foreground',
  tool: 'bg-primary',
  done: 'bg-muted-foreground/40',
  finished: 'bg-primary',
}

export function StyleTimeline(p: StyleProps) {
  const wrapRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    wrapRef.current?.scrollTo({ top: wrapRef.current.scrollHeight, behavior: 'smooth' })
  }, [p.played.length])

  return (
    <div ref={wrapRef} className="h-full overflow-auto bg-background">
      <div className="mx-auto max-w-3xl px-6 py-7">
        <div className="mb-6 flex items-center gap-2.5">
          <span className="text-[14px] font-medium text-foreground">{p.scenario.title}</span>
          <StatusPill status={p.status} />
          <div className="ml-auto flex items-center gap-3">
            <TokenBadge tokens={p.tokens} />
            <span className="font-mono text-[10px] text-muted-foreground">{p.played.length} events</span>
          </div>
        </div>

        {/* 轴线 */}
        <div className="relative pl-7">
          <span className="absolute bottom-2 left-[7px] top-1 w-px bg-border" />

          <div className="relative pb-5">
            <span className="absolute -left-7 top-1.5 flex h-4 w-4 items-center justify-center rounded-full border border-border bg-background">
              <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
            </span>
            <div className="text-[10px] uppercase tracking-[0.16em] text-muted-foreground">context · {p.scenario.context.label}</div>
            <pre className="m-0 mt-1 whitespace-pre-wrap font-mono text-[10.5px] leading-relaxed text-muted-foreground">{p.scenario.context.summary}</pre>
          </div>

          <div className="relative pb-5">
            <span className="absolute -left-7 top-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-primary">
              <span className="h-1.5 w-1.5 rounded-full bg-primary-foreground" />
            </span>
            <div className="text-[10px] uppercase tracking-[0.16em] text-muted-foreground">user</div>
            <div className="mt-1"><UserBubble text={p.scenario.question} tone="axis" /></div>
          </div>

          {p.blocks.map((b) => (
            <div key={b.key} className="relative pb-4">
              <span className="absolute -left-7 top-1.5 flex h-4 w-4 items-center justify-center rounded-full border border-border bg-background">
                <span className={`h-1.5 w-1.5 rounded-full ${DOT[b.kind]}`} />
              </span>
              <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
                {b.kind === 'tool' ? `tool · ${b.name}` : b.kind === 'thinking' ? 'thinking' : b.kind === 'text' ? 'assistant' : b.kind === 'done' ? 'message.done' : 'run.finished'}
                {b.kind === 'tool' && <span className="font-mono normal-case tracking-normal text-muted-foreground/60">#{b.callId}</span>}
              </div>
              <div className="max-w-[92%]">
                {b.kind === 'thinking' && <ThinkingBlock text={b.text} tone="axis" />}
                {b.kind === 'text' && <TextBlock text={b.text} done={b.done} tone="axis" />}
                {b.kind === 'tool' && <ToolCard block={b} pending={p.pendingApproval === b.callId} onApprove={p.onResolve} tone="axis" />}
                {b.kind === 'done' && (
                  <div className="flex items-center gap-2 text-[10.5px] text-muted-foreground">
                    <span className="h-px w-6 bg-border" />
                    in {b.usage?.in ?? 0} / out {b.usage?.out ?? 0}
                  </div>
                )}
                {b.kind === 'finished' && (
                  <div className="inline-flex items-center gap-1.5 rounded-full bg-accent px-2.5 py-0.5 text-[10.5px] font-medium text-accent-foreground">
                    <Play size={10} /> run.finished · {b.status}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export const STYLES = [
  { id: 'classic', name: '轻线卡片', desc: '项目默认：白卡 + 发丝线 + 绿色强调' },
  { id: 'terminal', name: '终端', desc: '暗色变量组 + 全等宽 + 单色层级' },
  { id: 'minimal', name: '极简', desc: '去卡片与边框，靠留白和字号分层' },
  { id: 'split', name: '分屏 IDE', desc: '工具轨道 + 紧凑网格 + 直角' },
  { id: 'timeline', name: '时间轴', desc: '事件即主轴，消息沿轴展开' },
] as const

export type StyleId = (typeof STYLES)[number]['id']

export function StyleRenderer({ id, ...props }: StyleProps & { id: StyleId }) {
  switch (id) {
    case 'terminal':
      return <StyleTerminal {...props} />
    case 'minimal':
      return <StyleMinimal {...props} />
    case 'split':
      return <StyleSplit {...props} />
    case 'timeline':
      return <StyleTimeline {...props} />
    default:
      return <StyleClassic {...props} />
  }
}

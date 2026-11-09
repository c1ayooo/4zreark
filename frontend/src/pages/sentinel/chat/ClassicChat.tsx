/**
 * 对话工作台 · 正式布局（风格 01 轻线卡片）
 *
 * 输入模型：文本 + 附件（上传分析）+ skill（注入检查项）
 *   - 附件：点击/拖拽上传，chip 可在发送前移除；上传走 POST /sentinel/uploads（分片）
 *   - skill：输入框左侧选择，选中后随 run 一起提交，后端注入检查项清单
 *   - 发送后 run 事件流（file.uploaded / skill.loaded / tool.* ）经侧栏呈现
 * 配色全部取自项目 token；审批卡可交互。
 */
import { useEffect, useRef, useState } from 'react'
import type { Attachment, RunEvent, Scenario, Skill } from './mockRuns'
import { SKILLS, attachmentKind, formatSize } from './mockRuns'
import type { PlaybackStatus } from './useRunPlayback'
import type { Block } from './parts'
import { EventList, StatusPill, TextBlock, ThinkingBlock, ToolCard } from './parts'
import {
  ArrowUp, FileArchive, FileCode2, FilePlus2, FileText, Plus, Send, Sparkles, X,
} from 'lucide-react'

export interface ComposerState {
  text: string
  attachments: Attachment[]
  skill: Skill | null
}

/** 历史轮次：真接线后多轮对话要在同一条流里回溯 */
export interface HistoryTurn {
  question: string
  attachments?: Attachment[]
  skill?: Skill | null
  blocks: Block[]
}

export interface ClassicChatProps {
  scenario: Scenario
  blocks: Block[]
  played: RunEvent[]
  status: PlaybackStatus
  tokens?: { in: number; out: number }
  pendingApproval: string | null
  onResolve: (d: 'approved' | 'rejected') => void
  composer: ComposerState
  onTextChange: (t: string) => void
  onAddFiles: (files: File[]) => void
  onRemoveAttachment: (name: string) => void
  onSelectSkill: (s: Skill | null) => void
  onSend: () => void
  /** 技能清单由调用方给（真数据来自后端），缺省用内置示例 */
  skills?: Skill[]
  /** 之前的轮次 */
  history?: HistoryTurn[]
  /** 顶部提示条（如：未配置模型接入） */
  banner?: React.ReactNode
}

function fileIcon(kind: string) {
  if (kind === 'zip') return FileArchive
  if (kind === 'pdf') return FileText
  if (kind === 'text') return FileText
  return FileCode2
}

function AttachmentCard({ a }: { a: Attachment }) {
  const Icon = fileIcon(a.kind)
  return (
    <div className="flex items-center gap-2.5 rounded-xl border border-border bg-card px-3 py-2">
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-secondary text-secondary-foreground">
        <Icon size={14} />
      </span>
      <div className="min-w-0">
        <div className="truncate text-[12px] font-medium text-card-foreground">{a.name}</div>
        <div className="text-[10.5px] text-muted-foreground">
          {formatSize(a.size)}
          {a.files ? ` · ${a.files} 个文件` : ''}
          {a.status === 'parsing' ? ' · 解析中…' : a.status === 'failed' ? ' · 解析失败' : ''}
        </div>
      </div>
    </div>
  )
}

function SkillTag({ skill }: { skill: Skill }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-accent px-2.5 py-1 text-[11px] font-medium text-accent-foreground">
      <Sparkles size={11} />
      {skill.name}
      <span className="font-mono text-[10px] opacity-70">{skill.version}</span>
    </span>
  )
}

export default function ClassicChat(p: ClassicChatProps) {
  const [dragging, setDragging] = useState(false)
  const [skillOpen, setSkillOpen] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const pickFiles = (list: FileList | null) => {
    if (!list || !list.length) return
    p.onAddFiles(Array.from(list))
  }

  const canSend = p.composer.text.trim().length > 0 || p.composer.attachments.length > 0 || !!p.composer.skill

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' })
  }, [p.played.length])

  return (
    <div
      className="relative flex h-full min-h-0 bg-background"
      onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
      onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false) }}
      onDrop={(e) => { e.preventDefault(); setDragging(false); pickFiles(e.dataTransfer.files) }}
    >
      {/* 左：会话上下文 */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-border bg-card md:flex">
        <div className="border-b border-border px-4 py-3">
          <div className="text-[13px] font-semibold text-card-foreground">{p.scenario.title}</div>
          <div className="mt-1.5 flex items-center gap-1.5">
            <span className="rounded-full bg-accent px-1.5 py-0.5 text-[10px] font-medium text-accent-foreground">{p.scenario.modeLabel}</span>
            <StatusPill status={p.status} />
          </div>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-auto px-4 py-3">
          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">本次输入</div>
            {p.composer.attachments.length === 0 && !p.composer.skill && (
              <div className="rounded-xl border border-dashed border-border px-2.5 py-3 text-center text-[11px] text-muted-foreground">
                未附加文件 / 未指定 skill
              </div>
            )}
            <div className="space-y-1.5">
              {p.composer.attachments.map((a) => (
                <div key={a.name} className="flex items-center gap-1.5 rounded-lg border border-border bg-background px-2 py-1.5">
                  {(() => { const I = fileIcon(a.kind); return <I size={12} className="shrink-0 text-muted-foreground" /> })()}
                  <span className="min-w-0 flex-1 truncate text-[11px] text-secondary-foreground">{a.name}</span>
                  <span className="font-mono text-[10px] text-muted-foreground">{formatSize(a.size)}</span>
                </div>
              ))}
            </div>
            {p.composer.skill && (
              <div className="mt-1.5 flex items-center gap-1.5 rounded-lg bg-accent px-2 py-1.5 text-[11px] text-accent-foreground">
                <Sparkles size={12} className="shrink-0" />
                <span className="min-w-0 flex-1 truncate">{p.composer.skill.name} {p.composer.skill.version}</span>
                <span className="font-mono text-[10px] opacity-70">{p.composer.skill.checks} 项</span>
              </div>
            )}
          </section>

          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">上下文</div>
            <div className="rounded-xl border border-border bg-background px-2.5 py-2">
              <div className="text-[11.5px] font-medium text-foreground">{p.scenario.context.label}</div>
              <pre className="m-0 mt-1 whitespace-pre-wrap font-mono text-[10.5px] leading-relaxed text-muted-foreground">{p.scenario.context.summary}</pre>
            </div>
          </section>

          <section>
            <div className="mb-1.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">工具权限</div>
            {[['read_file / grep / list_files', true], ['run_bash（需审批）', true], ['submit_finding', true]].map(([label, on]) => (
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

      {/* 中：消息流 */}
      <main className="flex min-w-0 flex-1 flex-col">
        <div className="flex items-center gap-2 border-b border-border px-5 py-2.5">
          <span className="text-[13px] font-medium text-foreground">{p.scenario.title}</span>
          <span className="hidden text-[11px] text-muted-foreground lg:inline">{p.scenario.desc}</span>
          <div className="ml-auto flex items-center gap-2">
            {p.tokens && (
              <span className="font-mono text-[10.5px] text-muted-foreground">
                {(p.tokens.in / 1000).toFixed(1)}k in / {(p.tokens.out / 1000).toFixed(1)}k out
              </span>
            )}
            <StatusPill status={p.status} />
          </div>
        </div>

        <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-auto px-5 py-4">
          <div className="rounded-xl border border-dashed border-border px-3 py-2">
            <div className="text-[10px] text-muted-foreground">系统上下文 · {p.scenario.context.label}</div>
          </div>

          {p.banner}

          {/* 历史轮次：只回放文本结论，工具细节属于当轮 */}
          {p.history?.map((h, i) => (
            <div key={`h${i}`} className="space-y-2">
              <div className="flex flex-col items-end gap-1.5">
                {h.skill && (
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] text-muted-foreground">指定 skill</span>
                    <SkillTag skill={h.skill} />
                  </div>
                )}
                {!!h.attachments?.length && (
                  <div className="w-[min(78%,360px)] space-y-1.5">
                    {h.attachments.map((a) => <AttachmentCard key={a.name} a={a} />)}
                  </div>
                )}
                <div className="max-w-[78%] rounded-2xl rounded-br-sm bg-primary px-4 py-2.5 text-[13.5px] leading-relaxed text-primary-foreground">
                  {h.question}
                </div>
              </div>
              {h.blocks
                .filter((b): b is Extract<Block, { kind: 'text' }> => b.kind === 'text')
                .map((b) => <TextBlock key={`${i}-${b.key}`} text={b.text} done tone="card" />)}
            </div>
          ))}

          {/* 用户消息：skill + 附件 + 文本 */}
          <div className="flex flex-col items-end gap-1.5">
            {p.scenario.skill && (
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] text-muted-foreground">指定 skill</span>
                <SkillTag skill={p.scenario.skill} />
              </div>
            )}
            {!!p.scenario.attachments?.length && (
              <div className="w-[min(78%,360px)] space-y-1.5">
                {p.scenario.attachments.map((a) => <AttachmentCard key={a.name} a={a} />)}
              </div>
            )}
            <div className="max-w-[78%] rounded-2xl rounded-br-sm bg-primary px-4 py-2.5 text-[13.5px] leading-relaxed text-primary-foreground">
              {p.scenario.question}
            </div>
          </div>

          {p.played.length === 0 && (
            <div className="py-10 text-center text-[11px] text-muted-foreground">
              <span className="mr-2 inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-border border-t-primary align-middle" />
              等待事件流 run.started …
            </div>
          )}

          {p.blocks.map((b) => {
            if (b.kind === 'notice') {
              return (
                <div key={b.key} className="flex items-center gap-1.5 pl-1 text-[11px] text-muted-foreground">
                  {b.tone === 'skill' ? <Sparkles size={11} className="text-accent-foreground" /> : <FileArchive size={11} className="text-primary" />}
                  {b.text}
                  <span className="h-px flex-1 bg-border" />
                </div>
              )
            }
            if (b.kind === 'thinking') return <ThinkingBlock key={b.key} text={b.text} tone="card" />
            if (b.kind === 'text') return <TextBlock key={b.key} text={b.text} done={b.done} tone="card" />
            if (b.kind === 'tool') {
              return (
                <div key={b.key} className="ml-7 max-w-[92%]">
                  <ToolCard block={b} pending={p.pendingApproval === b.callId} onApprove={p.onResolve} tone="card" />
                </div>
              )
            }
            if (b.kind === 'done') {
              return (
                <div key={b.key} className="flex items-center gap-2 pl-1 text-[10.5px] text-muted-foreground/70">
                  <span className="h-px w-6 bg-border" />
                  message.done{b.usage ? ` · in ${b.usage.in} / out ${b.usage.out}` : ''}
                </div>
              )
            }
            return (
              <div key={b.key} className="flex items-center gap-2 pl-1">
                <span className="rounded-full bg-accent px-2 py-0.5 text-[10.5px] font-medium text-accent-foreground">run.finished · {b.status}</span>
                {b.tokens && <span className="font-mono text-[10.5px] text-muted-foreground">in {b.tokens.in} / out {b.tokens.out}</span>}
              </div>
            )
          })}
        </div>

        {/* 输入区：文本 + 附件 + skill */}
        <div className="border-t border-border px-5 py-3">
          <div className="relative rounded-2xl border border-border bg-card shadow-sm focus-within:border-primary/40">
            {/* 已选 chips */}
            {(p.composer.attachments.length > 0 || p.composer.skill) && (
              <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
                {p.composer.skill && (
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-accent px-2 py-1 text-[11px] text-accent-foreground">
                    <Sparkles size={11} />
                    {p.composer.skill.name}
                    <span className="font-mono text-[10px] opacity-70">{p.composer.skill.version}</span>
                    <button onClick={() => p.onSelectSkill(null)} className="ml-0.5 rounded-full hover:bg-accent-foreground/10"><X size={10} /></button>
                  </span>
                )}
                {p.composer.attachments.map((a) => {
                  const I = fileIcon(a.kind)
                  return (
                    <span key={a.name} className="inline-flex max-w-[240px] items-center gap-1.5 rounded-full border border-border bg-background px-2 py-1 text-[11px] text-secondary-foreground">
                      <I size={11} className="shrink-0 text-muted-foreground" />
                      <span className="truncate">{a.name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">{formatSize(a.size)}</span>
                      <button onClick={() => p.onRemoveAttachment(a.name)} className="ml-0.5 rounded-full hover:bg-muted"><X size={10} /></button>
                    </span>
                  )
                })}
              </div>
            )}

            <textarea
              rows={2}
              value={p.composer.text}
              onChange={(e) => p.onTextChange(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); if (canSend) p.onSend() }
              }}
              placeholder="描述要分析什么，或直接拖入代码包 / 单文件；可用 / 指定 skill"
              className="w-full resize-none bg-transparent px-3.5 pt-3 text-[13px] leading-relaxed text-foreground outline-none placeholder:text-muted-foreground"
            />

            <div className="flex items-center gap-1.5 px-2.5 pb-2">
              <input ref={fileInputRef} type="file" multiple hidden
                accept=".zip,.tar.gz,.tgz,.7z,.java,.go,.php,.c,.h,.cc,.py,.js,.ts,.diff,.patch,.pdf,.txt"
                onChange={(e) => { pickFiles(e.target.files); e.target.value = '' }} />
              <button
                onClick={() => fileInputRef.current?.click()}
                className="inline-flex items-center gap-1 rounded-full border border-border px-2.5 py-1 text-[11px] text-secondary-foreground hover:bg-muted"
              >
                <FilePlus2 size={12} />上传文件
              </button>

              <button
                onClick={() => setSkillOpen((o) => !o)}
                className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] ${p.composer.skill ? 'border-transparent bg-accent text-accent-foreground' : 'border-border text-secondary-foreground hover:bg-muted'}`}
              >
                <Sparkles size={12} />{p.composer.skill ? '已指定 skill' : '指定 skill'}
              </button>

              <span className="ml-auto hidden items-center gap-2 text-[10.5px] text-muted-foreground sm:flex">
                <span>Enter 发送 · Shift+Enter 换行</span>
              </span>
              <button
                onClick={p.onSend}
                disabled={!canSend}
                className={`ml-1 flex h-8 w-8 items-center justify-center rounded-full transition-opacity ${canSend ? 'bg-primary text-primary-foreground hover:opacity-90' : 'bg-muted text-muted-foreground'}`}
              >
                <ArrowUp size={15} />
              </button>
            </div>

            {/* skill 选择面板 */}
            {skillOpen && (
              <div className="absolute bottom-full left-0 z-20 mb-2 w-[340px] overflow-hidden rounded-xl border border-border bg-popover shadow-lg">
                <div className="flex items-center justify-between border-b border-border px-3 py-2">
                  <span className="text-[11px] font-medium text-popover-foreground">选择 skill（注入检查项）</span>
                  <button onClick={() => setSkillOpen(false)} className="text-muted-foreground hover:text-foreground"><X size={12} /></button>
                </div>
                <div className="max-h-64 overflow-auto py-1">
                  {(p.skills?.length ? p.skills : SKILLS).map((s) => {
                    const on = p.composer.skill?.id === s.id
                    return (
                      <button
                        key={s.id}
                        onClick={() => { p.onSelectSkill(on ? null : s); setSkillOpen(false) }}
                        className={`block w-full px-3 py-2 text-left transition-colors ${on ? 'bg-accent' : 'hover:bg-muted'}`}
                      >
                        <div className="flex items-center gap-1.5">
                          <Sparkles size={11} className={on ? 'text-accent-foreground' : 'text-muted-foreground'} />
                          <span className={`text-[12px] font-medium ${on ? 'text-accent-foreground' : 'text-foreground'}`}>{s.name}</span>
                          <span className="font-mono text-[10px] text-muted-foreground">{s.version}</span>
                          <span className="ml-auto rounded-full bg-secondary px-1.5 py-0.5 text-[9.5px] text-secondary-foreground">{s.checks} 项</span>
                        </div>
                        <p className="mt-0.5 line-clamp-2 pl-[18px] text-[10.5px] leading-relaxed text-muted-foreground">{s.desc}</p>
                      </button>
                    )
                  })}
                </div>
                <div className="border-t border-border px-3 py-1.5 text-[10px] text-muted-foreground">
                  skill 只注入检查项与检索顺序，不改变工具权限
                </div>
              </div>
            )}
          </div>

          <div className="mt-1.5 flex items-center gap-3 text-[10.5px] text-muted-foreground">
            <span>审批：manual</span>
            <span>附件 ≤200MB · zip 解析后按 skill 检查项检索</span>
            <span className="ml-auto inline-flex items-center gap-1"><Plus size={10} />支持拖拽到消息区</span>
          </div>
        </div>
      </main>

      {/* 右：事件流 */}
      <aside className="hidden w-[360px] shrink-0 flex-col border-l border-border bg-card lg:flex">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2">
          <span className="text-[11px] font-medium text-card-foreground">事件流</span>
          <span className="font-mono text-[10px] text-muted-foreground">{p.played.length}</span>
          <span className="ml-auto text-[10px] text-muted-foreground">seq ↑</span>
        </div>
        <EventList played={p.played} tone="rows" />
      </aside>

      {/* 拖拽遮罩 */}
      {dragging && (
        <div className="pointer-events-none absolute inset-0 z-30 flex flex-col items-center justify-center gap-2 rounded-none bg-accent/80 backdrop-blur-sm">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-primary/30 bg-card text-primary">
            <Send size={20} />
          </div>
          <div className="text-[13px] font-medium text-accent-foreground">松开上传，开始分析</div>
          <div className="text-[11px] text-accent-foreground/70">zip / tar.gz / 单文件 · ≤200MB</div>
        </div>
      )}
    </div>
  )
}

/** 上传前把 File 转成展示模型（生产：先本地占位 parsing，上传接口回填 files/sha256） */
export function fileToAttachment(f: File): Attachment {
  return { name: f.name, size: f.size, kind: attachmentKind(f.name), status: 'parsing' }
}

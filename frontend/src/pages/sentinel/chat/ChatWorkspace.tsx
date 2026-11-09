/**
 * 对话工作台（生产版）
 *
 * 与之前的 ChatLivePage / ChatDemoPage 的差别：
 *   - 会话落库（conversation/message 表），可新建、切换、改名、删除；
 *   - SSE 流式输出，边生成边渲染，可中途停止；
 *   - 附件真实上传 + 服务端解析（zip 目录树 / 源码可疑点），摘要随消息注入；
 *   - 技能从技能库读取，可切换，也能在设置里增删改。
 *
 * 不存在任何 mock 数据：没有模型配置时直接给出「去设置里配」的提示。
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Popconfirm, Select, Tag, Tooltip } from 'antd'
import {
  AlertCircle,
  Check,
  Loader2,
  MessageSquarePlus,
  Paperclip,
  Pencil,
  Send,
  Sparkles,
  Square,
  Trash2,
} from 'lucide-react'
import { chatApi, streamMessage, type ChatMsg, type Conversation, type UploadResult } from '@/api/chat'
import { sentinelApi, type SentinelSkill } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import { MarkdownLite } from '@/components/chat/MarkdownLite'

const MAX_UPLOAD_FILES = 3

export default function ChatWorkspace({ embedded = false }: { embedded?: boolean }) {
  const { toast } = useToast()
  const qc = useQueryClient()

  const [activeId, setActiveId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMsg[]>([])
  const [text, setText] = useState('')
  const [skillId, setSkillId] = useState('')
  const [uploads, setUploads] = useState<UploadResult[]>([])
  const [uploading, setUploading] = useState(false)
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [renameText, setRenameText] = useState('')

  const abortRef = useRef<AbortController | null>(null)
  const scrollRef = useRef<HTMLDivElement | null>(null)
  const fileRef = useRef<HTMLInputElement | null>(null)

  const conversationsQuery = useQuery({
    queryKey: ['chat', 'conversations'],
    queryFn: chatApi.listConversations,
  })
  const skillsQuery = useQuery({
    queryKey: ['chat', 'skills'],
    queryFn: () => sentinelApi.skills(),
    staleTime: 60_000,
  })

  const conversations = conversationsQuery.data ?? []
  const skills = useMemo(
    () => (skillsQuery.data?.items ?? []).filter((s: SentinelSkill) => s.id),
    [skillsQuery.data],
  )
  // 判定链路的默认技能：会话没绑定技能时，后端实际注入的就是它，
  // 下拉必须显示同一份，否则界面看起来「没有可用技能」，用户会以为功能没生效。
  const defaultSkillId = skillsQuery.data?.default_id ?? ''

  const detailQuery = useQuery({
    queryKey: ['chat', 'conversation', activeId],
    queryFn: () => chatApi.getConversation(activeId as string),
    enabled: !!activeId,
  })

  // 服务端数据到达后覆盖本地（流式结束时会 invalidate，借此拿到真实消息 id 与用量）
  useEffect(() => {
    if (detailQuery.data) {
      setMessages(detailQuery.data.messages)
      setSkillId(detailQuery.data.conversation.skill_id || defaultSkillId)
    }
  }, [detailQuery.data, defaultSkillId])

  // 首次进入自动选最近的会话；没有会话就停在空状态，不自动创建（避免堆空壳）
  useEffect(() => {
    if (!activeId && conversations.length > 0) {
      setActiveId(conversations[0].id)
    }
  }, [conversations, activeId])

  // 新消息 / 流式增量都往下滚
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages])

  const createMutation = useMutation({
    mutationFn: () => chatApi.createConversation({ skill_id: skillId }),
    onSuccess: (c) => {
      setActiveId(c.id)
      setMessages([])
      setError(null)
      qc.invalidateQueries({ queryKey: ['chat', 'conversations'] })
    },
    onError: (e: Error) => toast({ title: '新建对话失败', description: e.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => chatApi.remove(id),
    onSuccess: (_d, id) => {
      if (id === activeId) {
        setActiveId(null)
        setMessages([])
      }
      qc.invalidateQueries({ queryKey: ['chat', 'conversations'] })
      toast({ title: '会话已删除' })
    },
    onError: (e: Error) => toast({ title: '删除失败', description: e.message, variant: 'destructive' }),
  })

  const rename = async (id: string) => {
    const title = renameText.trim()
    setRenaming(null)
    if (!title) return
    try {
      await chatApi.rename(id, title)
      qc.invalidateQueries({ queryKey: ['chat', 'conversations'] })
      qc.invalidateQueries({ queryKey: ['chat', 'conversation', id] })
    } catch (e) {
      toast({ title: '改名失败', description: (e as Error).message, variant: 'destructive' })
    }
  }

  const pickFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return
    const room = MAX_UPLOAD_FILES - uploads.length
    const list = Array.from(files).slice(0, Math.max(0, room))
    if (list.length === 0) {
      toast({ title: `最多 ${MAX_UPLOAD_FILES} 个附件`, variant: 'destructive' })
      return
    }
    setUploading(true)
    for (const f of list) {
      try {
        const r = await chatApi.upload(f)
        setUploads((prev) => [...prev, r])
      } catch (e) {
        toast({ title: `${f.name} 解析失败`, description: (e as Error).message, variant: 'destructive' })
      }
    }
    setUploading(false)
    if (fileRef.current) fileRef.current.value = ''
  }

  const stop = () => {
    abortRef.current?.abort()
    abortRef.current = null
    setStreaming(false)
  }

  const send = async () => {
    const content = text.trim()
    if (streaming) return
    if (!content && uploads.length === 0) return
    if (!content) {
      toast({ title: '请输入要分析的内容（附件不能单独发送）', variant: 'destructive' })
      return
    }

    let convId = activeId
    if (!convId) {
      try {
        const c = await chatApi.createConversation({ skill_id: skillId })
        convId = c.id
        setActiveId(c.id)
        qc.invalidateQueries({ queryKey: ['chat', 'conversations'] })
      } catch (e) {
        setError((e as Error).message)
        return
      }
    }

    const now = new Date().toISOString()
    const draftId = -Date.now()
    const userMsg: ChatMsg = {
      id: draftId - 1,
      role: 'user',
      content,
      attachments: uploads.map((u) => ({ id: u.id, name: u.name, size: u.size, kind: u.kind })),
      created_at: now,
    }
    const assistantMsg: ChatMsg = {
      id: draftId,
      role: 'assistant',
      content: '',
      created_at: now,
    }
    setMessages((prev) => [...prev, userMsg, assistantMsg])

    const uploadIds = uploads.map((u) => u.id)
    setText('')
    setUploads([])
    setError(null)
    setStreaming(true)

    const controller = new AbortController()
    abortRef.current = controller

    try {
      await streamMessage(
        convId,
        { content, skill_id: skillId || undefined, upload_ids: uploadIds },
        (ev) => {
          if (ev.type === 'skill.loaded') {
            // 服务端可能按消息内容自动换了技能：下拉框要跟着变，
            // 否则界面显示 java、实际跑的是 php，人会以为「选了没用」。
            const p = ev.payload as { skill?: string; name?: string; version?: string; auto?: boolean }
            if (p.skill) {
              setSkillId(p.skill)
              if (p.auto) {
                // 自动选的技能写回会话，刷新后下拉框仍显示实际用的那一份
                chatApi.setSkill(convId, p.skill).catch(() => undefined)
                toast({ title: `已按内容选用技能：${p.name ?? p.skill} ${p.version ?? ''}`.trim() })
              }
            }
          } else if (ev.type === 'message.delta') {
            const delta = String((ev.payload as { delta?: string }).delta ?? '')
            if (!delta) return
            setMessages((prev) =>
              prev.map((m) => (m.id === draftId ? { ...m, content: m.content + delta } : m)),
            )
          } else if (ev.type === 'message.done') {
            const usage = (ev.payload as { usage?: { in: number; out: number } }).usage
            if (usage) {
              setMessages((prev) => prev.map((m) => (m.id === draftId ? { ...m, usage } : m)))
            }
          } else if (ev.type === 'error') {
            const msg = String((ev.payload as { message?: string }).message ?? '生成失败')
            setError(msg)
          }
        },
        controller.signal,
      )
    } catch (e) {
      if ((e as Error).name !== 'AbortError') {
        setError((e as Error).message)
      }
    } finally {
      setStreaming(false)
      abortRef.current = null
      // 用服务端数据校正：真实消息 id、usage、事件都以后端为准
      qc.invalidateQueries({ queryKey: ['chat', 'conversation', convId] })
      qc.invalidateQueries({ queryKey: ['chat', 'conversations'] })
    }
  }

  const activeConv: Conversation | undefined = detailQuery.data?.conversation ??
    conversations.find((c) => c.id === activeId)

  const shellHeight = embedded ? 'h-[calc(100vh-8.5rem)]' : 'h-screen'

  return (
    <div className={`flex ${shellHeight} min-h-[560px] overflow-hidden rounded-xl border border-border bg-card text-foreground`}>
      {/* ---------------- 会话列表 ---------------- */}
      <aside className="flex w-[228px] shrink-0 flex-col border-r border-border bg-muted/20">
        <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
          <span className="text-[12.5px] font-semibold">对话</span>
          <Button
            size="small"
            type="primary"
            className="ml-auto"
            icon={<MessageSquarePlus size={13} />}
            loading={createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            新建
          </Button>
        </div>

        <div className="min-h-0 flex-1 overflow-auto p-1.5">
          {conversationsQuery.isLoading && (
            <p className="flex items-center gap-1.5 px-2 py-2 text-[11.5px] text-muted-foreground">
              <Loader2 size={12} className="animate-spin" /> 加载会话…
            </p>
          )}
          {!conversationsQuery.isLoading && conversations.length === 0 && (
            <p className="px-2 py-3 text-[11.5px] leading-relaxed text-muted-foreground">
              还没有会话。点「新建」开始；首条消息会自动成为会话标题。
            </p>
          )}
          {conversations.map((c) => {
            const active = c.id === activeId
            return (
              <div
                key={c.id}
                className={`group relative mb-0.5 cursor-pointer rounded-md px-2 py-1.5 transition-colors ${
                  active ? 'bg-accent text-accent-foreground' : 'hover:bg-muted'
                }`}
                onClick={() => {
                  if (streaming) {
                    toast({ title: '正在生成，先停止或等待完成', variant: 'destructive' })
                    return
                  }
                  setActiveId(c.id)
                  setError(null)
                }}
              >
                {renaming === c.id ? (
                  <Input
                    size="small"
                    autoFocus
                    value={renameText}
                    onChange={(e) => setRenameText(e.target.value)}
                    onPressEnter={() => rename(c.id)}
                    onBlur={() => rename(c.id)}
                    onClick={(e) => e.stopPropagation()}
                  />
                ) : (
                  <>
                    <div className="truncate pr-10 text-[12.5px] leading-tight" title={c.title}>
                      {c.title || '新对话'}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-muted-foreground">
                      <span>{c.message_count} 条</span>
                      <span>·</span>
                      <span>{shortTime(c.updated_at)}</span>
                    </div>
                    <div className="absolute right-1 top-1 hidden items-center gap-0.5 group-hover:flex">
                      <Tooltip title="重命名">
                        <button
                          className="rounded p-1 text-muted-foreground hover:bg-background"
                          onClick={(e) => {
                            e.stopPropagation()
                            setRenaming(c.id)
                            setRenameText(c.title)
                          }}
                        >
                          <Pencil size={11} />
                        </button>
                      </Tooltip>
                      <Popconfirm
                        title="删除这个会话？"
                        description="消息会一并删除，不可恢复"
                        okText="删除"
                        cancelText="取消"
                        onConfirm={(e) => {
                          e?.stopPropagation()
                          deleteMutation.mutate(c.id)
                        }}
                        onCancel={(e) => e?.stopPropagation()}
                      >
                        <button
                          className="rounded p-1 text-muted-foreground hover:bg-background hover:text-destructive"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <Trash2 size={11} />
                        </button>
                      </Popconfirm>
                    </div>
                  </>
                )}
              </div>
            )
          })}
        </div>

        <div className="border-t border-border px-3 py-2 text-[10px] text-muted-foreground">
          {activeConv?.model ? `模型 ${activeConv.model}` : '模型由「设置 → 模型接入」决定'}
        </div>
      </aside>

      {/* ---------------- 主区 ---------------- */}
      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex shrink-0 items-center gap-2 border-b border-border px-4 py-2">
          <span className="truncate text-[12.5px] font-medium">
            {activeConv?.title || (activeId ? '对话' : '新对话')}
          </span>
          {streaming && (
            <span className="flex items-center gap-1 text-[10.5px] text-muted-foreground">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" /> 生成中
            </span>
          )}
          <span className="ml-auto flex items-center gap-2">
            <Select
              size="small"
              className="w-[220px]"
              placeholder="选择审计技能"
              allowClear
              value={skillId || (!activeId ? defaultSkillId : '') || undefined}
              onChange={(v) => {
                const next = v ?? ''
                setSkillId(next)
                if (activeId) {
                  chatApi.setSkill(activeId, next)
                    .then(() => qc.invalidateQueries({ queryKey: ['chat', 'conversation', activeId] }))
                    .catch(() => undefined)
                }
              }}
              options={skills.map((s) => ({
                value: s.id,
                label: `${s.name} ${s.version}`,
              }))}
              suffixIcon={<Sparkles size={12} className="text-muted-foreground" />}
            />
          </span>
        </header>

        <div ref={scrollRef} className="min-h-0 flex-1 space-y-3 overflow-auto px-4 py-4">
          {messages.length === 0 && !detailQuery.isLoading && (
            <EmptyState onPick={(t) => setText(t)} />
          )}

          {messages.map((m) =>
            m.role === 'user' ? (
              <div key={m.id} className="flex flex-col items-end gap-1.5">
                {!!m.attachments?.length && (
                  <div className="flex flex-wrap justify-end gap-1.5">
                    {m.attachments.map((a) => (
                      <Tag key={a.name} className="m-0 inline-flex items-center gap-1 border-border bg-muted text-[10.5px]">
                        <Paperclip size={10} />
                        {a.name}
                        <span className="text-muted-foreground">{humanSize(a.size)}</span>
                      </Tag>
                    ))}
                  </div>
                )}
                <div className="max-w-[78%] whitespace-pre-wrap rounded-2xl rounded-br-sm bg-primary px-4 py-2.5 text-[13.5px] leading-relaxed text-primary-foreground">
                  {m.content}
                </div>
              </div>
            ) : (
              <div key={m.id} className="max-w-[88%]">
                <div className="mb-1 flex items-center gap-1.5 text-[10px] text-muted-foreground">
                  <Sparkles size={10} />
                  {m.model || 'assistant'}
                  {m.usage && (m.usage.in > 0 || m.usage.out > 0) && (
                    <span className="font-mono">
                      in {m.usage.in} / out {m.usage.out}
                    </span>
                  )}
                </div>
                <div className="rounded-2xl rounded-tl-sm border border-border bg-background px-4 py-3">
                  {m.content ? (
                    <MarkdownLite
                      text={m.content}
                      streaming={streaming && m.id === messages[messages.length - 1]?.id}
                    />
                  ) : (
                    <span className="flex items-center gap-2 text-[12.5px] text-muted-foreground">
                      <Loader2 size={12} className="animate-spin" /> 等待首个 token…
                    </span>
                  )}
                </div>
              </div>
            ),
          )}

          {error && (
            <Alert
              type="error"
              showIcon
              message="出错了"
              description={
                <span className="break-all text-[11.5px]">
                  {error}
                  <span className="mt-1 block text-muted-foreground">
                    模型配置在「设置 → 模型接入」；本轮消息已保存，修好后可直接重发。
                  </span>
                </span>
              }
            />
          )}
        </div>

        {/* 输入区 */}
        <div className="shrink-0 border-t border-border p-3">
          {(uploads.length > 0 || uploading) && (
            <div className="mb-2 flex flex-wrap items-center gap-1.5">
              {uploads.map((u) => (
                <Tag
                  key={u.id}
                  closable
                  onClose={() => setUploads((prev) => prev.filter((x) => x.id !== u.id))}
                  className="m-0 inline-flex items-center gap-1 border-transparent bg-accent text-accent-foreground text-[10.5px]"
                >
                  <Paperclip size={10} />
                  {u.name}
                  <span className="opacity-70">{humanSize(u.size)}</span>
                  <Tooltip title={u.summary.slice(0, 400)}>
                    <Check size={10} />
                  </Tooltip>
                </Tag>
              ))}
              {uploading && (
                <span className="flex items-center gap-1 text-[10.5px] text-muted-foreground">
                  <Loader2 size={11} className="animate-spin" /> 解析中…
                </span>
              )}
            </div>
          )}

          <div className="rounded-xl border border-border bg-background focus-within:border-primary/60">
            <textarea
              className="max-h-[180px] min-h-[62px] w-full resize-y bg-transparent px-3 py-2 text-[13px] leading-relaxed outline-none placeholder:text-muted-foreground"
              placeholder="描述要分析的提交、贴代码片段，或说明漏洞现象。Enter 发送，Shift+Enter 换行。"
              value={text}
              onChange={(e) => setText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  void send()
                }
              }}
            />
            <div className="flex items-center gap-1.5 border-t border-border/60 px-2 py-1.5">
              <input
                ref={fileRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => void pickFiles(e.target.files)}
              />
              <Tooltip title={`上传附件（zip / 源码 / 日志，最多 ${MAX_UPLOAD_FILES} 个，单个 32MB）`}>
                <Button
                  size="small"
                  type="text"
                  icon={<Paperclip size={14} />}
                  loading={uploading}
                  onClick={() => fileRef.current?.click()}
                />
              </Tooltip>
              <span className="text-[10px] text-muted-foreground">
                附件由服务端解析（zip 列目录 + 抽可疑点），摘要随消息注入
              </span>
              <div className="ml-auto flex items-center gap-1.5">
                {streaming ? (
                  <Button size="small" danger icon={<Square size={12} />} onClick={stop}>
                    停止
                  </Button>
                ) : (
                  <Button
                    size="small"
                    type="primary"
                    icon={<Send size={12} />}
                    disabled={!text.trim() && uploads.length === 0}
                    onClick={() => void send()}
                  >
                    发送
                  </Button>
                )}
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

/* ---------------- 空状态：只给引导，不放假对话 ---------------- */

function EmptyState({ onPick }: { onPick: (text: string) => void }) {
  const samples = [
    '帮我审这段 PHP：unserialize($_COOKIE["data"]) 后面跟着 __destruct 里的 file_put_contents',
    '这个 Java 提交把 ObjectInputStream 换成了 readObject 白名单，算修复吗？',
    '上传一个 zip，帮我看哪些文件最可能有反序列化入口',
  ]
  return (
    <div className="mx-auto mt-10 max-w-lg">
      <div className="mb-3 flex items-center gap-2">
        <Sparkles size={16} className="text-primary" />
        <span className="text-[14px] font-semibold">对话工作台</span>
      </div>
      <p className="mb-4 text-[12.5px] leading-relaxed text-muted-foreground">
        直连你在「设置 → 模型接入」配置的模型。可以贴代码、描述提交、上传 zip 让模型先看目录结构。
        左侧「新建」开一个会话，标题会按首条消息自动生成。
      </p>
      <div className="space-y-1.5">
        {samples.map((s) => (
          <button
            key={s}
            className="flex w-full items-start gap-2 rounded-lg border border-border bg-background px-3 py-2 text-left text-[12px] leading-relaxed text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
            onClick={() => onPick(s)}
          >
            <AlertCircle size={12} className="mt-0.5 shrink-0" />
            {s}
          </button>
        ))}
      </div>
    </div>
  )
}

function shortTime(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  if (diff < 60_000) return '刚刚'
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`
  return `${d.getMonth() + 1}-${d.getDate()}`
}

function humanSize(n: number): string {
  if (!n) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

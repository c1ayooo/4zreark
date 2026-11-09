import type { ReactNode } from 'react'

/**
 * 轻量 Markdown 渲染：只覆盖模型回答里真正会出现的语法。
 *
 * 不引 react-markdown 的原因：模型输出是不可信内容，任何允许内联 HTML 的
 * 渲染器都是 XSS 面；这里全部走 React 节点拼装，天然转义。
 * 支持：``` 代码块、行内 `code`、**粗体**、# 标题、- / 1. 列表、> 引用。
 */
export function MarkdownLite({ text, streaming }: { text: string; streaming?: boolean }) {
  const blocks = text.split('```')
  return (
    <div className="space-y-2 text-[13.5px] leading-[1.75] text-foreground">
      {blocks.map((block, i) => {
        // 奇数段是围栏内容：第一行是语言标识，其余是代码
        if (i % 2 === 1) {
          const nl = block.indexOf('\n')
          const lang = nl >= 0 ? block.slice(0, nl).trim() : ''
          const code = nl >= 0 ? block.slice(nl + 1) : block
          return <CodeFence key={i} lang={lang} code={code.replace(/\n$/, '')} />
        }
        return <InlineLines key={i} text={block} streaming={streaming && i === blocks.length - 1} />
      })}
    </div>
  )
}

function CodeFence({ lang, code }: { lang: string; code: string }) {
  return (
    <div className="overflow-hidden rounded-lg border border-border bg-muted/60">
      <div className="flex items-center justify-between border-b border-border px-2.5 py-1">
        <span className="font-mono text-[10px] uppercase tracking-wide text-muted-foreground">
          {lang || 'code'}
        </span>
      </div>
      <pre className="max-h-[420px] overflow-auto px-3 py-2 font-mono text-[12px] leading-[1.6] text-foreground">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function InlineLines({ text, streaming }: { text: string; streaming?: boolean }) {
  const lines = text.split('\n')
  const out: ReactNode[] = []
  let list: string[] = []

  const flushList = () => {
    if (list.length === 0) return
    out.push(
      <ul key={`ul-${out.length}`} className="my-1 list-disc space-y-0.5 pl-5">
        {list.map((item, i) => (
          <li key={i}>{inline(item)}</li>
        ))}
      </ul>,
    )
    list = []
  }

  lines.forEach((line, i) => {
    const t = line.trimEnd()
    if (!t.trim()) {
      flushList()
      out.push(<div key={`sp-${i}`} className="h-1.5" />)
      return
    }
    const ordered = t.match(/^\s*\d+[.)]\s+(.*)$/)
    const bullet = t.match(/^\s*[-*+]\s+(.*)$/)
    if (bullet) {
      list.push(bullet[1])
      return
    }
    if (ordered) {
      flushList()
      out.push(
        <div key={i} className="flex gap-1.5">
          <span className="text-muted-foreground">{t.match(/^\s*(\d+)/)?.[1]}.</span>
          <span>{inline(ordered[1])}</span>
        </div>,
      )
      return
    }
    flushList()
    if (t.startsWith('### ')) {
      out.push(<h4 key={i} className="mt-1 text-[13px] font-semibold">{inline(t.slice(4))}</h4>)
      return
    }
    if (t.startsWith('## ')) {
      out.push(<h3 key={i} className="mt-1 text-[14px] font-semibold">{inline(t.slice(3))}</h3>)
      return
    }
    if (t.startsWith('# ')) {
      out.push(<h3 key={i} className="mt-1 text-[15px] font-semibold">{inline(t.slice(2))}</h3>)
      return
    }
    if (t.startsWith('> ')) {
      out.push(
        <blockquote key={i} className="border-l-2 border-border pl-2.5 text-muted-foreground">
          {inline(t.slice(2))}
        </blockquote>,
      )
      return
    }
    out.push(<p key={i} className="whitespace-pre-wrap">{inline(t)}</p>)
  })
  flushList()

  return (
    <>
      {out}
      {streaming && <span className="ml-0.5 inline-block h-3.5 w-1 animate-pulse bg-primary align-middle" />}
    </>
  )
}

/** 行内代码 / 粗体。用 React 节点拼装，不注入 HTML。 */
function inline(text: string): ReactNode {
  const tokens = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
  return tokens.map((tok, i) => {
    if (tok.startsWith('`') && tok.endsWith('`') && tok.length > 2) {
      return (
        <code key={i} className="rounded bg-muted px-1 py-0.5 font-mono text-[12px] text-foreground">
          {tok.slice(1, -1)}
        </code>
      )
    }
    if (tok.startsWith('**') && tok.endsWith('**') && tok.length > 4) {
      return <strong key={i} className="font-semibold text-foreground">{tok.slice(2, -2)}</strong>
    }
    return tok
  })
}

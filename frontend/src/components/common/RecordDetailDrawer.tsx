import { useMemo, useState, type ReactNode } from 'react'
import { Drawer } from 'antd'
import { Check, Copy, Inbox } from 'lucide-react'

import { useToast } from '@/components/ui/use-toast'
import { cn } from '@/lib/utils'

import EmptyState from './EmptyState'

export interface RecordDetailField {
  label: string
  /** 长文本不截断全量展示；字符串值附带复制按钮 */
  value: ReactNode
}

interface RecordDetailDrawerProps {
  open: boolean
  onClose: () => void
  title: ReactNode
  fields: RecordDetailField[]
  /** 任意 JSON 对象，pretty 打印 + 可复制 */
  raw?: unknown
  footer?: ReactNode
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  // 非 HTTPS 环境下 clipboard API 不可用，退回到临时 textarea（同 MCPAccessPanel）。
  const el = document.createElement('textarea')
  el.value = text
  document.body.appendChild(el)
  el.select()
  document.execCommand('copy')
  document.body.removeChild(el)
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const { toast } = useToast()
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await copyText(text)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
      toast({ title: '已复制到剪贴板' })
    } catch {
      toast({ title: '复制失败，请手动选择文本', variant: 'destructive' })
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      aria-label={`复制${label}`}
      className={cn(
        'text-muted-foreground hover:text-foreground inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-sm transition-colors hover:bg-muted'
      )}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
    </button>
  )
}

// 全站共享的通用详情抽屉：受控纯展示，不发起请求、不依赖任何页面。
// events/audit/queue/takeover/seeds 等字段各异的列表详情统一走这里，
// 长值与 JSON 全量展示不截断——「看不到内容没法确认」就在这里解决。
export default function RecordDetailDrawer({
  open,
  onClose,
  title,
  fields,
  raw,
  footer,
}: RecordDetailDrawerProps) {
  const rawText = useMemo(() => {
    if (raw === undefined) return null
    try {
      return JSON.stringify(raw, null, 2)
    } catch {
      // 循环引用等无法序列化的对象退化为字符串，抽屉不能因此崩掉
      return String(raw)
    }
  }, [raw])

  const isEmpty = fields.length === 0 && rawText === null

  return (
    <Drawer
      open={open}
      onClose={onClose}
      width={480}
      title={title}
      footer={footer}
      // 同 AssetDetailDrawer：antd Drawer 自带遮罩/ESC/焦点管理，不手写面板
      // antd6 的 .ant-drawer-title 是 flex 项且未带 min-width:0，长域名/种子值会撑破标题区；
      // 标题是纯字符串，min-w-0 压住 flex 撑破，truncate 补省略号（同 AssetDetailDrawer 内层行为）
      classNames={{ title: 'min-w-0 truncate' }}
      styles={{ body: { padding: 16, overflowY: 'auto' } }}
    >
      {isEmpty ? (
        <EmptyState
          icon={Inbox}
          title="暂无详情"
          description="这条记录没有可展示的字段。"
        />
      ) : (
        <div className="flex flex-col gap-4">
          {fields.map((f) => {
            const empty = f.value == null || f.value === ''
            return (
              <div key={f.label}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-muted-foreground text-xs">{f.label}</span>
                  {typeof f.value === 'string' && f.value !== '' && (
                    <CopyButton text={f.value} label={f.label} />
                  )}
                </div>
                <div className="mt-1 text-[13px] leading-relaxed break-all whitespace-pre-wrap font-mono">
                  {empty ? <span className="text-muted-foreground">—</span> : f.value}
                </div>
              </div>
            )
          })}
          {rawText !== null && (
            <div>
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="text-muted-foreground text-xs">原始数据（JSON）</span>
                <CopyButton text={rawText} label="JSON" />
              </div>
              <pre className="bg-muted/50 max-h-[60vh] rounded-md border p-3 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap">
                {rawText}
              </pre>
            </div>
          )}
        </div>
      )}
    </Drawer>
  )
}

// use-toast 兼容层：原 shadcn/radix toast 的调用面（toast({title, description, variant})）
// 原地切换到 antd message。Phase E 删兼容层时，各页直接用 App.useApp()。
import * as React from 'react'
import { App } from 'antd'

export interface ToastOptions {
  title?: React.ReactNode
  description?: React.ReactNode
  variant?: 'default' | 'destructive'
  // 兼容旧签名里出现过但 antd 语义下无用的字段
  action?: unknown
  duration?: number
  onOpenChange?: (open: boolean) => void
}

// 独立 toast()（非 hook 场景）用的静态实例，由 AntdProvider 内的桥组件注册
// antd v6：App.useApp().message 的实例类型（比静态 message 窄/异构，直接取返回类型）
type MessageInstance = ReturnType<typeof App.useApp>['message']
let staticApi: MessageInstance | null = null
export function _registerToastApi(api: MessageInstance) {
  staticApi = api
}

function toastContent({ title, description }: ToastOptions): React.ReactNode {
  if (title == null && description == null) return null
  return (
    <div className="flex max-w-[360px] flex-col gap-0.5 py-0.5">
      {title != null && <span className="text-[13px] font-medium leading-5">{title}</span>}
      {description != null && (
        <span className="whitespace-pre-wrap break-all text-xs leading-4 text-muted-foreground">
          {description}
        </span>
      )}
    </div>
  )
}

function showToast(api: MessageInstance, opts: ToastOptions) {
  const content = toastContent(opts)
  if (content == null) return
  const duration = opts.duration ?? (opts.variant === 'destructive' ? 5 : 3)
  if (opts.variant === 'destructive') {
    api.error({ content, duration })
  } else {
    api.info({ content, duration })
  }
}

export function toast(opts: ToastOptions) {
  if (staticApi) {
    showToast(staticApi, opts)
  } else {
    // AntdProvider 未挂载（测试/极端时序）：退化为 console，别静默吞掉
    console.warn('[toast]', opts.title, opts.description)
  }
}

export function useToast() {
  const { message } = App.useApp()
  const toastFn = React.useCallback((opts: ToastOptions) => showToast(message, opts), [message])
  const dismiss = React.useCallback(() => message.destroy(), [message])
  return { toast: toastFn, dismiss }
}

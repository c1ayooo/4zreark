import { createContext, useContext, useState, type ReactNode } from 'react'

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'

export interface ConfirmOptions {
  title: string
  description?: string
  confirmText?: string
  cancelText?: string
  destructive?: boolean
}

type ConfirmFn = (opts: ConfirmOptions | string) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn | null>(null)

/**
 * 全局确认框：替代浏览器原生 confirm()。
 *
 * 原生 confirm 阻塞渲染线程、样式不受控、移动端文案不可改；这里统一用 AlertDialog，
 * 调用方仍然写 `if (await confirm({ title: '删除？' }))`，语义不变。
 *
 * 对话框只挂在 App 根部一份，页面里不需要各自渲染，避免每个页面都塞一段弹窗 JSX。
 */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{
    open: boolean
    opts: ConfirmOptions
    resolve?: (value: boolean) => void
  }>({ open: false, opts: { title: '' } })

  const confirm: ConfirmFn = (opts) =>
    new Promise<boolean>((resolve) => {
      setState({
        open: true,
        opts: typeof opts === 'string' ? { title: opts } : opts,
        resolve,
      })
    })

  const settle = (value: boolean) => {
    state.resolve?.(value)
    setState({ open: false, opts: { title: '' } })
  }

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <AlertDialog
        open={state.open}
        onOpenChange={(open) => {
          if (!open) settle(false)
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{state.opts.title}</AlertDialogTitle>
            {state.opts.description ? (
              <AlertDialogDescription>{state.opts.description}</AlertDialogDescription>
            ) : null}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => settle(false)}>
              {state.opts.cancelText || '取消'}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => settle(true)}
              className={
                state.opts.destructive
                  ? 'bg-destructive text-destructive-foreground hover:bg-destructive/90'
                  : undefined
              }
            >
              {state.opts.confirmText || '确认'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </ConfirmContext.Provider>
  )
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm 必须在 ConfirmProvider 内使用')
  return ctx
}

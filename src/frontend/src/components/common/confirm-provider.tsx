import { createContext, useContext, type ReactNode } from 'react'

import { Modal } from 'antd'

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
 * 原生 confirm 阻塞渲染线程、样式不受控、移动端文案不可改；这里统一用 antd Modal.confirm，
 * 调用方仍然写 `if (await confirm({ title: '删除？' }))`，语义不变。
 *
 * 对话框不需要挂在 App 根部，Modal.confirm 自己管理实例；这里保留 Provider 只是为了
 * 维持 useConfirm() 的调用形式，页面里不需要各自渲染弹窗 JSX。
 */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const confirm: ConfirmFn = (opts) => {
    const o: ConfirmOptions = typeof opts === 'string' ? { title: opts } : opts
    return new Promise<boolean>((resolve) => {
      Modal.confirm({
        title: o.title,
        content: o.description,
        okText: o.confirmText || '确认',
        cancelText: o.cancelText || '取消',
        okButtonProps: o.destructive ? { danger: true } : undefined,
        onOk: () => resolve(true),
        onCancel: () => resolve(false),
      })
    })
  }

  return <ConfirmContext.Provider value={confirm}>{children}</ConfirmContext.Provider>
}

export function useConfirm(): ConfirmFn {
  const ctx = useContext(ConfirmContext)
  if (!ctx) throw new Error('useConfirm 必须在 ConfirmProvider 内使用')
  return ctx
}

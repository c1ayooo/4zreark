import type { ReactNode } from 'react'
import { Tag } from 'antd'
import { cn } from '@/lib/utils'

// shadcn Badge variant → antd Tag 类名的唯一映射。
// 此前 15 个页面各手抄一份 badgeCls 且已各自分叉(warning/info 只有个别页有),
// 这里收敛为单一出处;新页面一律用 <StatusTag />,旧页面以 statusTagClass 委托。
export type BadgeVariant =
  | 'default'
  | 'secondary'
  | 'destructive'
  | 'outline'
  | 'success'
  | 'warning'
  | 'info'

const variantClass: Record<BadgeVariant, string> = {
  default: 'border-transparent bg-primary text-primary-foreground',
  success: 'border-transparent bg-primary text-primary-foreground',
  secondary: 'border-transparent bg-secondary text-secondary-foreground',
  destructive: 'border-transparent bg-destructive text-destructive-foreground',
  warning: 'border-transparent bg-yellow-500 text-black',
  info: 'border-transparent bg-blue-500 text-white',
  outline: 'text-foreground',
}

export function statusTagClass(variant: BadgeVariant): string {
  return variantClass[variant] ?? variantClass.default
}

export function StatusTag({
  variant = 'default',
  className,
  children,
}: {
  variant?: BadgeVariant
  className?: string
  children?: ReactNode
}) {
  return <Tag className={cn(statusTagClass(variant), className)}>{children}</Tag>
}

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
  // 纯白轻线（G 打样）：成功/警示/提示用柔色底 + 深色字的胶囊，不再用实心色块
  success: 'border-transparent bg-accent text-accent-foreground',
  secondary: 'border-transparent bg-secondary text-secondary-foreground',
  destructive: 'border-transparent bg-destructive text-destructive-foreground',
  warning: 'border-transparent bg-amber-500/15 text-amber-700 dark:text-amber-400',
  info: 'border-transparent bg-blue-500/15 text-blue-700 dark:text-blue-400',
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

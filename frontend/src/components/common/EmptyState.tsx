import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

import { cn } from '@/lib/utils'

interface EmptyStateProps {
  icon?: LucideIcon
  title: string
  description?: string
  /** 逐条说明「为什么现在是空的 / 数据从哪来 / 下一步做什么」 */
  hints?: string[]
  actions?: ReactNode
  className?: string
}

// EmptyState 是列表类页面的统一空态：
// 空表最容易让人以为「数据丢了」，所以这里强制要求写清楚原因与下一步动作。
export default function EmptyState({
  icon: Icon,
  title,
  description,
  hints,
  actions,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'mx-auto flex max-w-xl flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-10 text-center',
        className
      )}
    >
      {Icon && (
        <div className="bg-muted flex h-11 w-11 items-center justify-center rounded-full">
          <Icon className="text-muted-foreground h-5 w-5" />
        </div>
      )}
      <div className="text-sm font-medium">{title}</div>
      {description && <p className="text-muted-foreground text-sm leading-relaxed">{description}</p>}
      {hints && hints.length > 0 && (
        <ul className="text-muted-foreground space-y-1 text-left text-xs">
          {hints.map((h) => (
            <li key={h} className="flex gap-1.5">
              <span className="text-muted-foreground/60">·</span>
              <span>{h}</span>
            </li>
          ))}
        </ul>
      )}
      {actions && <div className="mt-1 flex flex-wrap items-center justify-center gap-2">{actions}</div>}
    </div>
  )
}

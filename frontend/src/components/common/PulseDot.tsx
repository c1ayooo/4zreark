import { cn } from '@/lib/utils'

// 运行态呼吸点：只传达「这一行 / 这个数正在动」，不做装饰性使用。
// 颜色走 bg-current 继承文字色——放在状态 Tag 里呈 Tag 前景色的点，
// 放在正文旁就是正文色的点；prefers-reduced-motion 下 ping 静止（index.css 全局规则）。
export function PulseDot({ className }: { className?: string }) {
  return (
    <span className={cn('relative inline-flex h-2 w-2 shrink-0', className)} aria-hidden="true">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-current opacity-60" />
      <span className="relative inline-flex h-2 w-2 rounded-full bg-current" />
    </span>
  )
}

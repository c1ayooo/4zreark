import type { ReactNode } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

// 页面路由过渡：fade + 4px 上移入场，快速淡出退场。
// 动效基调 150–250ms ease-out；reduced-motion 由 framer-motion 的
// MotionConfig(reducedMotion="user") 全局短路（AntdProvider 里）。
export function PageTransition({ routeKey, children }: { routeKey: string; children: ReactNode }) {
  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={routeKey}
        initial={{ opacity: 0, y: 4 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.18, ease: [0.215, 0.61, 0.355, 1] }}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  )
}

// 列表/卡片网格入场 stagger：子项 20ms 递进。
// 只用于小规模卡片网格，表格行与虚拟列表禁用（性能负资产）。
export function StaggerItem({
  index,
  children,
  className,
}: {
  index: number
  children: ReactNode
  className?: string
}) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: [0.215, 0.61, 0.355, 1], delay: Math.min(index * 0.02, 0.3) }}
    >
      {children}
    </motion.div>
  )
}

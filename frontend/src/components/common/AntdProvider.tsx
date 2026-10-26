import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { App as AntdApp, ConfigProvider, theme as antdTheme } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import 'dayjs/locale/zh-cn'
import dayjs from 'dayjs'
import { MotionConfig } from 'framer-motion'
import { useAppStore } from '@/store/app'
import { _registerToastApi } from '@/components/ui/use-toast'

dayjs.locale('zh-cn')

// 把 antd App 上下文里的 message 实例注册给 toast 兼容层（独立 toast() 用）
function ToastApiBridge() {
  const { message } = AntdApp.useApp()
  useEffect(() => {
    _registerToastApi(message)
  }, [message])
  return null
}

// HSL 字面量（"154 42% 28%"）→ hex。antd token 只吃颜色串，
// 每次主题变化时从 CSS 变量现读，保证与 Tailwind 侧同源。
function cssVarToHex(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  if (!raw) return fallback
  const m = raw.match(/^(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)%\s+(\d+(?:\.\d+)?)%$/)
  if (!m) return raw.startsWith('#') || raw.startsWith('rgb') ? raw : fallback
  const [, h, s, l] = m
  return hslToHex(Number(h), Number(s), Number(l))
}

function hslToHex(h: number, s: number, l: number): string {
  const a = (s / 100) * Math.min(l / 100, 1 - l / 100)
  const f = (n: number) => {
    const k = (n + h / 30) % 12
    const color = l / 100 - a * Math.max(-1, Math.min(k - 3, Math.min(9 - k, 1)))
    return Math.round(255 * color)
      .toString(16)
      .padStart(2, '0')
  }
  return `#${f(0)}${f(8)}${f(4)}`
}

// 主题解析：跟随 zustand 的 light/dark/system + 系统偏好变化。
// .dark class 由 store.applyTheme 维护，这里只消费结果。
function useResolvedDark(): boolean {
  const theme = useAppStore((s) => s.theme)
  const [systemDark, setSystemDark] = useState(
    () => typeof window !== 'undefined' && window.matchMedia('(prefers-color-scheme: dark)').matches,
  )
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (e: MediaQueryListEvent) => setSystemDark(e.matches)
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [])
  if (theme === 'dark') return true
  if (theme === 'light') return false
  return systemDark
}

export function AntdProvider({ children }: { children: ReactNode }) {
  const dark = useResolvedDark()
  // .dark class 切换后 CSS 变量已变，读值要晚一拍；用状态触发重算
  const [varEpoch, setVarEpoch] = useState(0)
  useEffect(() => {
    setVarEpoch((e) => e + 1)
  }, [dark])

  const themeConfig = useMemo(() => {
    void varEpoch
    const primary = cssVarToHex('--primary', dark ? '#3fc98a' : '#297a52')
    const bg = cssVarToHex('--background', dark ? '#11161b' : '#f5f7f9')
    const card = cssVarToHex('--card', dark ? '#161a20' : '#ffffff')
    const border = cssVarToHex('--border', dark ? '#323842' : '#d8dee4')
    const mutedFg = cssVarToHex('--muted-foreground', dark ? '#98a2b3' : '#5c6672')
    const destructive = cssVarToHex('--destructive', dark ? '#e05252' : '#b22424')
    return {
      algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
      token: {
        colorPrimary: primary,
        colorSuccess: primary,
        colorBgBase: bg,
        colorBgContainer: card,
        colorBgElevated: card,
        colorBorder: border,
        colorBorderSecondary: border,
        colorTextSecondary: mutedFg,
        colorError: destructive,
        colorWarning: '#d48806',
        // 圆角是明确的产品偏好：8/12px 的柔和圆角，与 Tailwind 侧 --radius: 0.5rem 对齐
        borderRadius: 8,
        borderRadiusLG: 12,
        fontFamily:
          "'Noto Sans SC Variable', 'Noto Sans SC', -apple-system, 'Segoe UI', Roboto, 'PingFang SC', 'Microsoft YaHei', sans-serif",
        fontSize: 14,
        // 动效基调：150–250ms、ease-out，与 framer-motion 侧同节奏
        motionDurationFast: '0.15s',
        motionDurationMid: '0.2s',
        motionDurationSlow: '0.25s',
        motionEaseOut: 'cubic-bezier(0.215, 0.61, 0.355, 1)',
      },
      components: {
        Table: { cellPaddingBlockSM: 6, cellPaddingInlineSM: 10, headerBg: dark ? '#1b2028' : '#f0f2f5' },
        Menu: { itemBorderRadius: 8, itemMarginInline: 6 },
        Modal: { contentBg: card, headerBg: card },
        Card: { paddingLG: 16 },
      },
    }
  }, [dark, varEpoch])

  return (
    <ConfigProvider locale={zhCN} theme={themeConfig}>
      {/* reduced-motion 一刀切：framer-motion 声明式降级；antd 侧由 overrides.css 兜 */}
      <MotionConfig reducedMotion="user">
        <AntdApp>
          <ToastApiBridge />
          {children}
        </AntdApp>
      </MotionConfig>
    </ConfigProvider>
  )
}

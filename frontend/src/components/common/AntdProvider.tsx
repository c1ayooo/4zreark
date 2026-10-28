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
    const primary = cssVarToHex('--primary', dark ? '#2fb569' : '#16a34a')
    const bg = cssVarToHex('--background', dark ? '#101216' : '#fbfbfd')
    const card = cssVarToHex('--card', dark ? '#141820' : '#ffffff')
    const border = cssVarToHex('--border', dark ? '#23272e' : '#ececf0')
    const mutedFg = cssVarToHex('--muted-foreground', dark ? '#8d94a3' : '#7c8089')
    const destructive = cssVarToHex('--destructive', dark ? '#e5476d' : '#e11d48')
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
        colorWarning: '#d97706',
        // 纯白轻线圆角体系：控件 12px、卡片/弹层 20px；按钮与标签另走 overrides 全胶囊
        borderRadius: 12,
        borderRadiusLG: 20,
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
        Table: {
          cellPaddingBlockSM: 6,
          cellPaddingInlineSM: 10,
          // 纯白轻线：表头无底色、淡色文字，行 hover 用轻灰
          headerBg: 'transparent',
          headerSplitColor: 'transparent',
          headerColor: mutedFg,
          rowHoverBg: dark ? '#1a1f27' : '#f4f4f6',
        },
        Menu: {
          // 侧栏菜单胶囊化：选中项 = 柔绿底 + 深绿字
          itemBorderRadius: 999,
          itemMarginInline: 8,
          itemHeight: 34,
          itemSelectedBg: cssVarToHex('--accent', dark ? '#1d3a28' : '#ecfdf3'),
          itemSelectedColor: cssVarToHex('--accent-foreground', dark ? '#7fd6a4' : '#14713f'),
        },
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

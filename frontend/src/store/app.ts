import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AppState {
  sidebarCollapsed: boolean
  theme: 'light' | 'dark' | 'system'
  // 侧栏分组展开状态：只存「展开」的组，未出现即收起。
  expandedGroups: string[]
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  toggleGroup: (id: string) => void
  setGroupExpanded: (id: string, expanded: boolean) => void
  setTheme: (theme: 'light' | 'dark' | 'system') => void
}

type Theme = AppState['theme']

// 把主题写到 <html> 上。启动、恢复持久化设置、system 跟随都走这里。
export function applyTheme(theme: Theme) {
  if (typeof document === 'undefined') return
  const prefersDark =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  const dark = theme === 'dark' || (theme === 'system' && prefersDark)
  document.documentElement.classList.toggle('dark', dark)
}

export const useAppStore = create<AppState>()(
  persist(
    (set) => ({
      sidebarCollapsed: false,
      theme: 'light',
      expandedGroups: ['overview'],
      toggleSidebar: () =>
        set((state) => ({ sidebarCollapsed: !state.sidebarCollapsed })),
      setSidebarCollapsed: (collapsed) => set({ sidebarCollapsed: collapsed }),
      toggleGroup: (id) =>
        set((state) => ({
          expandedGroups: state.expandedGroups.includes(id)
            ? state.expandedGroups.filter((g) => g !== id)
            : [...state.expandedGroups, id],
        })),
      setGroupExpanded: (id, expanded) =>
        set((state) => ({
          expandedGroups: expanded
            ? state.expandedGroups.includes(id)
              ? state.expandedGroups
              : [...state.expandedGroups, id]
            : state.expandedGroups.filter((g) => g !== id),
        })),
      setTheme: (theme) => {
        set({ theme })
        applyTheme(theme)
      },
    }),
    {
      name: 'app-storage',
    }
  )
)

// 首屏：localStorage 同步恢复后立刻应用，避免刷新回到浅色。
applyTheme(useAppStore.getState().theme)

// 持久化异步完成时再应用一次；system 模式跟随操作系统切换。
if (typeof window !== 'undefined') {
  useAppStore.persist?.onFinishHydration((state) => applyTheme(state.theme))
  const media = window.matchMedia('(prefers-color-scheme: dark)')
  const onChange = () => {
    if (useAppStore.getState().theme === 'system') applyTheme('system')
  }
  media.addEventListener?.('change', onChange)
}

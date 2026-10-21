import { Suspense, useEffect, useState } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import Sidebar from '@/components/layout/Sidebar'
import Header from '@/components/layout/Header'
import { useAppStore } from '@/store/app'
import { cn } from '@/lib/utils'

export default function MainLayout() {
  const { sidebarCollapsed } = useAppStore()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const location = useLocation()

  useEffect(() => {
    setMobileNavOpen(false)
  }, [location.pathname])

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <Sidebar mobileOpen={mobileNavOpen} onNavigate={() => setMobileNavOpen(false)} />
      {mobileNavOpen && (
        <button
          type="button"
          aria-label="关闭导航"
          className="fixed inset-0 z-40 bg-foreground/30 lg:hidden"
          onClick={() => setMobileNavOpen(false)}
        />
      )}
      <div
        className={cn(
          'flex min-w-0 flex-1 flex-col transition-[margin] duration-300',
          sidebarCollapsed ? 'lg:ml-16' : 'lg:ml-44'
        )}
      >
        <Header onMenuClick={() => setMobileNavOpen(true)} />
        <main className="flex-1 p-4 md:p-6">
          {/* Suspense 只包内容区：路由切换时侧栏与顶栏不重新挂载，避免整页闪烁。 */}
          <Suspense
            fallback={
              <div className="flex h-[60vh] items-center justify-center text-sm text-muted-foreground">
                加载中…
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </main>
        <footer className="border-t px-4 py-4 md:px-6">
          <p className="text-center text-xs text-muted-foreground">4zreark · c1ayoo</p>
        </footer>
      </div>
    </div>
  )
}

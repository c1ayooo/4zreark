import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '@/store/auth'
import { useAppStore } from '@/store/app'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { notifyApi, type InAppNotification } from '@/api/notify'
import { cn, formatDate } from '@/lib/utils'
import { Bell, CheckCheck, Sun, Moon, User, LogOut, Settings, Search, Menu, ChevronRight } from 'lucide-react'
import { navCurrentLabel } from '@/components/layout/Sidebar'
import { notificationLink } from '@/lib/notifyLink'
import { Input } from '@/components/ui/input'

const levelDot: Record<string, string> = {
  critical: 'bg-destructive',
  warning: 'bg-amber-500',
  info: 'bg-primary',
}

export default function Header({ onMenuClick }: { onMenuClick?: () => void }) {
  const navigate = useNavigate()
  const { user, logout } = useAuthStore()
  const { theme, setTheme } = useAppStore()
  const queryClient = useQueryClient()
  const [notifyOpen, setNotifyOpen] = useState(false)
  const location = useLocation()
  const breadcrumb = navCurrentLabel(location.pathname)
  const [query, setQuery] = useState('')

  const submitSearch = (e: React.FormEvent) => {
    e.preventDefault()
    const q = query.trim().replace(/"/g, '')
    if (!q) return
    // 资产页的 q 是 DSL（字段值必须带引号），全局搜索按全文检索 text="..." 拼。
    navigate(`/assets?q=${encodeURIComponent(`text="${q}"`)}`)
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const toggleTheme = () => {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }

  const unread = useQuery({
    queryKey: ['notify', 'unread'],
    queryFn: notifyApi.unreadCount,
    refetchInterval: 30_000,
    staleTime: 10_000,
  })

  const latest = useQuery({
    queryKey: ['notify', 'latest'],
    queryFn: () => notifyApi.listNotifications({ page: 1, page_size: 8 }),
    enabled: notifyOpen,
    staleTime: 5_000,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['notify'] })

  const markAll = useMutation({
    mutationFn: notifyApi.markAllRead,
    onSuccess: invalidate,
  })

  const markOne = useMutation({
    mutationFn: notifyApi.markRead,
    onSuccess: invalidate,
  })

  const unreadCount = unread.data?.data?.count ?? 0
  const items: InAppNotification[] = latest.data?.data?.items ?? []

  return (
    <header className="flex h-16 items-center justify-between border-b bg-card px-4 md:px-6">
      <div className="flex min-w-0 flex-1 items-center gap-3 md:gap-6">
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 lg:hidden"
          onClick={onMenuClick}
          aria-label="打开导航"
        >
          <Menu className="h-5 w-5" />
        </Button>
        <span className="shrink-0 text-sm font-semibold lg:hidden">4zreark</span>

        {/* 面包屑：分组 / 当前页，口径与侧栏一致 */}
        <nav className="hidden shrink-0 items-center gap-1.5 text-sm md:flex">
          <span className="text-muted-foreground">{breadcrumb.group}</span>
          <span className="text-muted-foreground/50">/</span>
          <span className="font-medium">{breadcrumb.label || '工作空间'}</span>
        </nav>

        {/* 全局搜索：回车跳到资产探索，命中域名/IP/站点价值最高 */}
        <form onSubmit={submitSearch} className="relative hidden w-full max-w-[380px] sm:block">
          <Search className="text-muted-foreground absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="搜索域名、IP 或站点…"
            className="h-9 border-transparent bg-muted/60 pl-9 pr-14"
          />
        </form>
      </div>

      <div className="flex items-center gap-2">
        {/* Theme Toggle */}
        <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label="切换主题">
          {theme === 'light' ? (
            <Moon className="h-5 w-5" />
          ) : (
            <Sun className="h-5 w-5" />
          )}
        </Button>

        {/* Notifications */}
        <DropdownMenu open={notifyOpen} onOpenChange={setNotifyOpen}>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon" className="relative" aria-label="通知">
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <span className="absolute -right-0.5 -top-0.5 min-w-4 rounded-full bg-destructive px-1 text-center text-xs leading-4 text-destructive-foreground">
                  {unreadCount > 99 ? '99+' : unreadCount}
                </span>
              )}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-[380px] p-0">
            <div className="flex items-center justify-between px-3 py-2">
              <span className="text-sm font-medium">通知</span>
              {unreadCount > 0 && (
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-xs"
                  disabled={markAll.isPending}
                  onClick={() => markAll.mutate()}
                >
                  <CheckCheck className="mr-1 h-3.5 w-3.5" />
                  全部已读
                </Button>
              )}
            </div>
            <DropdownMenuSeparator className="m-0" />

            <div className="max-h-[360px] overflow-y-auto">
              {latest.isLoading ? (
                <div className="px-3 py-8 text-center text-sm text-muted-foreground">加载中…</div>
              ) : items.length === 0 ? (
                <div className="px-3 py-8 text-center text-sm text-muted-foreground">暂无通知</div>
              ) : (
                items.map((n) => {
                  const target = notificationLink(n)
                  return (
                    <DropdownMenuItem
                      key={n.id}
                      className="flex cursor-pointer flex-col items-start gap-1 rounded-none px-3 py-2.5"
                      onSelect={() => {
                        if (!n.read) markOne.mutate(n.id)
                        setNotifyOpen(false)
                        if (target) navigate(target)
                      }}
                    >
                      <div className="flex w-full items-center gap-2">
                        <span className={cn('size-1.5 shrink-0 rounded-full', levelDot[n.level] ?? levelDot.info)} />
                        <span className={cn('min-w-0 truncate text-sm', !n.read && 'font-medium')}>
                          {n.title}
                        </span>
                        <span className="ml-auto shrink-0 text-xs text-muted-foreground">
                          {formatDate(n.created_at)}
                        </span>
                        {target && <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />}
                      </div>
                      {n.content && (
                        <p className="line-clamp-2 w-full whitespace-pre-wrap text-xs text-muted-foreground">
                          {n.content}
                        </p>
                      )}
                    </DropdownMenuItem>
                  )
                })
              )}
            </div>

            <DropdownMenuSeparator className="m-0" />
            <DropdownMenuItem
              className="justify-center py-2.5 text-sm"
              onSelect={() => {
                setNotifyOpen(false)
                navigate('/notify?tab=inbox')
              }}
            >
              查看全部
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* User Menu */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="gap-2" aria-label="账户菜单">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary">
                <User className="h-4 w-4 text-primary-foreground" />
              </div>
              <span className="hidden md:inline">{user?.nickname || user?.username}</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            <DropdownMenuLabel>我的账户</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate('/settings')}>
              <Settings className="mr-2 h-4 w-4" />
              设置
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={handleLogout} className="text-destructive">
              <LogOut className="mr-2 h-4 w-4" />
              退出登录
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}

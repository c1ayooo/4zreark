import { useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { cn } from '@/lib/utils'
import { useAppStore } from '@/store/app'
import { useAuthStore } from '@/store/auth'
import {
  LayoutDashboard,
  ListTodo,
  Shield,
  FileCode,
  HardDrive,
  Puzzle,
  Users,
  Settings,
  ChevronLeft,
  ChevronDown,
  Bell,
  Layers,
  Calendar,
  Network,
  Database,
  Rss,
  Briefcase,
  History,
  Share2,
  Activity,
  ShieldCheck,
  Smartphone,
  Building2,
  FileText,
  Fingerprint,
  Server,
  BookOpen,
  ScrollText,
  Wrench,
  Sprout,
  PieChart,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'

const ALL = ['admin', 'operator', 'user', 'viewer']
const OPS = ['admin', 'operator']
const ADMIN = ['admin']

interface MenuItem {
  path: string
  icon: typeof LayoutDashboard
  label: string
  roles?: string[]
}

interface MenuGroup {
  id: string
  label: string
  items: MenuItem[]
}

// 27 个入口按使用场景拆成 10 组，组标题可点击收起，当前路由所在分组自动展开。
const menuGroups: MenuGroup[] = [
  {
    id: 'overview',
    label: '概览',
    items: [
      { path: '/dashboard', icon: LayoutDashboard, label: '仪表盘', roles: ALL },
      { path: '/projects', icon: Briefcase, label: '项目管理', roles: ALL },
      { path: '/seeds', icon: Sprout, label: '种子', roles: ALL },
    ],
  },
  {
    id: 'assets',
    label: '资产',
    items: [
      { path: '/asset-overview', icon: PieChart, label: '资产总览', roles: ALL },
      { path: '/assets', icon: Database, label: '资产探索', roles: ALL },
      { path: '/topology', icon: Network, label: '资产星图', roles: ALL },
    ],
  },
  {
    id: 'footprint',
    label: '数字足迹',
    items: [
      { path: '/digital-assets', icon: Smartphone, label: '数字资产', roles: OPS },
      { path: '/enterprise', icon: Building2, label: '企业身份', roles: OPS },
      { path: '/local-documents', icon: FileText, label: '本地文档', roles: OPS },
    ],
  },
  {
    id: 'change',
    label: '变更与验证',
    items: [
      { path: '/events', icon: History, label: '变更时间线', roles: ALL },
      { path: '/verifications', icon: ShieldCheck, label: '验证状态', roles: ALL },
      { path: '/relations', icon: Share2, label: '关系图谱', roles: OPS },
    ],
  },
  {
    id: 'recon',
    label: '侦察任务',
    items: [
      { path: '/tasks', icon: ListTodo, label: '任务管理', roles: OPS },
      { path: '/cruise', icon: Calendar, label: '自动巡航', roles: OPS },
      { path: '/runs', icon: Activity, label: '执行记录', roles: OPS },
    ],
  },
  {
    id: 'intel',
    label: '情报库',
    items: [
      { path: '/fingerprints', icon: Fingerprint, label: '指纹库', roles: OPS },
      { path: '/sources', icon: Server, label: '数据源', roles: OPS },
      { path: '/dictionaries', icon: BookOpen, label: '字典', roles: OPS },
    ],
  },
  {
    id: 'vuln',
    label: '漏洞',
    items: [
      { path: '/vulnerabilities', icon: Shield, label: '漏洞管理', roles: OPS },
      { path: '/vuln-intel', icon: Rss, label: '漏洞情报', roles: OPS },
      { path: '/pocs', icon: FileCode, label: 'POC管理', roles: OPS },
    ],
  },
  {
    id: 'runtime',
    label: '节点与执行',
    items: [
      { path: '/nodes', icon: HardDrive, label: '节点管理', roles: ADMIN },
      { path: '/queue', icon: Layers, label: '任务队列', roles: ADMIN },
      { path: '/tools', icon: Wrench, label: '工具箱', roles: ADMIN },
    ],
  },
  {
    id: 'extend',
    label: '平台扩展',
    items: [
      { path: '/plugins', icon: Puzzle, label: '插件管理', roles: ADMIN },
      { path: '/notify', icon: Bell, label: '通知管理', roles: ADMIN },
    ],
  },
  {
    id: 'admin',
    label: '管理与安全',
    items: [
      { path: '/users', icon: Users, label: '用户管理', roles: ADMIN },
      { path: '/audit', icon: ScrollText, label: '审计日志', roles: ADMIN },
      { path: '/settings', icon: Settings, label: '系统设置', roles: ADMIN },
    ],
  },
]

function NavItem({
  item,
  collapsed,
  active,
  onNavigate,
}: {
  item: MenuItem
  collapsed: boolean
  active: boolean
  onNavigate?: () => void
}) {
  return (
    <Link
      to={item.path}
      onClick={onNavigate}
      className={cn(
        'flex items-center gap-3 rounded-sm px-3 py-1.5 text-[13px] transition-colors',
        active
          ? 'bg-muted text-foreground font-medium'
          : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground',
        collapsed && 'justify-center'
      )}
      title={collapsed ? item.label : undefined}
    >
      <item.icon
        className={cn('h-5 w-5 flex-shrink-0', active ? 'text-foreground' : '')}
      />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Link>
  )
}

// 面包屑用：把当前路径映射回「分组 / 菜单名」，找不到就退回工作空间。
export const navCurrentLabel = (pathname: string) => {
  let best: { group: string; label: string } = { group: '工作空间', label: '' }
  for (const group of menuGroups) {
    for (const item of group.items) {
      if (pathname === item.path || pathname.startsWith(`${item.path}/`)) {
        if (item.path.length >= best.label.length) best = { group: group.label, label: item.label }
      }
    }
  }
  return best
}

interface SidebarProps {
  mobileOpen?: boolean
  onNavigate?: () => void
}

export default function Sidebar({ mobileOpen = false, onNavigate }: SidebarProps = {}) {
  const location = useLocation()
  const {
    sidebarCollapsed,
    toggleSidebar,
    expandedGroups,
    toggleGroup,
    setGroupExpanded,
  } = useAppStore()
  const { user } = useAuthStore()
  const role = user?.role ?? 'viewer'
  // 手机抽屉打开时强制展开；桌面才遵循用户的收起状态。
  const collapsed = mobileOpen ? false : sidebarCollapsed

  const groups = menuGroups
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => !item.roles || item.roles.includes(role)),
    }))
    .filter((group) => group.items.length > 0)

  const isActive = (item: MenuItem) =>
    location.pathname === item.path || location.pathname.startsWith(`${item.path}/`)

  const activeGroupId = groups.find((group) => group.items.some(isActive))?.id

  // 只在「切换到另一个分组」时自动展开，避免用户手动收起当前组后被立刻弹开。
  const lastActiveGroupRef = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (activeGroupId && activeGroupId !== lastActiveGroupRef.current) {
      setGroupExpanded(activeGroupId, true)
      lastActiveGroupRef.current = activeGroupId
    }
  }, [activeGroupId, setGroupExpanded])

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-50 h-screen w-72 border-r bg-card transition-transform duration-300 lg:z-40 lg:translate-x-0',
        mobileOpen ? 'translate-x-0' : '-translate-x-full',
        collapsed ? 'lg:w-16' : 'lg:w-44'
      )}
    >
      {/* Logo */}
      <div className="flex h-16 items-center justify-between border-b px-4">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <img
              src="/icon-192x192.png"
              alt="4zreark"
              className="h-8 w-8 rounded-md dark:invert"
            />
            <span className="text-[15px] font-bold tracking-tight">4zreark</span>
          </div>
        )}
        {collapsed && (
          <img
            src="/icon-192x192.png"
            alt="4zreark"
            className="mx-auto h-8 w-8 rounded-md dark:invert"
          />
        )}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          aria-label={collapsed ? '展开侧栏' : '收起侧栏'}
          className={cn(
            'hidden h-8 w-8 hover:bg-black/10 hover:text-inherit lg:inline-flex',
            collapsed && 'mx-auto'
          )}
        >
          <ChevronLeft
            className={cn(
              'h-4 w-4 transition-transform',
              collapsed && 'rotate-180'
            )}
          />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          onClick={onNavigate}
          className="h-11 w-11 lg:hidden"
          aria-label="关闭导航"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Navigation：菜单项较多，必须让 nav 自己滚动，否则底部项会被裁掉。 */}
      <nav className="h-[calc(100vh-4rem)] overflow-y-auto p-2 pb-20">
        {collapsed ? (
          // 收起态只留图标，分组标题没有文字无法表达，直接平铺。
          <div className="space-y-1">
            {groups.flatMap((group) => group.items).map((item) => (
              <NavItem
                key={item.path}
                item={item}
                collapsed
                active={isActive(item)}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        ) : (
          <div className="space-y-1">
            {groups.map((group) => {
              const expanded = expandedGroups.includes(group.id)
              return (
                <div key={group.id}>
                  <button
                    type="button"
                    onClick={() => toggleGroup(group.id)}
                    aria-expanded={expanded}
                    className="flex w-full items-center justify-between gap-2 rounded-md px-3 py-1.5 text-[13px] font-semibold text-foreground transition-colors hover:bg-muted"
                  >
                    <span>{group.label}</span>
                    <ChevronDown
                      className={cn(
                        'h-3.5 w-3.5 shrink-0 transition-transform',
                        expanded ? 'rotate-0' : '-rotate-90'
                      )}
                    />
                  </button>
                  {expanded && (
                    <div className="mt-0.5 space-y-0.5">
                      {group.items.map((item) => (
                        <NavItem
                          key={item.path}
                          item={item}
                          collapsed={false}
                          active={isActive(item)}
                          onNavigate={onNavigate}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </nav>

      {/* 底部状态区：在线点 + 当前账号，参照 ScopesHub 的侧栏收尾 */}
      <div
        className={cn(
          'absolute bottom-0 left-0 right-0 border-t bg-card px-4 py-2.5 text-xs',
          collapsed && 'px-2'
        )}
      >
        <div className={cn('flex items-center gap-2', collapsed && 'justify-center')}>
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
          {!collapsed && (
            <span className="truncate text-muted-foreground">{user?.username || '未登录'}</span>
          )}
        </div>
        {!collapsed && (
          <div className="mt-0.5 truncate text-xs text-muted-foreground/70">
            {user?.role === 'admin' ? '管理员' : '只读 / 操作员'}
          </div>
        )}
      </div>
    </aside>
  )
}

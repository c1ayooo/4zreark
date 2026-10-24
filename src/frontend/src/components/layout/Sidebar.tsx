import { useEffect, useRef } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Button, Menu } from 'antd'
import type { MenuProps } from 'antd'
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
  Gauge,
  X,
} from 'lucide-react'

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
      { path: '/assets/fingerprint-scores', icon: Gauge, label: '指纹评分', roles: ALL },
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
  const navigate = useNavigate()
  const { sidebarCollapsed, toggleSidebar, expandedGroups, toggleGroup, setGroupExpanded } =
    useAppStore()
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

  // 子路径（/assets/fingerprint-scores）优先于父路径（/assets），避免两个菜单同时高亮。
  const activePath = groups
    .flatMap((group) => group.items.map((item) => item.path))
    .filter((path) => location.pathname === path || location.pathname.startsWith(`${path}/`))
    .sort((a, b) => b.length - a.length)[0]

  const activeGroupId = groups.find((group) => group.items.some((i) => i.path === activePath))?.id

  // 只在「切换到另一个分组」时自动展开，避免用户手动收起当前组后被立刻弹开。
  const lastActiveGroupRef = useRef<string | undefined>(undefined)
  useEffect(() => {
    if (activeGroupId && activeGroupId !== lastActiveGroupRef.current) {
      setGroupExpanded(activeGroupId, true)
      lastActiveGroupRef.current = activeGroupId
    }
  }, [activeGroupId, setGroupExpanded])

  // antd Menu items：分组 → SubMenu；收起态由 inlineCollapsed 承担（自带悬浮 tooltip）
  const items: MenuProps['items'] = collapsed
    ? groups.flatMap((group) =>
        group.items.map((item) => ({
          key: item.path,
          icon: <item.icon className="h-[17px] w-[17px]" style={{ fontSize: 0 }} />,
          label: item.label,
        })),
      )
    : groups.map((group) => ({
        key: group.id,
        label: group.label,
        children: group.items.map((item) => ({
          key: item.path,
          icon: <item.icon className="h-[17px] w-[17px]" style={{ fontSize: 0 }} />,
          label: item.label,
        })),
      }))

  const onMenuClick: MenuProps['onClick'] = ({ key }) => {
    navigate(String(key))
    onNavigate?.()
  }

  return (
    <aside
      className={cn(
        'fixed left-0 top-0 z-50 h-screen w-72 border-r bg-card transition-transform duration-300 lg:z-40 lg:translate-x-0',
        mobileOpen ? 'translate-x-0' : '-translate-x-full',
        collapsed ? 'lg:w-16' : 'lg:w-44'
      )}
    >
      {/* Logo：收起态只留居中的展开按钮，保证与下方图标列同轴 */}
      <div
        className={cn(
          'flex h-16 items-center justify-between border-b px-4',
          collapsed && 'justify-center'
        )}
      >
        {!collapsed && (
          <Link to="/dashboard" className="flex items-center gap-2">
            <img src="/icon-192x192.png" alt="4zreark" className="h-8 w-8 dark:invert" />
            <span className="text-[15px] font-bold tracking-tight">4zreark</span>
          </Link>
        )}
        {!collapsed && (
          <Button
            type="text"
            size="small"
            onClick={toggleSidebar}
            aria-label="收起侧栏"
            className="hidden h-8 w-8 lg:inline-flex"
            icon={<ChevronLeft className="h-4 w-4 transition-transform" />}
          />
        )}
        {collapsed && (
          <Button
            type="text"
            size="small"
            onClick={toggleSidebar}
            aria-label="展开侧栏"
            className="hidden h-8 w-8 lg:inline-flex"
            icon={<ChevronLeft className="h-4 w-4 rotate-180 transition-transform" />}
          />
        )}
        <Button
          type="text"
          className="h-11 w-11 lg:hidden"
          onClick={onNavigate}
          aria-label="关闭导航"
          icon={<X className="h-4 w-4" />}
        />
      </div>

      {/* Navigation：菜单项较多，必须让 nav 自己滚动，否则底部项会被裁掉。
          收起态隐藏滚动条并把菜单宽度贴合轨道，否则 antd 收起菜单按默认 80px
          居中，比 w-16 轨道宽 16px，图标整体右偏。 */}
      <nav className={cn('h-[calc(100vh-4rem)] overflow-y-auto pb-20', collapsed && 'scrollbar-none')}>
        <Menu
          mode="inline"
          inlineCollapsed={collapsed}
          items={items}
          selectedKeys={activePath ? [activePath] : []}
          openKeys={collapsed ? undefined : expandedGroups}
          onOpenChange={(keys) => {
            // 只有点组标题才会到这里；同步回 zustand 持久化
            for (const k of keys) {
              if (!expandedGroups.includes(String(k))) toggleGroup(String(k))
            }
            for (const g of expandedGroups) {
              if (!keys.includes(g)) toggleGroup(g)
            }
          }}
          onClick={onMenuClick}
          style={{ borderInlineEnd: 'none', background: 'transparent', fontSize: 13, width: '100%' }}
        />
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

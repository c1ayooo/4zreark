/**
 * 4zreark - 资产侦察与漏洞管理平台
 * 作者: c1ayoo
 */

import { lazy, useEffect, useState } from 'react'
import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { ConfirmProvider } from '@/components/common/confirm-provider'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/api/auth'
import MainLayout from '@/layouts/MainLayout'
import AuthLayout from '@/layouts/AuthLayout'
import { ErrorBoundary } from '@/components/ErrorBoundary'

// 路由级分包：每个页面独立 chunk，首屏只加载登录/布局与当前路由。
const LoginPage = lazy(() => import('@/pages/auth/LoginPage'))
const SetupPage = lazy(() => import('@/pages/auth/SetupPage'))
const DashboardPage = lazy(() => import('@/pages/dashboard/DashboardPage'))
const TasksPage = lazy(() => import('@/pages/tasks/TasksPage'))
const TaskDetailPage = lazy(() => import('@/pages/tasks/TaskDetailPage'))
const TaskCreatePage = lazy(() => import('@/pages/tasks/TaskCreatePage'))
const TaskLogsPage = lazy(() => import('@/pages/tasks/TaskLogsPage'))
const VulnerabilitiesPage = lazy(() => import('@/pages/vulnerabilities/VulnerabilitiesPage'))
const VulnerabilityDetailPage = lazy(() => import('@/pages/vulnerabilities/VulnerabilityDetailPage'))
const POCsPage = lazy(() => import('@/pages/pocs/POCsPage'))
const ToolkitPage = lazy(() => import('@/pages/tools/ToolkitPage'))
const GitHubLeakMonitorPage = lazy(() => import('@/pages/github-leak/GitHubLeakMonitorPage'))
const NodesPage = lazy(() => import('@/pages/nodes/NodesPage'))
const PluginsPage = lazy(() => import('@/pages/plugins/PluginsPage'))
const UsersPage = lazy(() => import('@/pages/users/UsersPage'))
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'))
const NotifyPage = lazy(() => import('@/pages/notify/NotifyPage'))
const SentinelOverviewPage = lazy(() => import('@/pages/sentinel/OverviewPage'))
const SentinelHighRiskFindingsPage = lazy(() => import('@/pages/sentinel/HighRiskFindingsPage'))
const SentinelReposPage = lazy(() => import('@/pages/sentinel/ReposPage'))
const SentinelCommitsPage = lazy(() => import('@/pages/sentinel/CommitsPage'))
const SentinelCommitDetailPage = lazy(() => import('@/pages/sentinel/CommitDetailPage'))
const TakeoverPage = lazy(() => import('@/pages/takeover/TakeoverPage'))
const QueuePage = lazy(() => import('@/pages/queue/QueuePage'))
const CruisePage = lazy(() =>
  import('@/pages/cruise').then((m) => ({ default: m.CruisePage }))
)
const TopologyPage = lazy(() => import('@/pages/topology/TopologyPage'))
const ProjectsPage = lazy(() => import('@/pages/projects/ProjectsPage'))
const ProjectDetailPage = lazy(() => import('@/pages/projects/ProjectDetailPage'))
const AssetsPage = lazy(() => import('@/pages/assets/AssetsPage'))
const AssetOverviewPage = lazy(() => import('@/pages/assets/AssetOverviewPage'))
const FingerprintScorePage = lazy(() => import('@/pages/assets/FingerprintScorePage'))
const SeedsPage = lazy(() => import('@/pages/seeds/SeedsPage'))
const AssetDetailPage = lazy(() => import('@/pages/assets/AssetDetailPage'))
const IntelPage = lazy(() => import('@/pages/intel/IntelPage'))
const EventsPage = lazy(() => import('@/pages/events/EventsPage'))
const RelationsPage = lazy(() => import('@/pages/relations/RelationsPage'))
const RunsPage = lazy(() => import('@/pages/runs/RunsPage'))
const VerificationsPage = lazy(() => import('@/pages/verifications/VerificationsPage'))
const DigitalAssetsPage = lazy(() => import('@/pages/digital-assets/DigitalAssetsPage'))
const EnterprisePage = lazy(() => import('@/pages/enterprise/EnterprisePage'))
const LocalDocumentsPage = lazy(() => import('@/pages/local-documents/LocalDocumentsPage'))
const FingerprintsPage = lazy(() => import('@/pages/fingerprints/FingerprintsPage'))
const AuditPage = lazy(() => import('@/pages/audit/AuditPage'))
const SourcesPage = lazy(() => import('@/pages/sources/SourcesPage'))
const DictionariesPage = lazy(() => import('@/pages/dictionaries/DictionariesPage'))
// CommitSentinel 工作台：对话 + 代码审计三页，共用主布局侧栏
const SentinelChatPage = lazy(() => import('@/pages/sentinel/chat/ChatWorkspace'))
const SentinelSkillsPage = lazy(() => import('@/pages/sentinel/skills/SkillsPage'))
const SentinelAnalysisTasksPage = lazy(() => import('@/pages/sentinel/audit/AnalysisTasksPage'))
const SentinelAnalysisResultsPage = lazy(() => import('@/pages/sentinel/audit/AnalysisResultsPage'))
const SentinelAnalysisArtifactsPage = lazy(
  () => import('@/pages/sentinel/audit/AnalysisArtifactsPage')
)

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

/**
 * 首次部署引导：系统还没有任何账号时，把所有访问引导到初始化页；
 * 已有账号后再访问 /setup 会被送回登录页（后端同样会拒绝再次初始化）。
 */
function BootstrapGate({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const [state, setState] = useState<'loading' | 'bootstrap' | 'ready'>('loading')

  useEffect(() => {
    let alive = true
    authApi
      .bootstrapStatus()
      .then((res) => {
        if (alive) setState(res.data?.needs_bootstrap ? 'bootstrap' : 'ready')
      })
      // 状态接口不可用时退回正常流程，避免整站白屏。
      .catch(() => {
        if (alive) setState('ready')
      })
    return () => {
      alive = false
    }
  }, [])

  if (state === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        正在检查系统状态…
      </div>
    )
  }

  if (state === 'bootstrap') {
    if (location.pathname !== '/setup') {
      return <Navigate to="/setup" replace />
    }
    return <>{children}</>
  }

  if (location.pathname === '/setup') {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <>
      <ErrorBoundary>
        {/* 全局确认框：替代浏览器原生 confirm()，样式与站内一致 */}
        <ConfirmProvider>
        <BootstrapGate>
        <Routes>
            {/* Auth routes */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/setup" element={<SetupPage />} />
            </Route>

            {/* 旧 demo 地址保留，重定向到新入口（已接入真实接口，需登录） */}

            {/* Protected routes */}
            <Route
              element={
                <ProtectedRoute>
                  <MainLayout />
                </ProtectedRoute>
              }
            >
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
            {/* CommitSentinel 工作台：数据来自 /api/sentinel/*，必须登录（JWT） */}
            <Route path="/sentinel/chat" element={<SentinelChatPage embedded />} />
            <Route path="/sentinel/skills" element={<SentinelSkillsPage />} />
            <Route path="/sentinel/audit/tasks" element={<SentinelAnalysisTasksPage />} />
            <Route path="/sentinel/audit/results" element={<SentinelAnalysisResultsPage />} />
            <Route path="/sentinel/audit/artifacts" element={<SentinelAnalysisArtifactsPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/topology" element={<TopologyPage />} />
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/projects/:id" element={<ProjectDetailPage />} />
            <Route path="/asset-overview" element={<AssetOverviewPage />} />
            <Route path="/assets" element={<AssetsPage />} />
            <Route path="/seeds" element={<SeedsPage />} />
            <Route path="/assets/:id" element={<AssetDetailPage />} />
            <Route path="/assets/fingerprint-scores" element={<FingerprintScorePage />} />
            <Route path="/events" element={<EventsPage />} />
            <Route path="/relations" element={<RelationsPage />} />
            <Route path="/runs" element={<RunsPage />} />
            <Route path="/verifications" element={<VerificationsPage />} />
            <Route path="/digital-assets" element={<DigitalAssetsPage />} />
            <Route path="/enterprise" element={<EnterprisePage />} />
            <Route path="/local-documents" element={<LocalDocumentsPage />} />
            <Route path="/fingerprints" element={<FingerprintsPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="/sources" element={<SourcesPage />} />
            <Route path="/dictionaries" element={<DictionariesPage />} />
            <Route path="/tasks" element={<TasksPage />} />
            <Route path="/tasklogs" element={<TaskLogsPage />} />
            <Route path="/tasks/new" element={<TaskCreatePage />} />
            <Route path="/tasks/:id" element={<TaskDetailPage />} />
            <Route path="/cruise" element={<CruisePage />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/vuln-intel" element={<IntelPage />} />
            <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
            <Route path="/pocs" element={<POCsPage />} />
            <Route path="/tools" element={<ToolkitPage />} />
            <Route path="/github-leaks" element={<GitHubLeakMonitorPage />} />
            <Route path="/takeover" element={<TakeoverPage />} />
                        <Route path="/sentinel" element={<SentinelOverviewPage />} />
            <Route path="/sentinel/high-risk" element={<SentinelHighRiskFindingsPage />} />
            <Route path="/sentinel/repos" element={<SentinelReposPage />} />
            <Route path="/sentinel/commits" element={<SentinelCommitsPage />} />
            <Route path="/sentinel/commits/:id" element={<SentinelCommitDetailPage />} />
            <Route path="/queue" element={<QueuePage />} />
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="/plugins" element={<PluginsPage />} />
            <Route path="/notify" element={<NotifyPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Routes>
        </BootstrapGate>
        </ConfirmProvider>
      </ErrorBoundary>
    </>
  )
}

export default App

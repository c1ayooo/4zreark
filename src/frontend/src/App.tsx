/**
 * 4zreark - 资产侦察与漏洞管理平台
 * 作者: c1ayoo
 */

import { lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from '@/components/ui/toaster'
import { ConfirmProvider } from '@/components/common/confirm-provider'
import { useAuthStore } from '@/store/auth'
import MainLayout from '@/layouts/MainLayout'
import AuthLayout from '@/layouts/AuthLayout'
import { ErrorBoundary } from '@/components/ErrorBoundary'

// 路由级分包：每个页面独立 chunk，首屏只加载登录/布局与当前路由。
const LoginPage = lazy(() => import('@/pages/auth/LoginPage'))
const DashboardPage = lazy(() => import('@/pages/dashboard/DashboardPage'))
const TasksPage = lazy(() => import('@/pages/tasks/TasksPage'))
const TaskDetailPage = lazy(() => import('@/pages/tasks/TaskDetailPage'))
const TaskCreatePage = lazy(() => import('@/pages/tasks/TaskCreatePage'))
const VulnerabilitiesPage = lazy(() => import('@/pages/vulnerabilities/VulnerabilitiesPage'))
const VulnerabilityDetailPage = lazy(() => import('@/pages/vulnerabilities/VulnerabilityDetailPage'))
const POCsPage = lazy(() => import('@/pages/pocs/POCsPage'))
const ToolkitPage = lazy(() => import('@/pages/tools/ToolkitPage'))
const NodesPage = lazy(() => import('@/pages/nodes/NodesPage'))
const PluginsPage = lazy(() => import('@/pages/plugins/PluginsPage'))
const UsersPage = lazy(() => import('@/pages/users/UsersPage'))
const SettingsPage = lazy(() => import('@/pages/settings/SettingsPage'))
const NotifyPage = lazy(() => import('@/pages/notify/NotifyPage'))
const MonitorPage = lazy(() => import('@/pages/monitor/MonitorPage'))
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

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()

  if (!isAuthenticated) {
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
        <Routes>
            {/* Auth routes */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<LoginPage />} />
            </Route>

            {/* Protected routes */}
            <Route
              element={
                <ProtectedRoute>
                  <MainLayout />
                </ProtectedRoute>
              }
            >
              <Route path="/" element={<Navigate to="/dashboard" replace />} />
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
            <Route path="/tasks/new" element={<TaskCreatePage />} />
            <Route path="/tasks/:id" element={<TaskDetailPage />} />
            <Route path="/cruise" element={<CruisePage />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/vuln-intel" element={<IntelPage />} />
            <Route path="/vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
            <Route path="/pocs" element={<POCsPage />} />
            <Route path="/tools" element={<ToolkitPage />} />
            <Route path="/takeover" element={<TakeoverPage />} />
            <Route path="/monitor" element={<MonitorPage />} />
            <Route path="/queue" element={<QueuePage />} />
            <Route path="/nodes" element={<NodesPage />} />
            <Route path="/plugins" element={<PluginsPage />} />
            <Route path="/notify" element={<NotifyPage />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Routes>
        </ConfirmProvider>
      </ErrorBoundary>
      <Toaster />
    </>
  )
}

export default App

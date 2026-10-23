import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import {
  Button,
  Dropdown,
  Input,
  Progress,
  Select,
  Tabs,
  Tag,
} from 'antd'
import { taskApi, type Task } from '@/api/tasks'
import { resultApi, type ResultType } from '@/api/results'
import TaskTopologyView from '@/components/tasks/TaskTopologyView'
import TaskAssetsView from '@/components/tasks/TaskAssetsView'
import { useToast } from '@/components/ui/use-toast'
import { useConfirm } from '@/components/common/confirm-provider'
import { getErrorMessage } from '@/lib/errors'
import TaskSettingsModal from './components/TaskSettingsModal'
import EditConfigModal from './components/EditConfigModal'
import { getStatusLabel } from './taskMeta'
import VulnDetailModal from './components/VulnDetailModal'
import {
  CrawlerResultsTable,
  DirScanResultsTable,
  GenericResultsTable,
  PortResultsTable,
  SensitiveResultsTable,
  ServiceResultsTable,
  SubdomainResultsTable,
  TakeoverResultsTable,
  UrlResultsTable,
  VulnResultsTable,
  type ResultsTableCtx,
} from './components/results'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import { 
  ArrowLeft, Play, Pause, Square, Trash2, RotateCcw, 
  Search, Download, Settings, ChevronDown,
  RefreshCw, Pencil
} from 'lucide-react'

// Tab 配置 - ID 对应后端 ResultType；assets 是任务级资产视图（非结果类型）
type TaskTabId = ResultType | 'assets'
const tabConfig: { id: TaskTabId; label: string }[] = [
  { id: 'assets', label: '本次任务资产' },
  { id: 'subdomain', label: '子域名' },
  { id: 'takeover', label: '子域名接管' },
  { id: 'app', label: 'APP' },
  { id: 'miniapp', label: '小程序' },
  { id: 'url', label: 'URL' },
  { id: 'crawler', label: '爬虫' },
  { id: 'sensitive', label: '敏感信息' },
  { id: 'dirscan', label: '目录扫描' },
  { id: 'vuln', label: '漏洞' },
  { id: 'port', label: '端口' },
  { id: 'service', label: 'Web服务' },
  { id: 'topology', label: '资产星图' },
]

export default function TaskDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  
  const [activeTab, setActiveTab] = useState<TaskTabId | null>(null)
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [selectedRows, setSelectedRows] = useState<string[]>([])
  const [selectedVuln, setSelectedVuln] = useState<Record<string, unknown> | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [statusCodeFilter, setStatusCodeFilter] = useState<string>('all')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  // 所有 hooks 必须在条件返回之前调用
  const { data, isLoading } = useQuery({
    queryKey: ['task', id],
    queryFn: () => taskApi.getTask(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const task = query.state.data?.data
      return task?.status === 'running' ? 3000 : false
    },
  })

  // 任务运行中时结果页签跟随刷新（此前运行期间结果是「死」的，只能切页签重挂刷新）
  const taskRunning = data?.data?.status === 'running'

  // 获取结果统计
  const { data: statsData } = useQuery({
    queryKey: ['task-results-stats', id],
    queryFn: () => resultApi.getResultStats(id!),
    enabled: !!id,
    refetchInterval: taskRunning ? 5000 : false,
  })

  // 默认落在「本次任务资产」：任务详情的第一诉求是这个任务产出了什么，而不是某个结果类型的原始流水。
  // 其余页签按需点开，仍保留结果明细。
  const resultStats = statsData?.data || {}
  useEffect(() => {
    if (activeTab === null && statsData?.data) {
      setActiveTab('assets')
    }
  }, [statsData?.data, activeTab])

  // 确保 activeTab 有值后再查询结果
  // 回落值必须是 tabConfig 里存在的页签：'domain' 不在其中，初载时 Tabs 会短暂无选中项
  const currentTab = activeTab || 'assets'

  // 获取当前Tab的结果数据（dirscan时支持状态码筛选）
  const statusCodeNum = statusCodeFilter !== 'all' ? parseInt(statusCodeFilter) : undefined
  
  // 端口数据使用聚合 API
  const { data: portResultsData, isLoading: portResultsLoading } = useQuery({
    queryKey: ['task-port-results', id, page, pageSize, search],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () => resultApi.getPortResults(id!, { page, pageSize, search }),
    enabled: !!id && currentTab === 'port',
    refetchInterval: taskRunning ? 5000 : false,
  })

  // 其他类型使用通用 API
  const { data: resultsData, isLoading: resultsLoading } = useQuery({
    queryKey: ['task-results', id, currentTab, page, pageSize, search, statusCodeFilter],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () => resultApi.getTaskResults(id!, { 
      type: currentTab as ResultType, 
      page, 
      pageSize,
      search,
      statusCode: currentTab === 'dirscan' ? statusCodeNum : undefined
    }),
    enabled: !!id && !!activeTab && currentTab !== 'port' && currentTab !== 'assets' && currentTab !== 'topology',
    refetchInterval: taskRunning ? 5000 : false,
  })

  // 任务操作 mutations
  const startMutation = useMutation({
    mutationFn: () => taskApi.startTask(id!),
    onSuccess: () => {
      toast({ title: '任务已开始' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const pauseMutation = useMutation({
    mutationFn: () => taskApi.pauseTask(id!),
    onSuccess: () => {
      toast({ title: '任务已暂停' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const resumeMutation = useMutation({
    mutationFn: () => taskApi.resumeTask(id!),
    onSuccess: () => {
      toast({ title: '任务已恢复' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const cancelMutation = useMutation({
    mutationFn: () => taskApi.cancelTask(id!),
    onSuccess: () => {
      toast({ title: '任务已停止' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const retryMutation = useMutation({
    mutationFn: () => taskApi.retryTask(id!),
    onSuccess: () => {
      toast({ title: '任务已重新启动' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const rescanMutation = useMutation({
    mutationFn: (fromScratch: boolean) => taskApi.rescanTask(id!, fromScratch),
    onSuccess: (_, fromScratch) => {
      toast({ title: fromScratch ? '任务已从头开始扫描' : '任务已继续扫描' })
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: () => toast({ title: '操作失败', variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: () => taskApi.deleteTask(id!),
    onSuccess: () => {
      toast({ title: '任务已删除' })
      navigate('/tasks')
    },
    onError: () => toast({ title: '删除失败', variant: 'destructive' }),
  })

  // 计算派生状态
  const isOperating = startMutation.isPending || pauseMutation.isPending || 
    resumeMutation.isPending || cancelMutation.isPending || 
    retryMutation.isPending || deleteMutation.isPending || rescanMutation.isPending

  const task = data?.data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const results: any[] = currentTab === 'port' 
    ? (portResultsData?.data?.list || [])
    : (resultsData?.data?.list || [])
  const total = currentTab === 'port'
    ? (portResultsData?.data?.total || 0)
    : (resultsData?.data?.total || 0)
  const isResultsLoading = currentTab === 'port' ? portResultsLoading : resultsLoading

  const updateConfigMutation = useMutation({
    mutationFn: (payload: { targets: string[]; config: Record<string, unknown> }) =>
      taskApi.updateTask(id!, { targets: payload.targets, config: { ...task!.config, ...payload.config } } as Partial<Task>),
    onSuccess: () => {
      toast({ title: '任务配置已更新' })
      setEditOpen(false)
      queryClient.invalidateQueries({ queryKey: ['task', id] })
    },
    onError: (e: unknown) =>
      toast({
        title: '保存失败',
        description: (e as { message?: string })?.message,
        variant: 'destructive',
      }),
  })

  const openEditConfig = () => {
    if (!task || task.status === 'running') return
    // 表单初值由 EditConfigModal 在 open 时自行从 task 初始化
    setEditOpen(true)
  }

  // 生成带统计数字的tabs
  // 页签只保留「这个任务会产生的结果类型」：
  // 全摆 12 个页签时，爬虫任务的「子域名 / 子域名接管」永远是空的，看着像数据丢了。
  // 规则：本任务资产 / 资产星图常驻；其余命中实际结果数或任务 config.scan_types 才显示。
  const tabScanSources: Record<string, string[]> = {
    subdomain: ['subdomain'],
    takeover: ['takeover'],
    app: ['app'],
    miniapp: ['miniapp'],
    url: ['crawler', 'dir_scan', 'sensitive'],
    crawler: ['crawler'],
    sensitive: ['sensitive'],
    dirscan: ['dir_scan'],
    vuln: ['vuln_scan'],
    port: ['port_scan', 'fingerprint', 'crawler', 'dir_scan', 'vuln_scan', 'sensitive'],
    service: ['fingerprint', 'port_scan'],
  }
  const taskScanTypes: string[] = Array.isArray(task?.config?.scan_types) ? task.config.scan_types : []

  const tabs = tabConfig
    .filter((tab) => {
      if (tab.id === 'assets' || tab.id === 'topology') return true
      if ((resultStats[tab.id] || 0) > 0) return true
      const sources = tabScanSources[tab.id] || []
      return sources.some((src) => taskScanTypes.includes(src))
    })
    .map((tab) => ({
      ...tab,
      count: resultStats[tab.id] || 0,
    }))

  // 条件渲染 - 在所有 hooks 之后
  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  if (!task) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="text-6xl mb-4">🔍</div>
        <h2 className="text-xl font-semibold text-foreground mb-2">任务不存在</h2>
        <p className="text-muted-foreground mb-6 text-center max-w-md">
          该任务可能已被删除，或任务ID无效。
          <br />
          <span className="text-xs text-muted-foreground/70">任务ID: {id}</span>
        </p>
        <Button type="primary" onClick={() => navigate('/tasks')}>返回任务列表</Button>
      </div>
    )
  }

  const handleSearch = () => {
    setSearch(searchInput)
    setPage(1)
  }

  const handleExport = async () => {
    try {
      const data = await resultApi.exportResults(id!, currentTab as ResultType)
      // 转换为CSV并下载
      const results = Array.isArray(data) ? data : (data as Record<string, unknown>)?.data || []
      const csvContent = convertToCSV(results as Record<string, unknown>[])
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${task?.name}-${currentTab}-${new Date().toISOString().slice(0, 10)}.csv`
      link.click()
      URL.revokeObjectURL(url)
      toast({ title: '导出成功' })
    } catch {
      toast({ title: '导出失败', variant: 'destructive' })
    }
  }

  // 转换为CSV格式
  const convertToCSV = (data: Record<string, unknown>[]) => {
    if (data.length === 0) return ''
    const headers = Object.keys(data[0])
    const rows = data.map(item => 
      headers.map(h => JSON.stringify(item[h] ?? '')).join(',')
    )
    return [headers.join(','), ...rows].join('\n')
  }

  // 删除任务：危险操作，先确认（替代原 AlertDialog）
  const handleDeleteTask = async () => {
    const ok = await confirm({
      title: '确认删除任务？',
      description: '此操作不可撤销。删除后，该任务及其所有相关数据将被永久删除。',
      confirmText: '删除',
      cancelText: '取消',
      destructive: true,
    })
    if (ok) deleteMutation.mutate()
  }

  // 10 个结果表共享的状态打包：表格只读字段，翻页/勾选/查看漏洞详情回调写回页面状态
  const resultsCtx: ResultsTableCtx = {
    results,
    total,
    page,
    pageSize,
    loading: isResultsLoading,
    selectedRows,
    onSelectedRowsChange: setSelectedRows,
    onPageChange: (p, s) => {
      setPage(p)
      setPageSize(s)
    },
    onViewVuln: setSelectedVuln,
  }

  // 渲染不同类型的表格
  const renderTable = () => {
    switch (currentTab) {
      case 'subdomain':
        return <SubdomainResultsTable ctx={resultsCtx} />
      case 'takeover':
        return <TakeoverResultsTable ctx={resultsCtx} />
      case 'url':
        return <UrlResultsTable ctx={resultsCtx} />
      case 'sensitive':
        return <SensitiveResultsTable ctx={resultsCtx} />
      case 'port':
        return <PortResultsTable ctx={resultsCtx} />
      case 'service':
        return <ServiceResultsTable ctx={resultsCtx} />
      case 'dirscan':
        return <DirScanResultsTable ctx={resultsCtx} />
      case 'crawler':
        return <CrawlerResultsTable ctx={resultsCtx} />
      case 'vuln':
        return <VulnResultsTable ctx={resultsCtx} />
      default:
        return <GenericResultsTable ctx={resultsCtx} />
    }
  }

  return (
    // 常规流式布局：此前用 -m-6 抵消 MainLayout 内边距做「满出血」页头，
    // md 以下布局 padding 是 16px 时会多抵 8px 导致内容贴边破版
    <div className="flex flex-col">
      {/* Header */}
      <div className="border-b bg-background px-1 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Button
              type="text"
              aria-label="返回任务列表"
              icon={<ArrowLeft className="h-5 w-5" />}
              onClick={() => navigate('/tasks')}
            />
            <div>
              <h1 className="text-xl font-semibold">{task.name}</h1>
              <div className="text-muted-foreground mt-1 max-w-[720px] truncate text-sm">
                目标：
                <span className="text-foreground font-mono">
                  {task.targets.length > 0 ? task.targets.join(', ') : '—'}
                </span>
              </div>
              <div className="flex items-center gap-2 mt-1">
                <Tag className={cn(getStatusColor(task.status), 'text-xs')}>
                  {getStatusLabel(task.status)}
                </Tag>
                {task.status === 'running' && (
                  <span className="text-sm text-blue-500 font-medium">
                    {task.progress}%
                    {task.progressDetails?.current_module && (
                      <span className="text-muted-foreground ml-1">
                        ({moduleLabels[task.progressDetails.current_module] || task.progressDetails.current_module})
                      </span>
                    )}
                  </span>
                )}
                <span className="text-muted-foreground text-sm">{task.type}</span>
                <span className="text-muted-foreground text-sm">•</span>
                <span className="text-muted-foreground text-sm">{formatDate(task.createdAt)}</span>
                {task.nodeId && (
                  <>
                    <span className="text-muted-foreground text-sm">•</span>
                    <span className="text-muted-foreground text-sm">执行节点: {task.nodeId}</span>
                  </>
                )}
                {task.status === 'running' && task.progressDetails?.elapsed_time && (
                  <>
                    <span className="text-muted-foreground text-sm">•</span>
                    <span className="text-muted-foreground text-sm">
                      已用: {task.progressDetails.elapsed_time}
                    </span>
                  </>
                )}
                {task.status === 'running' && task.progressDetails?.estimated_time_left && task.progressDetails.estimated_time_left !== '计算中...' && (
                  <>
                    <span className="text-muted-foreground text-sm">•</span>
                    <span className="text-muted-foreground text-sm">
                      剩余: {task.progressDetails.estimated_time_left}
                    </span>
                  </>
                )}
              </div>
              {/* 运行中时显示进度条 */}
              {task.status === 'running' && (
                <div className="mt-2 w-64">
                  <Progress percent={task.progress} showInfo={false} strokeWidth={8} />
                </div>
              )}
            </div>
          </div>
          
          {/* 操作按钮 */}
          <div className="flex items-center gap-2">
            <Button onClick={() => setSettingsOpen(true)}>
              <Settings className="h-4 w-4 mr-2" />
              任务设置
            </Button>
            <Button
              onClick={openEditConfig}
              disabled={isOperating || task.status === 'running'}
              title={task.status === 'running' ? '运行中不能改配置，请先点「停止」' : '修改任务目标与扫描配置'}
            >
              <Pencil className="h-4 w-4 mr-2" />
              编辑配置
            </Button>
            {task.status === 'pending' && (
              <Button type="primary" onClick={() => startMutation.mutate()} disabled={isOperating}>
                <Play className="h-4 w-4 mr-2" />
                开始
              </Button>
            )}
            {task.status === 'running' && (
              <>
                <Button onClick={() => pauseMutation.mutate()} disabled={isOperating}>
                  <Pause className="h-4 w-4 mr-2" />
                  暂停
                </Button>
                <Button danger onClick={() => cancelMutation.mutate()} disabled={isOperating}>
                  <Square className="h-4 w-4 mr-2" />
                  停止
                </Button>
              </>
            )}
            {task.status === 'paused' && (
              <>
                <Button type="primary" onClick={() => resumeMutation.mutate()} disabled={isOperating}>
                  <Play className="h-4 w-4 mr-2" />
                  继续
                </Button>
                <Button danger onClick={() => cancelMutation.mutate()} disabled={isOperating}>
                  <Square className="h-4 w-4 mr-2" />
                  停止
                </Button>
              </>
            )}
            {(task.status === 'failed' || task.status === 'cancelled') && (
              <Button type="primary" onClick={() => retryMutation.mutate()} disabled={isOperating}>
                <RotateCcw className="h-4 w-4 mr-2" />
                重试
              </Button>
            )}
            {(task.status === 'completed' || task.status === 'failed' || task.status === 'cancelled') && (
              <Dropdown
                trigger={['click']}
                menu={{
                  items: [
                    { key: 'continue', label: '继续未完成部分', onClick: () => rescanMutation.mutate(false) },
                    { key: 'scratch', label: '从头开始扫描（清空进度）', onClick: () => rescanMutation.mutate(true) },
                  ],
                }}
              >
                <Button disabled={isOperating}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  重新扫描
                </Button>
              </Dropdown>
            )}
            <Button
              danger
              aria-label="删除任务"
              icon={<Trash2 className="h-4 w-4" />}
              disabled={isOperating || task.status === 'running'}
              onClick={handleDeleteTask}
            />
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-background px-6">
        <Tabs
          activeKey={currentTab}
          onChange={(key) => {
            setActiveTab(key as TaskTabId)
            setPage(1)
            setSelectedRows([])
          }}
          items={tabs.map((tab) => ({
            key: tab.id,
            label: (
              <span className="inline-flex items-center">
                {tab.label}
                {tab.count > 0 && (
                  <span className="ml-2 text-xs bg-muted px-1.5 py-0.5 rounded">
                    {tab.count}
                  </span>
                )}
              </span>
            ),
          }))}
        />
      </div>

      {/* Toolbar - 资产星图与本任务资产自带工具条 */}
      {currentTab !== 'topology' && currentTab !== 'assets' && (
      <div className="border-b bg-background px-6 py-3">
        <div className="flex items-center gap-3">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 z-10 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="搜索"
              className="pl-9"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
          </div>
          <Button size="small" onClick={handleSearch}>
            <Search className="h-4 w-4 mr-2" />
            搜索
          </Button>
          <Button type="primary" size="small" onClick={handleExport}>
            <Download className="h-4 w-4 mr-2" />
            导出
          </Button>
          <Button
            size="small"
            icon={<RefreshCw className="h-4 w-4" />}
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ['task-results-stats', id] })
              queryClient.invalidateQueries({ queryKey: ['task-results', id] })
              queryClient.invalidateQueries({ queryKey: ['task-port-results', id] })
            }}
            title="刷新结果"
          >
            刷新结果
          </Button>
          {(() => {
            // 常驻渲染按需禁用：切 Tab 时工具栏几何形状不变
            const statusApplicable = currentTab === 'dirscan'
            return (
            <div className="flex items-center gap-1" title={statusApplicable ? undefined : '仅目录扫描结果支持按状态码筛选'}>
              <Select
                value={statusCodeFilter}
                onChange={(v) => { setStatusCodeFilter(v); setPage(1) }}
                className="w-28"
                placeholder="状态码"
                disabled={!statusApplicable}
                options={[
                  { value: 'all', label: '全部' },
                  { value: '200', label: '200' },
                  { value: '301', label: '301' },
                  { value: '302', label: '302' },
                  { value: '400', label: '400' },
                  { value: '401', label: '401' },
                  { value: '403', label: '403' },
                  { value: '404', label: '404' },
                  { value: '500', label: '500' },
                  { value: '502', label: '502' },
                  { value: '503', label: '503' },
                ]}
              />
              <Input
                type="number"
                placeholder="自定义"
                className="w-20 h-9"
                onChange={(e) => {
                  const val = e.target.value
                  setPage(1)
                  if (val === '' || val === '0') {
                    setStatusCodeFilter('all')
                  } else {
                    setStatusCodeFilter(val)
                  }
                }}
              />
            </div>
            )
          })()}
          <Dropdown
            trigger={['click']}
            menu={{
              items: [
                {
                  key: 'batch-delete',
                  label: '批量删除',
                  danger: true,
                  onClick: async () => {
                    const ok = await confirm({
                      title: `删除选中的 ${selectedRows.length} 条结果？`,
                      description: '删除后不可恢复。',
                      destructive: true,
                    })
                    if (!ok) return
                    try {
                      await resultApi.batchDelete(selectedRows)
                      toast({ title: '删除成功' })
                      setSelectedRows([])
                      queryClient.invalidateQueries({ queryKey: ['task-results', id] })
                    } catch (e) {
                      toast({ title: getErrorMessage(e, '删除失败'), variant: 'destructive' })
                    }
                  },
                },
              ],
            }}
          >
            <Button size="small" disabled={selectedRows.length === 0}>
              操作{selectedRows.length > 0 ? ` (${selectedRows.length})` : ''}
              <ChevronDown className="h-4 w-4 ml-2" />
            </Button>
          </Dropdown>
          <Button
            type="text"
            icon={<Settings className="h-4 w-4" />}
            onClick={() => setSettingsOpen(true)}
            title="任务设置"
          />
        </div>
      </div>
      )}

      <VulnDetailModal vuln={selectedVuln} onClose={() => setSelectedVuln(null)} />


      <EditConfigModal
        open={editOpen}
        task={task!}
        onClose={() => setEditOpen(false)}
        saving={updateConfigMutation.isPending}
        onSave={async (payload) => {
          await updateConfigMutation.mutateAsync(payload)
        }}
      />

      {/* Table Content or Topology View */}
            <TaskSettingsModal task={task} open={settingsOpen} onClose={() => setSettingsOpen(false)} />


      <div className={currentTab === 'topology' ? 'flex-1 overflow-hidden' : 'flex-1 overflow-auto'}>
        {currentTab === 'topology' ? (
          <TaskTopologyView taskId={id!} taskName={task?.name || ''} />
        ) : currentTab === 'assets' ? (
          <TaskAssetsView
            taskId={id!}
            taskStatus={task?.status}
            stats={resultStats as Record<string, number>}
            onOpenTab={(tab) => setActiveTab(tab as TaskTabId)}
            projectId={(task as any)?.project_id}
          />
        ) : (
          renderTable()
        )}
      </div>
    </div>
  )
}

const moduleLabels: Record<string, string> = {
  SubdomainScan: '子域名枚举',
  DomainVerify: '域名验证',
  PortPreparation: '端口预处理',
  PortScan: '端口扫描',
  Fingerprint: '指纹识别',
  VulnScan: '漏洞扫描',
  Crawler: 'Web 爬虫',
  DirScan: '目录扫描',
  Sensitive: '敏感信息',
}


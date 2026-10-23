import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import {
  Button,
  Checkbox,
  Dropdown,
  Input,
  Modal,
  Progress,
  Select,
  Table,
  Tabs,
  Tag,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { taskApi, type Task } from '@/api/tasks'
import { resultApi, type SubdomainResult, type ResultType } from '@/api/results'
import TaskTopologyView from '@/components/tasks/TaskTopologyView'
import TaskAssetsView from '@/components/tasks/TaskAssetsView'
import { useToast } from '@/components/ui/use-toast'
import { useConfirm } from '@/components/common/confirm-provider'
import { getErrorMessage } from '@/lib/errors'
import { DetailBlock } from './components/DetailBits'
import VulnDetailModal from './components/VulnDetailModal'
import { cn, formatDate, getSeverityColor, getStatusColor } from '@/lib/utils'
import { 
  ArrowLeft, Play, Pause, Square, Trash2, RotateCcw, 
  Search, Download, Settings, ChevronDown,
  RefreshCw, ExternalLink, Eye, Pencil
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

// shadcn Badge 变体 → antd Tag 的等价 className 映射（保持原视觉语义）
const TAG_PRIMARY = 'border-transparent bg-primary text-primary-foreground'
const TAG_SECONDARY = 'border-transparent bg-secondary text-secondary-foreground'
const TAG_DESTRUCTIVE = 'border-transparent bg-destructive text-destructive-foreground'

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
  const [editTargets, setEditTargets] = useState('')
  const [editScanTypes, setEditScanTypes] = useState<string[]>([])
  const [editPortMode, setEditPortMode] = useState('quick')
  const [editRate, setEditRate] = useState('10')
  const [editDelay, setEditDelay] = useState('500')
  const [editSubDict, setEditSubDict] = useState('')
  const [editDirDict, setEditDirDict] = useState('')
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
    mutationFn: () => {
      if (!task) return Promise.reject(new Error('任务不存在'))
      const targets = editTargets
        .split(/[\n,\s]+/)
        .map((t) => t.trim())
        .filter(Boolean)
      if (targets.length === 0) return Promise.reject(new Error('至少保留一个目标'))
      return taskApi.updateTask(id!, {
        targets,
        config: {
          ...task.config,
          scan_types: editScanTypes,
          port_scan_mode: editPortMode,
          rate_per_sec: Number(editRate) || 0,
          target_delay_ms: Number(editDelay) || 0,
          subdomain_dict_id: editSubDict.trim(),
          dir_dict_id: editDirDict.trim(),
        },
      } as Partial<Task>)
    },
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
    setEditTargets(task.targets.join('\n'))
    setEditScanTypes(task.config.scanTypes || [])
    setEditPortMode(task.config.port_scan_mode || 'quick')
    setEditRate(String(task.config.rate_per_sec || 10))
    setEditDelay(String(task.config.target_delay_ms || 500))
    setEditSubDict(task.config.subdomain_dict_id || '')
    setEditDirDict(task.config.dir_dict_id || '')
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

  const getStatusLabel = (status: string) => {
    const labels: Record<string, string> = {
      pending: '等待中',
      running: '运行中',
      paused: '已暂停',
      completed: '已完成',
      failed: '失败',
      cancelled: '已取消',
    }
    return labels[status] || status
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

  // antd Table 服务端分页：接现有 page/pageSize 状态（替代原手写分页 footer）
  const tablePagination = {
    current: page,
    pageSize,
    total,
    showQuickJumper: true,
    showSizeChanger: true,
    showTotal: (t: number) => `共 ${t} 条结果`,
    onChange: (p: number, s: number) => {
      setPage(p)
      setPageSize(s)
    },
  }

  // 行选择：key 统一为 string（port 表为 ip，其余为 id）
  const tableRowSelection = {
    selectedRowKeys: selectedRows,
    onChange: (keys: React.Key[]) => setSelectedRows(keys.map(String)),
    columnWidth: 48,
  }

  // 渲染不同类型的表格
  const renderTable = () => {
    switch (currentTab) {
      case 'subdomain':
        return renderSubdomainTable()
      case 'takeover':
        return renderTakeoverTable()
      case 'url':
        return renderURLTable()
      case 'sensitive':
        return renderSensitiveTable()
      case 'port':
        return renderPortTable()
      case 'service':
        return renderServiceTable()
      case 'dirscan':
        return renderDirScanTable()
      case 'crawler':
        return renderCrawlerTable()
      case 'vuln':
        return renderVulnTable()
      default:
        return renderGenericTable()
    }
  }

  const renderSubdomainTable = () => {
    const columns: ColumnsType<SubdomainResult> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: '子域名',
        key: 'subdomain',
        render: (_, item) => {
          // 兼容不同数据格式：subdomain 或 domain 字段
          const subdomainName = item.subdomain || item.domain || '-'
          return (
            <a 
              href={`https://${subdomainName}`} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-primary hover:underline flex items-center gap-1"
            >
              {subdomainName}
              <ExternalLink className="h-3 w-3" />
            </a>
          )
        },
      },
      {
        title: 'IP',
        key: 'ips',
        width: 150,
        className: 'text-muted-foreground font-mono text-xs',
        render: (_, item) => item.ips?.join(', ') || (item as unknown as { ip?: string }).ip || '-',
      },
      { title: '标题', key: 'title', width: 200, ellipsis: true, render: (_, item) => item.title || '-' },
      {
        title: '状态码',
        key: 'statusCode',
        width: 90,
        render: (_, item) => (
          item.statusCode && item.statusCode > 0 ? (
            <Tag className={item.statusCode === 200 ? TAG_PRIMARY : TAG_SECONDARY}>
              {item.statusCode}
            </Tag>
          ) : (
            <Tag className="text-muted-foreground">-</Tag>
          )
        ),
      },
      {
        title: 'CDN',
        key: 'cdn',
        width: 120,
        render: (_, item) => (
          item.cdn ? (
            <Tag>{item.cdnName || item.cdnProvider || 'CDN'}</Tag>
          ) : '-'
        ),
      },
      {
        title: '指纹',
        key: 'fingerprint',
        width: 200,
        render: (_, item) => (
          (item.technologies?.slice(0, 2) || item.fingerprint?.slice(0, 2))?.map((fp: string) => (
            <Tag key={fp} className="mr-1 text-xs">{fp}</Tag>
          )) || '-'
        ),
      },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1000 }}
      />
    )
  }

  // 子域名接管检测结果表格
  const renderTakeoverTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      { title: '子域名', key: 'subdomain', width: 220, className: 'font-mono', render: (_, item) => item.subdomain as string },
      { title: 'CNAME', key: 'cname', width: 200, ellipsis: true, className: 'font-mono text-xs', render: (_, item) => item.cname as string || '-' },
      { title: '服务商', key: 'provider', width: 120, render: (_, item) => <Tag>{item.provider as string || '-'}</Tag> },
      {
        title: '风险等级',
        key: 'severity',
        width: 100,
        render: (_, item) => (
          <Tag 
            className={
              (item.severity as string) === 'high' 
                ? TAG_DESTRUCTIVE
                : (item.severity as string) === 'medium'
                  ? TAG_SECONDARY
                  : undefined
            }
          >
            {(item.severity as string) || '高'}
          </Tag>
        ),
      },
      {
        title: '原因',
        key: 'reason',
        width: 300,
        ellipsis: true,
        render: (_, item) => <span title={item.reason as string}>{item.reason as string || '-'}</span>,
      },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        rowClassName={(item) => ((item.vulnerable as boolean) ? 'bg-destructive/5' : '')}
        sticky
        scroll={{ x: 1000 }}
      />
    )
  }

  const renderURLTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: 'URL',
        key: 'url',
        width: 400,
        ellipsis: true,
        render: (_, item) => (
          <a 
            href={item.url as string} 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            {item.url as string}
          </a>
        ),
      },
      { title: '方法', key: 'method', width: 90, render: (_, item) => <Tag>{(item.method as string) || 'GET'}</Tag> },
      {
        title: '状态码',
        key: 'statusCode',
        width: 90,
        render: (_, item) => (
          <Tag className={(item.statusCode as number) === 200 ? TAG_PRIMARY : TAG_SECONDARY}>
            {item.statusCode as number || '-'}
          </Tag>
        ),
      },
      { title: '类型', key: 'contentType', width: 160, className: 'text-muted-foreground', render: (_, item) => item.contentType as string || '-' },
      { title: '长度', key: 'length', width: 90, className: 'text-muted-foreground', render: (_, item) => item.length as number || '-' },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1000 }}
      />
    )
  }

  const renderSensitiveTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: 'URL',
        key: 'url',
        width: 300,
        ellipsis: true,
        render: (_, item) => (
          <a 
            href={item.url as string} 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            {item.url as string}
          </a>
        ),
      },
      { title: '类型', key: 'type', width: 110, render: (_, item) => <Tag>{item.type as string}</Tag> },
      { title: '模式', key: 'pattern', width: 140, className: 'text-muted-foreground', render: (_, item) => item.pattern as string },
      {
        title: '匹配内容',
        key: 'matches',
        width: 200,
        ellipsis: true,
        className: 'font-mono text-xs',
        render: (_, item) => (
          <span title={Array.isArray(item.matches) ? (item.matches as string[]).join(', ') : ''}>
            {Array.isArray(item.matches) ? (item.matches as string[]).slice(0, 2).join(', ') : '-'}
            {Array.isArray(item.matches) && (item.matches as string[]).length > 2 && '...'}
          </span>
        ),
      },
      {
        title: '级别',
        key: 'severity',
        width: 100,
        render: (_, item) => (
          <Tag 
            className={
              (item.severity as string) === 'critical' || (item.severity as string) === 'high' ? TAG_DESTRUCTIVE :
              (item.severity as string) === 'medium' ? TAG_PRIMARY : TAG_SECONDARY
            }
          >
            {item.severity as string}
          </Tag>
        ),
      },
      { title: '位置', key: 'location', width: 110, className: 'text-muted-foreground', render: (_, item) => item.location as string },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1100 }}
      />
    )
  }

  const renderPortTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      { title: 'IP', key: 'ip', width: 160, className: 'font-mono', render: (_, item) => item.ip as string },
      {
        title: '端口',
        key: 'ports',
        render: (_, item) => {
          const ports = (item.ports as string[]) || []
          return (
            <div className="flex flex-wrap gap-1">
              {ports.slice(0, 10).map((port, i) => (
                <Tag key={i} className="text-xs">
                  {port}
                </Tag>
              ))}
              {ports.length > 10 && (
                <Tag className={cn(TAG_SECONDARY, 'text-xs')}>+{ports.length - 10}</Tag>
              )}
            </div>
          )
        },
      },
      {
        title: '服务',
        key: 'services',
        render: (_, item) => {
          const services = (item.services as string[]) || []
          return (
            <div className="flex flex-wrap gap-1">
              {[...new Set(services.filter(Boolean))].slice(0, 5).map((s: string, i) => (
                <Tag key={i} className={cn(TAG_SECONDARY, 'text-xs')}>{s}</Tag>
              ))}
              {[...new Set(services.filter(Boolean))].length > 5 && (
                <Tag className="text-xs">+{[...new Set(services.filter(Boolean))].length - 5}</Tag>
              )}
            </div>
          )
        },
      },
      { title: '时间', key: 'created_at', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.created_at as string) },
    ]
    return (
      <Table
        rowKey="ip"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: isResultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 900 }}
      />
    )
  }

  const renderServiceTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: 'URL',
        key: 'url',
        render: (_, item) => (
          <a 
            href={item.url as string} 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-primary hover:underline flex items-center gap-1 max-w-xs truncate"
          >
            {item.url as string}
            <ExternalLink className="h-3 w-3 flex-shrink-0" />
          </a>
        ),
      },
      {
        title: '标题',
        key: 'title',
        width: 200,
        ellipsis: true,
        render: (_, item) => <span title={item.title as string}>{item.title as string || '-'}</span>,
      },
      {
        title: '状态码',
        key: 'status_code',
        width: 90,
        render: (_, item) => (
          <Tag 
            className={
              (item.status_code as number) >= 200 && (item.status_code as number) < 300 ? TAG_PRIMARY :
              (item.status_code as number) >= 300 && (item.status_code as number) < 400 ? TAG_SECONDARY :
              (item.status_code as number) >= 400 ? TAG_DESTRUCTIVE : undefined
            }
          >
            {item.status_code as number || '-'}
          </Tag>
        ),
      },
      { title: 'Server', key: 'server', width: 140, className: 'text-muted-foreground', render: (_, item) => item.server as string || '-' },
      {
        title: '技术栈',
        key: 'technologies',
        width: 180,
        render: (_, item) => (
          (item.technologies as string[])?.slice(0, 3).map((tech: string) => (
            <Tag key={tech} className="mr-1 text-xs">{tech}</Tag>
          ))
        ),
      },
      {
        title: '指纹',
        key: 'fingerprints',
        width: 160,
        render: (_, item) => (
          (item.fingerprints as string[])?.slice(0, 2).map((fp: string) => (
            <Tag key={fp} className={cn(TAG_SECONDARY, 'mr-1 text-xs')}>{fp}</Tag>
          ))
        ),
      },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1100 }}
      />
    )
  }

  const renderDirScanTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: 'URL',
        key: 'url',
        width: 400,
        ellipsis: true,
        render: (_, item) => {
          // 从 data 字段中提取数据
          const data = (item.data || item) as Record<string, unknown>
          return (
            <a 
              href={data.url as string} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {data.url as string}
            </a>
          )
        },
      },
      {
        title: '状态码',
        key: 'status',
        width: 90,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.status ? (
            <Tag 
              className={
                (data.status as number) >= 200 && (data.status as number) < 300 ? TAG_PRIMARY : 
                (data.status as number) >= 400 ? TAG_DESTRUCTIVE : TAG_SECONDARY
              }
            >
              {data.status as number}
            </Tag>
          ) : '-'
        },
      },
      {
        title: '大小',
        key: 'size',
        width: 90,
        className: 'text-muted-foreground',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.size ? `${data.size}` : '-'
        },
      },
      {
        title: '类型',
        key: 'content_type',
        width: 140,
        className: 'text-muted-foreground text-xs',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.content_type as string || '-'
        },
      },
      {
        title: '目标',
        key: 'target',
        width: 150,
        ellipsis: true,
        className: 'text-muted-foreground',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.target as string || '-'
        },
      },
      {
        title: '时间',
        key: 'createdAt',
        width: 160,
        className: 'text-muted-foreground',
        render: (_, item) => formatDate(item.createdAt as string),
      },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1000 }}
      />
    )
  }

  const renderCrawlerTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: 'URL',
        key: 'url',
        width: 400,
        ellipsis: true,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (
            <a 
              href={data.url as string} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {data.url as string}
            </a>
          )
        },
      },
      {
        title: '方法',
        key: 'method',
        width: 90,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return <Tag>{(data.method as string) || 'GET'}</Tag>
        },
      },
      {
        title: '状态码',
        key: 'status_code',
        width: 90,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.status_code ? (
            <Tag 
              className={
                (data.status_code as number) === 200 ? TAG_PRIMARY : 
                (data.status_code as number) >= 400 ? TAG_DESTRUCTIVE : TAG_SECONDARY
              }
            >
              {data.status_code as number}
            </Tag>
          ) : '-'
        },
      },
      {
        title: '爬虫',
        key: 'crawler',
        width: 120,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (
            <Tag className="text-xs">
              {(data.crawler as string) || (item.source as string) || '-'}
            </Tag>
          )
        },
      },
      {
        title: '目标',
        key: 'target',
        width: 150,
        ellipsis: true,
        className: 'text-muted-foreground',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return data.target as string || '-'
        },
      },
      {
        title: '时间',
        key: 'createdAt',
        width: 160,
        className: 'text-muted-foreground',
        render: (_, item) => formatDate(item.createdAt as string),
      },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1000 }}
      />
    )
  }

  const renderVulnTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      {
        title: '等级',
        key: 'severity',
        width: 80,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          const severity = String(data.severity || '').toLowerCase()
          return (
            <Tag className={cn(getSeverityColor(severity), 'text-xs')}>
              {severity || 'unknown'}
            </Tag>
          )
        },
      },
      {
        title: '漏洞名称',
        key: 'name',
        width: 320,
        ellipsis: true,
        className: 'font-medium',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (data.name as string) || (data.vuln_id as string) || '-'
        },
      },
      {
        title: '目标',
        key: 'target',
        width: 240,
        ellipsis: true,
        className: 'font-mono text-xs',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (data.target as string) || '-'
        },
      },
      {
        title: '匹配位置',
        key: 'matched_at',
        width: 260,
        ellipsis: true,
        className: 'font-mono text-xs text-muted-foreground',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (data.matched_at as string) || '-'
        },
      },
      {
        title: '来源',
        key: 'source',
        width: 112,
        className: 'text-muted-foreground',
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (item.source as string) || (data.source as string) || '-'
        },
      },
      {
        title: '操作',
        key: 'actions',
        width: 96,
        render: (_, item) => {
          const data = (item.data || item) as Record<string, unknown>
          return (
            <Button
              type="text"
              size="small"
              onClick={() => setSelectedVuln(data)}
            >
              <Eye className="h-4 w-4 mr-1" />
              详情
            </Button>
          )
        },
      },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无漏洞' }}
        sticky
        scroll={{ x: 1100 }}
      />
    )
  }

  const renderGenericTable = () => {
    const columns: ColumnsType<Record<string, unknown>> = [
      { title: '序号', key: 'index', width: 64, className: 'text-muted-foreground', render: (_, __, index) => (page - 1) * pageSize + index + 1 },
      {
        title: '数据',
        key: 'data',
        width: 400,
        ellipsis: true,
        className: 'font-mono text-xs',
        render: (_, item) => JSON.stringify(item.data || item),
      },
      { title: '项目', key: 'project', width: 140, render: (_, item) => item.project as string || '-' },
      {
        title: 'TAG',
        key: 'tags',
        width: 200,
        render: (_, item) => (
          (item.tags as string[])?.length > 0 ? (
            (item.tags as string[]).map((tag: string) => (
              <Tag key={tag} className="mr-1">{tag}</Tag>
            ))
          ) : '-'
        ),
      },
      { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
    ]
    return (
      <Table
        rowKey="id"
        columns={columns}
        dataSource={results}
        rowSelection={tableRowSelection}
        pagination={tablePagination}
        locale={{ emptyText: resultsLoading ? '加载中...' : '暂无数据' }}
        sticky
        scroll={{ x: 1000 }}
      />
    )
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


      {/* 编辑配置：运行中只读，先停止再改 */}
      <Modal
        open={editOpen}
        onCancel={() => setEditOpen(false)}
        title="编辑任务配置"
        width={672}
        footer={null}
      >
        <div className="space-y-3 py-2">
          <div className="space-y-1">
            <label className="text-sm font-medium">扫描目标（每行一个）</label>
            <Input.TextArea
              rows={3}
              className="font-mono text-xs"
              value={editTargets}
              onChange={(e) => setEditTargets(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">扫描类型</label>
            <div className="grid gap-2 sm:grid-cols-3">
              {Object.entries(scanTypeLabels).map(([id, label]) => (
                <label key={id} className="flex items-center gap-2 rounded-md border px-2 py-1.5 text-sm">
                  <Checkbox
                    checked={editScanTypes.includes(id)}
                    onChange={(e) =>
                      setEditScanTypes((prev) =>
                        e.target.checked ? [...prev, id] : prev.filter((x) => x !== id)
                      )
                    }
                  />
                  {label}
                </label>
              ))}
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">端口模式</label>
              <Select
                value={editPortMode}
                onChange={(v) => setEditPortMode(v)}
                className="w-full"
                options={[
                  { value: 'quick', label: '快速' },
                  { value: 'top1000', label: 'Top 1000' },
                  { value: 'full', label: '全端口' },
                ]}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">限速（req/s）</label>
              <Input value={editRate} onChange={(e) => setEditRate(e.target.value)} />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">目标间隔（ms）</label>
              <Input value={editDelay} onChange={(e) => setEditDelay(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1">
              <label className="text-sm font-medium">子域字典 ID（留空内置）</label>
              <Input value={editSubDict} onChange={(e) => setEditSubDict(e.target.value)} placeholder="dictionaries.id" />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">目录字典 ID（留空 spray 默认）</label>
              <Input value={editDirDict} onChange={(e) => setEditDirDict(e.target.value)} placeholder="dictionaries.id" />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button onClick={() => setEditOpen(false)}>取消</Button>
            <Button type="primary" onClick={() => updateConfigMutation.mutate()} disabled={updateConfigMutation.isPending}>
              保存配置
            </Button>
          </div>
        </div>
      </Modal>

      {/* Table Content or Topology View */}
      <Modal
        open={settingsOpen}
        onCancel={() => setSettingsOpen(false)}
        title="任务设置"
        width={672}
        footer={null}
      >
        <div className="space-y-3 py-2 text-sm">
          <div className="grid gap-3 sm:grid-cols-2">
            <DetailBlock label="任务类型" value={task.type} />
            <DetailBlock label="当前状态" value={getStatusLabel(task.status)} />
            <DetailBlock label="归属项目" value={`#${task.projectId ?? 0}`} />
            <DetailBlock label="执行节点" value={task.nodeId || '自动选择'} />
            <DetailBlock
              label="扫描节奏"
              value={
                task.config.rate_per_sec
                  ? `${task.config.rate_per_sec} req/s · 目标间隔 ${task.config.target_delay_ms ?? 0}ms`
                  : '默认（未显式限速）'
              }
            />
            <DetailBlock label="端口模式" value={task.config.port_scan_mode || 'quick'} />
            <DetailBlock label="超时 / 并发" value={`${task.config.timeout ?? '默认'}s / ${task.config.concurrent ?? '默认'}`} />
            <DetailBlock label="创建时间" value={formatDate(task.createdAt)} />
          </div>

          <div>
            <div className="text-muted-foreground text-xs">扫描类型</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {(task.config.scanTypes || []).length === 0 ? (
                <span className="text-muted-foreground text-xs">未显式配置</span>
              ) : (
                (task.config.scanTypes || []).map((t) => (
                  <Tag key={t} className={cn(TAG_SECONDARY, 'text-xs')}>
                    {scanTypeLabels[t] || t}
                  </Tag>
                ))
              )}
            </div>
          </div>

          <div>
            <div className="text-muted-foreground text-xs">扫描目标</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {task.targets.map((t) => (
                <Tag key={t} className="font-mono text-xs">
                  {t}
                </Tag>
              ))}
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <DetailBlock
              label="子域字典"
              value={
                task.config.subdomain_dict_id
                  ? `${task.config.subdomain_dict_id} · ${task.config.subdomain_wordlist?.length ?? 0} 条`
                  : '内置词表'
              }
            />
            <DetailBlock
              label="目录字典"
              value={
                task.config.dir_dict_id
                  ? `${task.config.dir_dict_id} · ${task.config.dir_wordlist?.length ?? 0} 条`
                  : 'spray 默认字典'
              }
            />
          </div>

          <details className="rounded-md border p-3">
            <summary className="text-muted-foreground cursor-pointer text-xs">原始配置 JSON</summary>
            <pre className="bg-muted/50 mt-2 max-h-64 overflow-auto rounded p-2 font-mono text-xs">
              {JSON.stringify(task.config, null, 2)}
            </pre>
          </details>
        </div>
      </Modal>

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

const scanTypeLabels: Record<string, string> = {
  subdomain: '子域名枚举',
  takeover: '子域名接管',
  port_scan: '端口扫描',
  fingerprint: '指纹识别',
  crawler: 'Web 爬虫',
  dir_scan: '目录扫描',
  sensitive: '敏感信息',
  vuln_scan: '漏洞扫描',
  service_detect: '服务识别',
  exposure_scan: '暴露面探测',
  clue_hunt: '存量线索',
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


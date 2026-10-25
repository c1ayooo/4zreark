import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { cruiseApi, CruiseTask, CruiseCreateRequest, CruiseTargetPreview } from '@/api/cruise'
import { enterpriseApi, type EnterpriseProvider } from '@/api/enterprise'
import { projectApi } from '@/api/projects'
import { seedCollectionApi, CruiseOverviewRow } from '@/api/seedCollection'
import { Badge, Button, Card, Input, Modal, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import { useConfirm } from '@/components/common/confirm-provider'
import { formatDate } from '@/lib/utils'
import {
  Plus,
  Search,
  Trash2,
  Edit,
  Play,
  Clock,
  RefreshCw,
  CheckCircle,
  XCircle,
  Loader2,
  History,
  Pause,
} from 'lucide-react'
import CruiseLogsDialog from './CruiseLogsDialog'

// 常用的 Cron 表达式预设
const CRON_PRESETS = [
  { label: '每天 00:00', value: '0 0 * * *' },
  { label: '每天 08:00', value: '0 8 * * *' },
  { label: '每天 12:00', value: '0 12 * * *' },
  { label: '每天 20:00', value: '0 20 * * *' },
  { label: '每周一 00:00', value: '0 0 * * 1' },
  { label: '每周一 08:00', value: '0 8 * * 1' },
  { label: '每月 1 日 00:00', value: '0 0 1 * *' },
  { label: '每小时', value: '0 * * * *' },
  { label: '每 6 小时', value: '0 */6 * * *' },
  { label: '每 12 小时', value: '0 */12 * * *' },
]

const TASK_TYPES = [
  { value: 'full', label: '全量扫描' },
  { value: 'subdomain', label: '子域名扫描' },
  { value: 'port_scan', label: '端口扫描' },
  { value: 'fingerprint', label: '指纹识别' },
  { value: 'vuln_scan', label: '漏洞扫描' },
  { value: 'dir_scan', label: '目录扫描' },
  { value: 'crawler', label: '爬虫扫描' },
]

const TARGET_TYPES = [
  { value: 'domain', label: '域名' },
  { value: 'ip', label: 'IP地址' },
  { value: 'url', label: 'URL' },
  { value: 'cidr', label: 'CIDR网段' },
]

export default function CruisePage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [editingCruise, setEditingCruise] = useState<CruiseTask | null>(null)
  const [logsDialogCruise, setLogsDialogCruise] = useState<CruiseTask | null>(null)
  const [preview, setPreview] = useState<CruiseTargetPreview | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)

  // 表单状态
  const [formData, setFormData] = useState<Partial<CruiseCreateRequest>>({
    name: '',
    description: '',
    project_id: 0,
    kind: 'scan',
    target_source: 'static',
    cron_expr: '0 0 * * *',
    targets: [],
    target_type: 'domain',
    task_type: 'full',
    config: {
      scan_types: ['subdomain', 'port_scan', 'fingerprint', 'vuln_scan'],
      port_scan_mode: 'top1000',
      timeout: 30,
      concurrent: 50,
    },
    digital: {
      provider: 'xiaolanben',
      username: '',
      password: '',
      cookie: '',
      max_entities: 20,
      max_assets: 50,
      depth: 1,
      max_nodes: 20,
    },
    notify_on_complete: false,
    notify_on_vuln: true,
  })
  const [targetsText, setTargetsText] = useState('')

  const isProjectSource = formData.target_source === 'project'
  const isDigital = formData.kind === 'digital_assets'
  const isDeep = formData.kind === 'enterprise_deep'
  const isNonScan = isDigital || isDeep
  const providers = useQuery({
    queryKey: ['enterprise-providers'],
    queryFn: () => enterpriseApi.providers(),
    enabled: isDigital,
  })
  const collectProvider: EnterpriseProvider | undefined = providers.data?.data?.items?.find(
    (p) => p.Name === formData.digital?.provider
  )
  const setDigital = (patch: Partial<NonNullable<CruiseCreateRequest['digital']>>) =>
    setFormData({ ...formData, digital: { ...formData.digital!, ...patch } })
  const targetTypeLabel =
    TARGET_TYPES.find((t) => t.value === formData.target_type)?.label || formData.target_type

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['cruises', page, pageSize, search],
    queryFn: () => cruiseApi.getCruises({ page, pageSize, search }),
    refetchInterval: 10000,
  })

  const { data: stats } = useQuery({
    queryKey: ['cruiseStats'],
    queryFn: () => cruiseApi.getCruiseStats(),
    refetchInterval: 10000,
  })

  const { data: projects } = useQuery({
    queryKey: ['asset-projects'],
    queryFn: () => projectApi.list(),
  })
  const projectList = projects?.data ?? []
  const projectName = (id?: number) =>
    projectList.find((p) => p.id === id)?.name || (id ? `项目 #${id}` : '-')

  // 资产巡航 v2 总览：被动发现 + 站点内容巡检（60s 自动刷新）
  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['cruise-v2-overview'],
    queryFn: () => seedCollectionApi.overview(),
    refetchInterval: 60000,
  })
  const overviewRows = overview?.data ?? []
  const queryClient = useQueryClient()
  const pauseMutation = useMutation({
    mutationFn: ({ id, paused }: { id: number; paused: boolean }) =>
      paused ? projectApi.resume(id) : projectApi.pause(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['cruise-v2-overview'] }),
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const overviewColumns: TableProps<CruiseOverviewRow>['columns'] = [
    {
      title: '项目',
      dataIndex: 'name',
      key: 'name',
      render: (_, row) => (
        <div className="flex items-baseline gap-2">
          <span className="font-medium">{row.name}</span>
          <span className="font-mono text-xs text-muted-foreground">{row.code}</span>
        </div>
      ),
    },
    {
      title: '最近发现轮',
      dataIndex: 'last_run_at',
      key: 'last_run_at',
      width: 170,
      render: (v: string | null) =>
        v ? (
          <span className="text-sm">{formatDate(v)}</span>
        ) : (
          <span className="text-sm text-muted-foreground">尚未运行</span>
        ),
    },
    {
      title: '状态',
      dataIndex: 'paused',
      key: 'paused',
      width: 80,
      render: (paused: boolean) =>
        paused ? <Tag className="border-transparent bg-amber-500/15 text-amber-600">已暂停</Tag> : <Tag className="border-transparent bg-emerald-500/15 text-emerald-600">采集中</Tag>,
    },
    { title: '发现累计', dataIndex: 'discover_new', key: 'discover_new', width: 90 },
    {
      title: '待确认候选',
      dataIndex: 'pending',
      key: 'pending',
      width: 100,
      render: (v: number, row) =>
        v > 0 ? (
          <Link to={`/projects/${row.project_id}`} className="text-sm text-green-600">
            {v}
          </Link>
        ) : (
          <span className="text-sm">{v}</span>
        ),
    },
    { title: '巡检可达', dataIndex: 'reachable', key: 'reachable', width: 90 },
    { title: '24h 已查', dataIndex: 'checked_24h', key: 'checked_24h', width: 90 },
    {
      title: '累计变更',
      dataIndex: 'changed_total',
      key: 'changed_total',
      width: 90,
      render: (v: number) => <span className={v > 0 ? 'text-red-600' : undefined}>{v}</span>,
    },
    {
      title: '收集队列',
      dataIndex: 'collecting',
      key: 'collecting',
      width: 100,
      render: (v: number) =>
        v > 0 ? (
          <Badge status="processing" text={<span className="text-sm text-blue-500">{v}</span>} />
        ) : (
          <span className="text-sm">{v}</span>
        ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_, row) => (
        <div className="flex items-center gap-2">
          <Button
            type="text"
            size="small"
            disabled={pauseMutation.isPending}
            onClick={() => pauseMutation.mutate({ id: row.project_id, paused: row.paused })}
            icon={row.paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          >
            {row.paused ? '恢复' : '暂停'}
          </Button>
          <Link to={`/projects/${row.project_id}`} className="text-sm">
            前往项目
          </Link>
        </div>
      ),
    },
  ]

  const createMutation = useMutation({
    mutationFn: cruiseApi.createCruise,
    onSuccess: () => {
      toast({ title: '创建成功', description: '巡航任务已创建' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] })
      closeDialog()
    },
    onError: (error: Error) => {
      toast({ title: '创建失败', description: error.message, variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<CruiseCreateRequest> }) =>
      cruiseApi.updateCruise(id, data),
    onSuccess: () => {
      toast({ title: '更新成功' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
      closeDialog()
    },
    onError: (error: Error) => {
      toast({ title: '更新失败', description: error.message, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: cruiseApi.deleteCruise,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '删除失败'), variant: 'destructive' })
    },
  })

  const enableMutation = useMutation({
    mutationFn: cruiseApi.enableCruise,
    onSuccess: () => {
      toast({ title: '已启用' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '启用失败'), variant: 'destructive' })
    },
  })

  const disableMutation = useMutation({
    mutationFn: cruiseApi.disableCruise,
    onSuccess: () => {
      toast({ title: '已禁用' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
      queryClient.invalidateQueries({ queryKey: ['cruiseStats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '禁用失败'), variant: 'destructive' })
    },
  })

  const runMutation = useMutation({
    mutationFn: cruiseApi.runCruise,
    onSuccess: () => {
      toast({ title: '已触发执行' })
      queryClient.invalidateQueries({ queryKey: ['cruises'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '执行失败'), variant: 'destructive' })
    },
  })

  const closeDialog = () => {
    setCreateDialogOpen(false)
    setEditingCruise(null)
    setPreview(null)
    setFormData({
      name: '',
      description: '',
      project_id: 0,
      kind: 'scan',
      target_source: 'static',
      cron_expr: '0 0 * * *',
      targets: [],
      target_type: 'domain',
      task_type: 'full',
      config: {
        scan_types: ['subdomain', 'port_scan', 'fingerprint', 'vuln_scan'],
        port_scan_mode: 'top1000',
        timeout: 30,
        concurrent: 50,
      },
      digital: {
        provider: 'xiaolanben',
        username: '',
        password: '',
        cookie: '',
        max_entities: 20,
        max_assets: 50,
      },
      notify_on_complete: false,
      notify_on_vuln: true,
    })
    setTargetsText('')
  }

  const openEditDialog = (cruise: CruiseTask) => {
    setEditingCruise(cruise)
    setPreview(null)
    setFormData({
      name: cruise.name,
      description: cruise.description,
      project_id: cruise.project_id,
      kind: (cruise.kind as CruiseCreateRequest['kind']) || 'scan',
      target_source: cruise.target_source || 'static',
      cron_expr: cruise.cron_expr,
      targets: cruise.targets,
      target_type: cruise.target_type,
      task_type: cruise.task_type,
      config: cruise.config,
      digital: cruise.digital
        ? {
            provider: cruise.digital.provider,
            username: cruise.digital.username ?? '',
            password: cruise.digital.password ?? '',
            cookie: cruise.digital.cookie ?? '',
            max_entities: cruise.digital.max_entities ?? 20,
            max_assets: cruise.digital.max_assets ?? 50,
          }
        : {
            provider: 'xiaolanben',
            username: '',
            password: '',
            cookie: '',
            max_entities: 20,
            max_assets: 50,
            depth: 1,
            max_nodes: 20,
          },
      notify_on_complete: cruise.notify_on_complete,
      notify_on_vuln: cruise.notify_on_vuln,
    })
    setTargetsText(cruise.targets.join('\n'))
    setCreateDialogOpen(true)
  }

  const handlePreview = async () => {
    if (!formData.project_id) {
      toast({ title: '请先选择归属项目', variant: 'destructive' })
      return
    }
    setPreviewLoading(true)
    try {
      const result = await cruiseApi.previewTargets(
        formData.project_id,
        isNonScan ? 'digital_assets' : formData.target_type || 'domain'
      )
      setPreview(result)
    } catch (error: any) {
      toast({
        title: '预览失败',
        description: error?.message || '无法读取项目资产',
        variant: 'destructive',
      })
    } finally {
      setPreviewLoading(false)
    }
  }

  const handleSubmit = () => {
    const targets = targetsText
      .split('\n')
      .map((t) => t.trim())
      .filter((t) => t)

    if (!formData.name) {
      toast({ title: '请输入名称', variant: 'destructive' })
      return
    }
    if (!formData.project_id) {
      toast({ title: '请选择归属项目', variant: 'destructive' })
      return
    }
    if (!formData.cron_expr) {
      toast({ title: '请设置执行周期', variant: 'destructive' })
      return
    }
    if (!isProjectSource && !isNonScan && targets.length === 0) {
      toast({ title: '请输入扫描目标', variant: 'destructive' })
      return
    }
    if (isNonScan && !formData.digital?.provider) {
      toast({ title: '请选择数字资产数据源', variant: 'destructive' })
      return
    }

    const submitData = {
      ...formData,
      targets: isProjectSource || isNonScan ? [] : targets,
    } as CruiseCreateRequest

    if (editingCruise) {
      updateMutation.mutate({ id: editingCruise.id, data: submitData })
    } else {
      createMutation.mutate(submitData)
    }
  }

  const handleToggle = (cruise: CruiseTask) => {
    if (cruise.status === 'enabled' || cruise.status === 'running') {
      disableMutation.mutate(cruise.id)
    } else {
      enableMutation.mutate(cruise.id)
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'enabled':
        return <Tag className="border-transparent bg-green-500 text-white">已启用</Tag>
      case 'disabled':
        return <Tag className="border-transparent bg-secondary text-secondary-foreground">已禁用</Tag>
      case 'running':
        return <Tag className="border-transparent bg-blue-500 text-white">执行中</Tag>
      default:
        return <Tag>{status}</Tag>
    }
  }

  const getLastStatusIcon = (status?: string) => {
    switch (status) {
      case 'success':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'running':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      default:
        return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  // antd Table 服务端分页：接现有 page/pageSize 状态（替代原手写分页 footer）
  const tablePagination = {
    current: page,
    pageSize,
    total: data?.total ?? 0,
    showQuickJumper: true,
    showSizeChanger: true,
    showTotal: (t: number) => `共 ${t} 条记录`,
    onChange: (p: number, s: number) => {
      setPage(p)
      setPageSize(s)
    },
  }

  const columns: TableProps<CruiseTask>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (_, cruise) => (
        <div>
          <div className="font-medium">{cruise.name}</div>
          {cruise.description && (
            <div className="text-sm text-muted-foreground truncate max-w-[200px]">
              {cruise.description}
            </div>
          )}
        </div>
      ),
    },
    {
      title: '归属项目',
      dataIndex: 'project_id',
      key: 'project_id',
      render: (_, cruise) => (
        <div>
          <div className="text-sm font-medium">{projectName(cruise.project_id)}</div>
          <Tag className="mt-1 text-xs">
            {cruise.target_source === 'project' ? '项目派生' : '固定目标'}
          </Tag>
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => getStatusBadge(v),
    },
    {
      title: '执行周期',
      dataIndex: 'cron_expr',
      key: 'cron_expr',
      width: 110,
      render: (v: string) => (
        <code className="text-xs bg-muted px-1.5 py-0.5 rounded">{v}</code>
      ),
    },
    {
      title: '目标数量',
      dataIndex: 'targets',
      key: 'targets',
      width: 130,
      render: (_, cruise) =>
        cruise.target_source === 'project' ? (
          <span className="text-sm text-muted-foreground">执行时自动派生</span>
        ) : (
          cruise.targets?.length || 0
        ),
    },
    {
      title: '任务类型',
      dataIndex: 'task_type',
      key: 'task_type',
      width: 100,
      render: (_, cruise) =>
        cruise.kind === 'digital_assets' ? (
          <Tag className="border-primary bg-primary/10 text-primary">数字资产采集</Tag>
        ) : cruise.kind === 'enterprise_deep' ? (
          <Tag className="border-primary bg-primary/10 text-primary">企业深度采集</Tag>
        ) : (
          (TASK_TYPES.find((t) => t.value === cruise.task_type)?.label || cruise.task_type)
        ),
    },
    {
      title: '上次执行',
      dataIndex: 'last_run_at',
      key: 'last_run_at',
      width: 170,
      render: (_, cruise) => (
        <div className="flex items-center space-x-1">
          {getLastStatusIcon(cruise.last_status)}
          <span className="text-sm">
            {cruise.last_run_at ? formatDate(cruise.last_run_at) : '-'}
          </span>
        </div>
      ),
    },
    {
      title: '下次执行',
      dataIndex: 'next_run_at',
      key: 'next_run_at',
      width: 170,
      render: (v: string) => <span className="text-sm">{v ? formatDate(v) : '-'}</span>,
    },
    {
      title: '执行统计',
      key: 'stats',
      width: 110,
      render: (_, cruise) => (
        <div className="text-sm">
          <span className="text-green-600">{cruise.success_count}</span>
          {' / '}
          <span className="text-red-600">{cruise.fail_count}</span>
          {' / '}
          <span>{cruise.run_count}</span>
        </div>
      ),
    },
    {
      title: '启用',
      key: 'enabled',
      width: 70,
      render: (_, cruise) => (
        <Switch
          checked={cruise.status === 'enabled' || cruise.status === 'running'}
          onChange={() => handleToggle(cruise)}
          disabled={cruise.status === 'running'}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      render: (_, cruise) => (
        <div className="flex items-center justify-end gap-1">
          <Button
            type="text"
            title="立即执行"
            icon={<Play className="h-4 w-4" />}
            onClick={() => runMutation.mutate(cruise.id)}
            disabled={cruise.status === 'running'}
          />
          <Button
            type="text"
            title="执行日志"
            icon={<History className="h-4 w-4" />}
            onClick={() => setLogsDialogCruise(cruise)}
          />
          <Button
            type="text"
            title="编辑"
            icon={<Edit className="h-4 w-4" />}
            onClick={() => openEditDialog(cruise)}
          />
          <Button
            type="text"
            danger
            title="删除"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
                const ok = await confirm({
                  title: `删除巡航任务「${cruise.name}」？`,
                  description: '执行日志将一并删除，历史不可恢复。',
                  destructive: true,
                })
                if (ok) deleteMutation.mutate(cruise.id)
              }}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      {/* 头部统计 */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold">{stats?.total || 0}</div>
          <div className="text-sm text-muted-foreground">总任务数</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-green-500">{stats?.enabled || 0}</div>
          <div className="text-sm text-muted-foreground">已启用</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-gray-500">{stats?.disabled || 0}</div>
          <div className="text-sm text-muted-foreground">已禁用</div>
        </div>
        <div className="rounded-lg border bg-card p-4">
          <div className="text-2xl font-bold text-blue-500">{stats?.running || 0}</div>
          <div className="text-sm text-muted-foreground">执行中</div>
        </div>
      </div>

      {/* 资产巡航 v2 总览 */}
      <Card
        title={
          <div className="flex flex-col gap-1">
            <span>资产巡航 v2（发现 + 巡检）</span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              被动发现与站点内容巡检的汇总。新内容在项目详情「发现候选」面板确认；详情见
              docs/方案-资产巡航v2
            </span>
          </div>
        }
      >
        <Table<CruiseOverviewRow>
          columns={overviewColumns}
          dataSource={overviewRows}
          rowKey="project_id"
          loading={overviewLoading}
          size="small"
          pagination={false}
          locale={{ emptyText: <EmptyState title="暂无项目数据" className="border-0" /> }}
        />
      </Card>


      {/* 工具栏 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="搜索巡航任务..."
              className="pl-8 w-64"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <Button onClick={() => refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" />
            刷新
          </Button>
          <Button type="primary" onClick={() => setCreateDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            新建巡航
          </Button>
        </div>
      </div>

      {/* 表格 */}
      <Table
        columns={columns}
        dataSource={data?.items ?? []}
        rowKey="id"
        loading={isLoading}
        locale={{ emptyText: <EmptyState title="暂无巡航任务" className="border-0" /> }}
        pagination={tablePagination}
      />

      {/* 创建/编辑对话框 */}
      <Modal
        open={createDialogOpen}
        onCancel={() => closeDialog()}
        title={editingCruise ? '编辑巡航任务' : '新建巡航任务'}
        width={672}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={closeDialog}>取消</Button>
            <Button
              type="primary"
              onClick={handleSubmit}
              loading={createMutation.isPending || updateMutation.isPending}
            >
              保存
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground mb-4">
          配置定时自动扫描任务，系统将按照设定的周期自动执行扫描
        </p>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">任务名称 *</label>
              <Input
                placeholder="例如：每日资产巡航"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">巡航类型</label>
              <Select
                className="w-full"
                value={formData.kind || 'scan'}
                options={[
                  { value: 'scan', label: '扫描巡航' },
                  { value: 'digital_assets', label: '数字资产采集' },
                  { value: 'enterprise_deep', label: '企业深度采集' },
                ]}
                onChange={(value) => {
                  setFormData({ ...formData, kind: value })
                  setPreview(null)
                }}
              />
            </div>
          </div>

          {!isNonScan && (
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">任务类型</label>
                <Select
                  className="w-full"
                  placeholder="选择任务类型"
                  options={TASK_TYPES}
                  value={formData.task_type}
                  onChange={(value) => setFormData({ ...formData, task_type: value })}
                />
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">归属项目 *</label>
              <Select
                className="w-full"
                placeholder="选择资产项目"
                value={formData.project_id ? String(formData.project_id) : undefined}
                options={projectList.map((project) => ({
                  value: String(project.id),
                  label: project.name,
                }))}
                onChange={(value) => {
                  setFormData({ ...formData, project_id: Number(value) })
                  setPreview(null)
                }}
              />
              {projectList.length === 0 && (
                <div className="text-xs text-amber-600">
                  还没有资产项目，请先到「资产项目」创建
                </div>
              )}
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">目标来源</label>
              <Select
                className="w-full"
                placeholder="选择目标来源"
                disabled={isNonScan}
                value={isNonScan ? 'project' : formData.target_source || 'static'}
                options={[
                  { value: 'static', label: '固定目标列表' },
                  { value: 'project', label: '项目整体资产（自动派生）' },
                ]}
                onChange={(value) => {
                  setFormData({
                    ...formData,
                    target_source: value as 'static' | 'project',
                  })
                  setPreview(null)
                }}
              />
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">描述</label>
            <Input
              placeholder="任务描述（可选）"
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">执行周期 *</label>
              <Select
                className="w-full"
                placeholder="选择执行周期"
                options={CRON_PRESETS}
                value={formData.cron_expr}
                onChange={(value) => setFormData({ ...formData, cron_expr: value })}
              />
              <div className="text-xs text-muted-foreground">
                当前: <code className="bg-muted px-1 rounded">{formData.cron_expr}</code>
              </div>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">目标类型</label>
              {isNonScan ? (
                <Select
                  className="w-full"
                  value={formData.digital?.provider}
                  options={(providers.data?.data?.items ?? [])
                    .filter((p) => p.Available)
                    .map((p) => ({ value: p.Name, label: p.Label }))}
                  onChange={(value) => setDigital({ provider: value })}
                />
              ) : (
                <>
                  <Select
                    className="w-full"
                    placeholder="选择目标类型"
                    options={TARGET_TYPES}
                    value={formData.target_type}
                    onChange={(value) => {
                      setFormData({ ...formData, target_type: value })
                      setPreview(null)
                    }}
                  />
                  {isProjectSource && (
                    <div className="text-xs text-muted-foreground">
                      派生维度：域名会归并到根域，IP / URL / CIDR 会去重
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {isNonScan ? (
            <div className="space-y-3 rounded-md border bg-muted/30 p-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium">
                    {isDeep ? '按项目企业线索周期深度采集（子公司树）' : '按项目企业线索周期采集'}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {isDeep
                      ? '每次执行遍历项目企业线索，逐个错峰启动 BFS 子公司树展开（分支/投资/集团成员 + 数字资产顺带）；任务进度在企业身份页查看。'
                      : '每次执行遍历项目企业线索，从数据源拉取 APP / 小程序 / 公众号 / 新媒体；diff 后只把新增上榜送进数字资产候选池，确认后才落名单。'}
                  </div>
                </div>
                <Button
                  size="small"
                  onClick={handlePreview}
                  loading={previewLoading}
                  icon={<RefreshCw className="h-4 w-4" />}
                >
                  预览
                </Button>
              </div>
              {preview && (
                <div className="space-y-2">
                  <div className="text-xs text-muted-foreground">
                    共 {preview.total} 家企业线索（每次执行取前 {formData.digital?.max_entities ?? (isDeep ? 10 : 20)} 家）
                  </div>
                  {preview.targets.length === 0 ? (
                    <div className="rounded bg-background p-2 text-xs text-muted-foreground">
                      项目还没有企业线索，请先到「企业身份」录入或采集
                    </div>
                  ) : (
                    <div className="max-h-32 overflow-y-auto rounded bg-background p-2 text-xs">
                      {preview.targets.slice(0, 50).map((target) => (
                        <div key={target} className="truncate">
                          {target}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              <div className="grid grid-cols-3 gap-3">
                <div className="space-y-2">
                  <label className="text-xs font-medium">数据源</label>
                  <Select
                    className="w-full"
                    value={formData.digital?.provider}
                    options={(providers.data?.data?.items ?? [])
                      .filter((p) => p.Available)
                      .map((p) => ({ value: p.Name, label: p.Label }))}
                    onChange={(value) => setDigital({ provider: value })}
                  />
                </div>
                {isDeep ? (
                  <>
                    <div className="space-y-2">
                      <label className="text-xs font-medium">展开深度（1–2）</label>
                      <Input
                        type="number"
                        min={1}
                        max={2}
                        value={formData.digital?.depth}
                        onChange={(e) =>
                          setDigital({ depth: Number(e.target.value) || 1 })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-medium">单次节点上限（≤50）</label>
                      <Input
                        type="number"
                        min={1}
                        max={50}
                        value={formData.digital?.max_nodes}
                        onChange={(e) =>
                          setDigital({ max_nodes: Number(e.target.value) || 20 })
                        }
                      />
                    </div>
                  </>
                ) : (
                  <>
                    <div className="space-y-2">
                      <label className="text-xs font-medium">单次企业数上限（≤50）</label>
                      <Input
                        type="number"
                        min={1}
                        max={50}
                        value={formData.digital?.max_entities}
                        onChange={(e) =>
                          setDigital({ max_entities: Number(e.target.value) || 20 })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-medium">单企业资产上限（≤200）</label>
                      <Input
                        type="number"
                        min={1}
                        max={200}
                        value={formData.digital?.max_assets}
                        onChange={(e) =>
                          setDigital({ max_assets: Number(e.target.value) || 50 })
                        }
                      />
                    </div>
                  </>
                )}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <label className="text-xs font-medium">账号（账号类数据源）</label>
                  <Input
                    value={formData.digital?.username ?? ''}
                    onChange={(e) => setDigital({ username: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs font-medium">密码</label>
                  <Input
                    type="password"
                    value={formData.digital?.password ?? ''}
                    onChange={(e) => setDigital({ password: e.target.value })}
                  />
                </div>
              </div>
              <div className="text-xs text-muted-foreground">
                {collectProvider?.Hint ?? '当前仅小蓝本提供数字资产字段'}
                ；定时执行没有请求上下文，凭据随任务配置存储，请确认敏感信息可接受。
              </div>
            </div>
          ) : isProjectSource ? (
            <div className="space-y-3 rounded-md border bg-muted/30 p-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium">执行时自动派生</div>
                  <div className="text-xs text-muted-foreground">
                    每次执行都会重新读取该项目的种子、站点、原始记录和任务结果，按「
                    {targetTypeLabel}」归并去重后生成扫描目标。
                  </div>
                </div>
                <Button
                  size="small"
                  onClick={handlePreview}
                  loading={previewLoading}
                  icon={<RefreshCw className="h-4 w-4" />}
                >
                  预览
                </Button>
              </div>
              {preview && (
                <div className="space-y-2">
                  <div className="text-xs text-muted-foreground">
                    共派生 {preview.total} 个{targetTypeLabel}
                    {preview.truncated && `，执行时取前 ${preview.targets.length} 个`}
                  </div>
                  {preview.targets.length === 0 ? (
                    <div className="rounded bg-background p-2 text-xs text-muted-foreground">
                      项目里还没有可用的{targetTypeLabel}资产
                    </div>
                  ) : (
                    <div className="max-h-40 overflow-y-auto rounded bg-background p-2 font-mono text-xs">
                      {preview.targets.slice(0, 50).map((target) => (
                        <div key={target} className="truncate">
                          {target}
                        </div>
                      ))}
                      {preview.targets.length > 50 && (
                        <div className="pt-1 text-muted-foreground">
                          ... 还有 {preview.targets.length - 50} 个
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <label className="text-sm font-medium">扫描目标 *</label>
              <Input.TextArea
                placeholder={'每行一个目标，例如：\nexample.com\n192.168.1.1\n10.0.0.0/24'}
                rows={6}
                value={targetsText}
                onChange={(e) => setTargetsText(e.target.value)}
              />
              <div className="text-xs text-muted-foreground">
                已输入 {targetsText.split('\n').filter((t) => t.trim()).length} 个目标
              </div>
            </div>
          )}

          <div className="space-y-3">
            <label className="text-sm font-medium">通知设置</label>
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <Switch
                  checked={formData.notify_on_complete}
                  onChange={(checked) =>
                    setFormData({ ...formData, notify_on_complete: checked })
                  }
                />
                <label className="text-sm font-normal">完成时通知</label>
              </div>
              <div className="flex items-center space-x-2">
                <Switch
                  checked={formData.notify_on_vuln}
                  onChange={(checked) =>
                    setFormData({ ...formData, notify_on_vuln: checked })
                  }
                />
                <label className="text-sm font-normal">发现漏洞时通知</label>
              </div>
            </div>
          </div>
        </div>
      </Modal>

      {/* 执行日志对话框 */}
      {logsDialogCruise && (
        <CruiseLogsDialog
          cruise={logsDialogCruise}
          open={!!logsDialogCruise}
          onOpenChange={(open) => !open && setLogsDialogCruise(null)}
        />
      )}
    </div>
  )
}

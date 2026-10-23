import { useState } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { monitorApi, MonitorType, type ChangeRecord, type MonitoredPage } from '@/api/monitor'
import { Button, Card, Input, Modal, Select, Switch, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'
import {
  Eye,
  Plus,
  RefreshCw,
  Trash2,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  FileText,
  Link as LinkIcon,
  Hash,
  Layout,
} from 'lucide-react'

const monitorTypeLabels: Record<MonitorType, string> = {
  content_hash: '内容哈希',
  dom_structure: 'DOM结构',
  keywords: '关键词',
  links: '链接',
}

const monitorTypeIcons: Record<MonitorType, React.ReactNode> = {
  content_hash: <Hash className="h-4 w-4" />,
  dom_structure: <Layout className="h-4 w-4" />,
  keywords: <FileText className="h-4 w-4" />,
  links: <LinkIcon className="h-4 w-4" />,
}

const statusConfig: Record<string, { label: string; variant: 'default' | 'destructive' | 'outline' | 'secondary'; icon: React.ReactNode }> = {
  normal: { label: '正常', variant: 'default', icon: <CheckCircle className="h-3 w-3" /> },
  changed: { label: '已变化', variant: 'destructive', icon: <AlertTriangle className="h-3 w-3" /> },
  error: { label: '错误', variant: 'destructive', icon: <XCircle className="h-3 w-3" /> },
  pending: { label: '待检查', variant: 'outline', icon: <Clock className="h-3 w-3" /> },
}

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'default' | 'secondary' | 'destructive' | 'outline') =>
  variant === 'default'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : ''

export default function MonitorPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState('pages')
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [changesPage, setChangesPage] = useState(1)

  // 新建监控表单
  const [newPage, setNewPage] = useState({
    url: '',
    name: '',
    interval: 60,
    monitorTypes: ['content_hash'] as MonitorType[],
    keywords: '',
  })

  // 获取监控页面列表
  const { data: pagesData, isLoading: pagesLoading, refetch: refetchPages } = useQuery({
    queryKey: ['monitor-pages'],
    queryFn: () => monitorApi.getPages(),
  })

  // 获取变化记录
  const { data: changesData, isLoading: changesLoading } = useQuery({
    queryKey: ['monitor-changes', changesPage],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () => monitorApi.getChanges({ page: changesPage, pageSize: 10 }),
    enabled: activeTab === 'changes',
  })

  // 添加监控
  const addMutation = useMutation({
    mutationFn: monitorApi.addPage,
    onSuccess: () => {
      toast({ title: '添加成功' })
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] })
      setShowAddDialog(false)
      setNewPage({ url: '', name: '', interval: 60, monitorTypes: ['content_hash'], keywords: '' })
    },
    onError: () => {
      toast({ title: '添加失败', variant: 'destructive' })
    },
  })

  // 删除监控
  const deleteMutation = useMutation({
    mutationFn: monitorApi.deletePage,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] })
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' })
    },
  })

  // 切换启用状态
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      monitorApi.togglePage(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] })
    },
    onError: () => {
      toast({ title: '状态切换失败', variant: 'destructive' })
    },
  })

  // 立即检查
  const checkMutation = useMutation({
    mutationFn: monitorApi.checkNow,
    onSuccess: (res) => {
      if (res.data?.changed) {
        toast({ title: '检测到变化', variant: 'destructive' })
      } else {
        toast({ title: '检查完成', description: '未检测到变化' })
      }
      queryClient.invalidateQueries({ queryKey: ['monitor-pages'] })
    },
    onError: () => {
      toast({ title: '检查失败', variant: 'destructive' })
    },
  })

  // 确认变化
  const acknowledgeMutation = useMutation({
    mutationFn: monitorApi.acknowledgeChange,
    onSuccess: () => {
      toast({ title: '已确认' })
      queryClient.invalidateQueries({ queryKey: ['monitor-changes'] })
    },
    onError: () => {
      toast({ title: '确认失败', variant: 'destructive' })
    },
  })

  const pages = pagesData?.data?.list || []
  const changes = changesData?.data?.list || []
  const changesTotal = changesData?.data?.total || 0

  // 统计
  const stats = {
    total: pages.length,
    normal: pages.filter((p) => p.status === 'normal').length,
    changed: pages.filter((p) => p.status === 'changed').length,
    error: pages.filter((p) => p.status === 'error').length,
  }

  const handleAdd = () => {
    if (!newPage.url || !newPage.name) {
      toast({ title: '请填写完整信息', variant: 'destructive' })
      return
    }
    addMutation.mutate({
      url: newPage.url,
      name: newPage.name,
      interval: newPage.interval,
      monitorTypes: newPage.monitorTypes,
      keywords: newPage.keywords ? newPage.keywords.split(',').map((k) => k.trim()) : undefined,
    })
  }

  const toggleMonitorType = (type: MonitorType) => {
    if (newPage.monitorTypes.includes(type)) {
      setNewPage({
        ...newPage,
        monitorTypes: newPage.monitorTypes.filter((t) => t !== type),
      })
    } else {
      setNewPage({
        ...newPage,
        monitorTypes: [...newPage.monitorTypes, type],
      })
    }
  }

  const pagesColumns: TableProps<MonitoredPage>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (v: string) => <span className="font-medium">{v}</span>,
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      render: (v: string) => (
        <a
          href={v}
          target="_blank"
          rel="noopener noreferrer"
          className="block max-w-xs truncate text-primary hover:underline"
        >
          {v}
        </a>
      ),
    },
    {
      title: '监控类型',
      dataIndex: 'monitorTypes',
      key: 'monitorTypes',
      render: (types: MonitorType[]) => (
        <div className="flex flex-wrap gap-1">
          {types.map((type) => (
            <Tag key={type} className="text-xs">
              {monitorTypeLabels[type]}
            </Tag>
          ))}
        </div>
      ),
    },
    {
      title: '检查间隔',
      dataIndex: 'interval',
      key: 'interval',
      render: (v: number) => `${v}分钟`,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (v: string) => {
        const status = statusConfig[v] || statusConfig.pending
        return (
          <Tag className={cn('flex w-fit items-center gap-1', badgeCls(status.variant))}>
            {status.icon}
            {status.label}
          </Tag>
        )
      },
    },
    {
      title: '最后检查',
      dataIndex: 'lastCheck',
      key: 'lastCheck',
      render: (v?: string) => (v ? formatDate(v) : '-'),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (v: boolean, page) => (
        <Switch
          checked={v}
          onChange={(checked) => toggleMutation.mutate({ id: page.id, enabled: checked })}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_, page) => (
        <div className="flex gap-1">
          <Button
            type="text"
            size="small"
            title="立即检查"
            icon={<Play className="h-4 w-4 text-green-500" />}
            onClick={() => checkMutation.mutate(page.id)}
            disabled={checkMutation.isPending}
          />
          <Button
            type="text"
            size="small"
            danger
            title="删除"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => deleteMutation.mutate(page.id)}
          />
        </div>
      ),
    },
  ]

  const changesColumns: TableProps<ChangeRecord>['columns'] = [
    {
      title: '页面',
      key: 'page',
      render: (_, change) => (
        <div>
          <p className="font-medium">{change.pageName}</p>
          <p className="max-w-xs truncate text-xs text-muted-foreground">{change.url}</p>
        </div>
      ),
    },
    {
      title: '变化类型',
      dataIndex: 'changeType',
      key: 'changeType',
      render: (v: MonitorType) => (
        <Tag className="flex w-fit items-center gap-1">
          {monitorTypeIcons[v]}
          {monitorTypeLabels[v]}
        </Tag>
      ),
    },
    {
      title: '检测时间',
      dataIndex: 'detectedAt',
      key: 'detectedAt',
      render: (v: string) => formatDate(v),
    },
    {
      title: '状态',
      dataIndex: 'acknowledged',
      key: 'acknowledged',
      render: (v: boolean) =>
        v ? (
          <Tag className="flex w-fit items-center gap-1">
            <CheckCircle className="h-3 w-3 mr-1" />
            已确认
          </Tag>
        ) : (
          <Tag className={cn('flex w-fit items-center gap-1', badgeCls('destructive'))}>
            <AlertTriangle className="h-3 w-3 mr-1" />
            待确认
          </Tag>
        ),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_, change) =>
        !change.acknowledged ? (
          <Button size="small" onClick={() => acknowledgeMutation.mutate(change.id)}>
            确认
          </Button>
        ) : null,
    },
  ]

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Eye className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">页面监控</h1>
        </div>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetchPages()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button type="primary" size="small" onClick={() => setShowAddDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加监控
          </Button>
        </div>
      </div>

      {/* 统计卡片 */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <span className="text-sm font-medium">总监控数</span>
          <div className="text-2xl font-bold">{stats.total}</div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <span className="text-sm font-medium text-green-600">正常</span>
          <div className="text-2xl font-bold text-green-600">{stats.normal}</div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <span className="text-sm font-medium text-orange-600">已变化</span>
          <div className="text-2xl font-bold text-orange-600">{stats.changed}</div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <span className="text-sm font-medium text-red-600">错误</span>
          <div className="text-2xl font-bold text-red-600">{stats.error}</div>
        </Card>
      </div>

      {/* 标签页 */}
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'pages',
            label: '监控列表',
            children: (
              <div className="overflow-hidden rounded-lg border">
                <Table<MonitoredPage>
                  columns={pagesColumns}
                  dataSource={pages}
                  rowKey="id"
                  loading={pagesLoading}
                  locale={{
                    emptyText: (
                      <div className="py-8 text-center text-muted-foreground">
                        暂无监控页面，点击&quot;添加监控&quot;开始
                      </div>
                    ),
                  }}
                  pagination={false}
                />
              </div>
            ),
          },
          {
            key: 'changes',
            label: (
              <>
                变化记录
                {stats.changed > 0 && (
                  <Tag
                    className={cn(
                      'ml-2 inline-flex h-5 w-5 items-center justify-center p-0',
                      badgeCls('destructive')
                    )}
                  >
                    {stats.changed}
                  </Tag>
                )}
              </>
            ),
            children: (
              <div className="overflow-hidden rounded-lg border">
                <Table<ChangeRecord>
                  columns={changesColumns}
                  dataSource={changes}
                  rowKey="id"
                  loading={changesLoading}
                  locale={{
                    emptyText: (
                      <div className="py-8 text-center text-muted-foreground">暂无变化记录</div>
                    ),
                  }}
                  pagination={{
                    current: changesPage,
                    pageSize: 10,
                    total: changesTotal,
                    showQuickJumper: true,
                    // page_size 固定 10、无独立 pageSize 状态，不展示切换器
                    showSizeChanger: false,
                    hideOnSinglePage: true,
                    onChange: (p) => setChangesPage(p),
                  }}
                />
              </div>
            ),
          },
        ]}
      />

      {/* 添加监控对话框 */}
      <Modal
        open={showAddDialog}
        onCancel={() => setShowAddDialog(false)}
        title="添加页面监控"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setShowAddDialog(false)}>取消</Button>
            <Button type="primary" onClick={handleAdd} disabled={addMutation.isPending}>
              添加
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">监控名称</label>
            <Input
              placeholder="输入监控名称"
              value={newPage.name}
              onChange={(e) => setNewPage({ ...newPage, name: e.target.value })}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">页面 URL</label>
            <Input
              placeholder="https://example.com"
              value={newPage.url}
              onChange={(e) => setNewPage({ ...newPage, url: e.target.value })}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">检查间隔 (分钟)</label>
            <Select
              className="w-full"
              value={String(newPage.interval)}
              onChange={(value) => setNewPage({ ...newPage, interval: Number(value) })}
              options={[
                { value: '5', label: '5分钟' },
                { value: '15', label: '15分钟' },
                { value: '30', label: '30分钟' },
                { value: '60', label: '1小时' },
                { value: '360', label: '6小时' },
                { value: '1440', label: '24小时' },
              ]}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">监控类型</label>
            <div className="flex flex-wrap gap-2">
              {(Object.keys(monitorTypeLabels) as MonitorType[]).map((type) => (
                <Button
                  key={type}
                  type={newPage.monitorTypes.includes(type) ? 'primary' : 'default'}
                  size="small"
                  onClick={() => toggleMonitorType(type)}
                >
                  {monitorTypeIcons[type]}
                  <span className="ml-1">{monitorTypeLabels[type]}</span>
                </Button>
              ))}
            </div>
          </div>
          {newPage.monitorTypes.includes('keywords') && (
            <div className="space-y-2">
              <label className="text-sm font-medium">关键词 (逗号分隔)</label>
              <Input
                placeholder="关键词1, 关键词2"
                value={newPage.keywords}
                onChange={(e) => setNewPage({ ...newPage, keywords: e.target.value })}
              />
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}

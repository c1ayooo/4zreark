import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { queueApi, QueueTask } from '@/api/queue'
import { Button, Card, Progress, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import { useConfirm } from '@/components/common/confirm-provider'
import { cn, formatDate } from '@/lib/utils'
import {
  ListTodo,
  RefreshCw,
  Trash2,
  RotateCcw,
  Clock,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Server,
} from 'lucide-react'

const statusConfig: Record<string, { label: string; variant: 'default' | 'destructive' | 'outline' | 'secondary'; icon: React.ReactNode }> = {
  pending: { label: '等待中', variant: 'outline', icon: <Clock className="h-3 w-3" /> },
  processing: { label: '处理中', variant: 'default', icon: <Loader2 className="h-3 w-3 animate-spin" /> },
  completed: { label: '已完成', variant: 'secondary', icon: <CheckCircle className="h-3 w-3" /> },
  failed: { label: '失败', variant: 'destructive', icon: <XCircle className="h-3 w-3" /> },
  deadletter: { label: '死信', variant: 'destructive', icon: <AlertTriangle className="h-3 w-3" /> },
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

export default function QueuePage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState('overview')
  const [pendingPage, setPendingPage] = useState(1)
  const [deadletterPage, setDeadletterPage] = useState(1)

  // 获取队列统计
  const { data: statsData, isLoading: statsLoading, refetch: refetchStats } = useQuery({
    queryKey: ['queue-stats'],
    queryFn: queueApi.getStats,
    refetchInterval: 5000, // 每5秒刷新
  })

  // 获取处理中任务
  const { data: processingData } = useQuery({
    queryKey: ['queue-processing'],
    queryFn: queueApi.getProcessingTasks,
    refetchInterval: 3000,
    enabled: activeTab === 'processing',
  })

  // 获取待处理任务
  const { data: pendingData, isLoading: pendingLoading } = useQuery({
    queryKey: ['queue-pending', pendingPage],
    queryFn: () => queueApi.getPendingTasks({ page: pendingPage, pageSize: 10 }),
    enabled: activeTab === 'pending',
  })

  // 获取死信队列
  const { data: deadletterData, isLoading: deadletterLoading } = useQuery({
    queryKey: ['queue-deadletter', deadletterPage],
    queryFn: () => queueApi.getDeadLetterTasks({ page: deadletterPage, pageSize: 10 }),
    enabled: activeTab === 'deadletter',
  })

  // 获取Worker状态
  const { data: workersData } = useQuery({
    queryKey: ['queue-workers'],
    queryFn: queueApi.getWorkerStatus,
    refetchInterval: 5000,
    enabled: activeTab === 'workers',
  })

  // 重试死信任务
  const retryMutation = useMutation({
    mutationFn: queueApi.retryDeadLetterTask,
    onSuccess: () => {
      toast({ title: '已重新加入队列' })
      queryClient.invalidateQueries({ queryKey: ['queue-deadletter'] })
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '重试失败'), variant: 'destructive' })
    },
  })

  // 清空死信队列
  const clearDeadletterMutation = useMutation({
    mutationFn: queueApi.clearDeadLetter,
    onSuccess: () => {
      toast({ title: '已清空死信队列' })
      queryClient.invalidateQueries({ queryKey: ['queue-deadletter'] })
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '清空失败'), variant: 'destructive' })
    },
  })

  // 取消任务
  const cancelMutation = useMutation({
    mutationFn: queueApi.cancelTask,
    onSuccess: () => {
      toast({ title: '任务已取消' })
      queryClient.invalidateQueries({ queryKey: ['queue-pending'] })
      queryClient.invalidateQueries({ queryKey: ['queue-stats'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '取消失败'), variant: 'destructive' })
    },
  })

  const stats = statsData?.data
  const processing = processingData?.data || []
  const pending = pendingData?.data?.list || []
  const pendingTotal = pendingData?.data?.total || 0
  const deadletter = deadletterData?.data?.list || []
  const deadletterTotal = deadletterData?.data?.total || 0
  const workers = workersData?.data?.workers || []

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ListTodo className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">任务队列</h1>
        </div>
        <Button size="small" onClick={() => refetchStats()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          刷新
        </Button>
      </div>

      {/* 统计卡片 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <div className="flex items-center gap-2 text-sm font-medium">
            <Clock className="h-4 w-4 text-blue-500" />
            等待中
          </div>
          <div className="text-2xl font-bold text-blue-600">
            {statsLoading ? '-' : stats?.pending || 0}
          </div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <div className="flex items-center gap-2 text-sm font-medium">
            <Loader2 className="h-4 w-4 text-green-500" />
            处理中
          </div>
          <div className="text-2xl font-bold text-green-600">
            {statsLoading ? '-' : stats?.processing || 0}
          </div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <div className="flex items-center gap-2 text-sm font-medium">
            <CheckCircle className="h-4 w-4 text-gray-500" />
            已完成
          </div>
          <div className="text-2xl font-bold">
            {statsLoading ? '-' : stats?.completed || 0}
          </div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <div className="flex items-center gap-2 text-sm font-medium">
            <XCircle className="h-4 w-4 text-red-500" />
            失败
          </div>
          <div className="text-2xl font-bold text-red-600">
            {statsLoading ? '-' : stats?.failed || 0}
          </div>
        </Card>
        <Card styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
          <div className="flex items-center gap-2 text-sm font-medium">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            死信
          </div>
          <div className="text-2xl font-bold text-orange-600">
            {statsLoading ? '-' : stats?.deadletter || 0}
          </div>
        </Card>
      </div>

      {/* Worker 状态 */}
      <Card
        title={<span className="text-sm font-medium">Worker 状态</span>}
        extra={<Tag>{stats?.workersActive || 0} / {stats?.workersTotal || 0} 活跃</Tag>}
        styles={{ body: { paddingTop: 12 } }}
      >
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span>平均处理时间</span>
            <span>{stats?.averageProcessTime ? `${stats.averageProcessTime}ms` : '-'}</span>
          </div>
          <Progress
            percent={stats ? (stats.workersActive / Math.max(stats.workersTotal, 1)) * 100 : 0}
            showInfo={false}
          />
        </div>
      </Card>

      {/* 标签页 */}
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'overview',
            label: '概览',
            children: (
              <div className="grid gap-4 md:grid-cols-2">
                <Card
                  title={
                    <div>
                      队列健康度
                      <span className="block text-xs font-normal text-muted-foreground">
                        基于处理效率和失败率
                      </span>
                    </div>
                  }
                >
                  <div className="flex items-center gap-4">
                    <div className="flex-1">
                      <Progress
                        percent={
                          100 - (stats?.failed || 0) / Math.max(stats?.totalProcessed || 1, 1) * 100
                        }
                        showInfo={false}
                      />
                    </div>
                    <span className="text-2xl font-bold text-green-600">
                      {Math.round(100 - (stats?.failed || 0) / Math.max(stats?.totalProcessed || 1, 1) * 100)}%
                    </span>
                  </div>
                </Card>
                <Card
                  title={
                    <div>
                      总处理量
                      <span className="block text-xs font-normal text-muted-foreground">
                        历史处理任务总数
                      </span>
                    </div>
                  }
                >
                  <div className="text-3xl font-bold">
                    {stats?.totalProcessed || 0}
                  </div>
                </Card>
              </div>
            ),
          },
          {
            key: 'processing',
            label: (
              <>
                处理中
                {stats?.processing ? (
                  <Tag
                    className={cn(
                      'ml-2 inline-flex h-5 w-5 items-center justify-center p-0',
                      badgeCls('default')
                    )}
                  >
                    {stats.processing}
                  </Tag>
                ) : null}
              </>
            ),
            children: (
              <TaskTable
                tasks={processing}
                loading={false}
                emptyText="当前没有正在处理的任务"
              />
            ),
          },
          {
            key: 'pending',
            label: (
              <>
                等待中
                {stats?.pending ? (
                  <Tag className="ml-2 inline-flex h-5 w-5 items-center justify-center p-0">
                    {stats.pending}
                  </Tag>
                ) : null}
              </>
            ),
            children: (
              <TaskTable
                tasks={pending}
                loading={pendingLoading}
                emptyText="队列为空"
                showCancel
                onCancel={(id) => cancelMutation.mutate(id)}
                pagination={{
                  current: pendingPage,
                  pageSize: 10,
                  total: pendingTotal,
                  showQuickJumper: true,
                  // page_size 固定 10、无独立 pageSize 状态，不展示切换器
                  showSizeChanger: false,
                  hideOnSinglePage: true,
                  onChange: (p) => setPendingPage(p),
                }}
              />
            ),
          },
          {
            key: 'deadletter',
            label: (
              <>
                死信队列
                {stats?.deadletter ? (
                  <Tag
                    className={cn(
                      'ml-2 inline-flex h-5 w-5 items-center justify-center p-0',
                      badgeCls('destructive')
                    )}
                  >
                    {stats.deadletter}
                  </Tag>
                ) : null}
              </>
            ),
            children: (
              <div>
                <div className="mb-4 flex justify-end">
                  <Button
                    danger
                    size="small"
                    onClick={async () => {
                      const ok = await confirm({
                        title: `清空全部 ${deadletter.length} 条死信？`,
                        description: '死信任务将永久删除，无法重试。',
                        destructive: true,
                      })
                      if (ok) clearDeadletterMutation.mutate()
                    }}
                    disabled={clearDeadletterMutation.isPending || deadletter.length === 0}
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    清空队列
                  </Button>
                </div>
                <TaskTable
                  tasks={deadletter}
                  loading={deadletterLoading}
                  emptyText="死信队列为空"
                  showRetry
                  onRetry={(id) => retryMutation.mutate(id)}
                  pagination={{
                    current: deadletterPage,
                    pageSize: 10,
                    total: deadletterTotal,
                    showQuickJumper: true,
                    // page_size 固定 10、无独立 pageSize 状态，不展示切换器
                    showSizeChanger: false,
                    hideOnSinglePage: true,
                    onChange: (p) => setDeadletterPage(p),
                  }}
                />
              </div>
            ),
          },
          {
            key: 'workers',
            label: 'Workers',
            children: (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {workers.map((worker) => (
                  <Card key={worker.id} styles={{ body: { paddingTop: 12 } }}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-sm font-medium">
                        <Server className="h-4 w-4" />
                        {worker.id}
                      </div>
                      <Tag className={badgeCls(worker.status === 'busy' ? 'default' : 'outline')}>
                        {worker.status === 'busy' ? '忙碌' : '空闲'}
                      </Tag>
                    </div>
                    <div className="mt-2 space-y-2">
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">已处理</span>
                        <span>{worker.processedCount}</span>
                      </div>
                      {worker.currentTask && (
                        <div className="flex justify-between text-sm">
                          <span className="text-muted-foreground">当前任务</span>
                          <span className="truncate max-w-[150px]">{worker.currentTask}</span>
                        </div>
                      )}
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">启动时间</span>
                        <span>{formatDate(worker.startedAt)}</span>
                      </div>
                    </div>
                  </Card>
                ))}
                {workers.length === 0 && (
                  <div className="col-span-full text-center py-8 text-muted-foreground">
                    暂无 Worker 运行
                  </div>
                )}
              </div>
            ),
          },
        ]}
      />
    </div>
  )
}

// 任务表格组件
function TaskTable({
  tasks,
  loading,
  emptyText,
  showCancel,
  showRetry,
  onCancel,
  onRetry,
  pagination,
}: {
  tasks: QueueTask[]
  loading: boolean
  emptyText: string
  showCancel?: boolean
  showRetry?: boolean
  onCancel?: (id: string) => void
  onRetry?: (id: string) => void
  pagination?: TableProps<QueueTask>['pagination']
}) {
  const columns: TableProps<QueueTask>['columns'] = [
    {
      title: '任务ID',
      dataIndex: 'id',
      key: 'id',
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (v: string) => <Tag>{v}</Tag>,
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
    { title: '优先级', dataIndex: 'priority', key: 'priority' },
    {
      title: '重试次数',
      key: 'retries',
      render: (_, t) => `${t.retries} / ${t.maxRetries}`,
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      render: (v: string) => formatDate(v),
    },
  ]
  if (showCancel || showRetry) {
    columns.push({
      title: '操作',
      key: 'actions',
      render: (_, t) => (
        <div className="flex gap-1">
          {showRetry && (
            <Button
              type="text"
              size="small"
              title="重试"
              icon={<RotateCcw className="h-4 w-4" />}
              onClick={() => onRetry?.(t.id)}
            />
          )}
          {showCancel && (
            <Button
              type="text"
              size="small"
              danger
              title="取消"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={() => onCancel?.(t.id)}
            />
          )}
        </div>
      ),
    })
  }

  return (
    <div className="overflow-hidden rounded-lg border">
      <Table<QueueTask>
        columns={columns}
        dataSource={tasks}
        rowKey="id"
        loading={loading}
        locale={{
          emptyText: <div className="py-8 text-center text-muted-foreground">{emptyText}</div>,
        }}
        pagination={pagination ?? false}
      />
    </div>
  )
}

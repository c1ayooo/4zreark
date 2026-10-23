import { useEffect, useState } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { taskApi, Task } from '@/api/tasks'
import { Button, Input, Progress, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import EmptyState from '@/components/common/EmptyState'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import {
  Plus,
  Search,
  Trash2,
  Eye,
  Play,
  Pause,
  Square,
  RefreshCw,
  RotateCw,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import TaskCreateDialog from '@/components/tasks/TaskCreateDialog'
import { useConfirm } from '@/components/common/confirm-provider'
import { getErrorMessage } from '@/lib/errors'

export default function TasksPage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([undefined])
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const cursor = cursorStack[cursorStack.length - 1]
  const page = cursorStack.length

  useEffect(() => {
    setCursorStack([undefined])
  }, [search, statusFilter])

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['tasks', cursor, search, statusFilter],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      taskApi.getTasks({
        cursor: cursor ?? '',
        pageSize: 10,
        search,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
    refetchInterval: (query) => {
      // 只有存在运行中/排队的任务才自动刷新，列表静止时不打后端
      const list = query.state.data?.data?.list
      return list?.some((t) => t.status === 'running' || t.status === 'pending') ? 5000 : false
    },
  })

  const startMutation = useMutation({
    mutationFn: taskApi.startTask,
    onSuccess: () => {
      toast({ title: '任务已启动' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '启动任务失败'), variant: 'destructive' })
    },
  })

  const pauseMutation = useMutation({
    mutationFn: taskApi.pauseTask,
    onSuccess: () => {
      toast({ title: '任务已暂停' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '暂停任务失败'), variant: 'destructive' })
    },
  })

  const cancelMutation = useMutation({
    mutationFn: taskApi.cancelTask,
    onSuccess: () => {
      toast({ title: '任务已取消' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '取消任务失败'), variant: 'destructive' })
    },
  })

  const resumeMutation = useMutation({
    mutationFn: taskApi.resumeTask,
    onSuccess: () => {
      toast({ title: '任务已恢复' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '恢复任务失败'), variant: 'destructive' })
    },
  })

  const retryMutation = useMutation({
    mutationFn: taskApi.retryTask,
    onSuccess: () => {
      toast({ title: '任务已重试' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '重试任务失败'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: taskApi.deleteTask,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '删除任务失败'), variant: 'destructive' })
    },
  })

  const tasks = data?.data?.list || []
  const hasMore = data?.data?.hasMore ?? false
  const nextCursor = data?.data?.nextCursor ?? '' 

  const getStatusLabel = (status: Task['status']) => {
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

  const columns: TableProps<Task>['columns'] = [
    {
      title: '任务名称',
      dataIndex: 'name',
      key: 'name',
      render: (_, task) => (
        <div className="font-medium">
          {task.name}
          <div className="mt-1 text-[13px] tabular-nums text-muted-foreground sm:hidden">
            {task.progress}%
          </div>
        </div>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 110,
      responsive: ['md'],
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (status: Task['status']) => (
        <Tag className={cn(getStatusColor(status))}>
          {getStatusLabel(status)}
        </Tag>
      ),
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 190,
      align: 'right',
      responsive: ['sm'],
      render: (_, task) => (
        <div className="w-28 text-left md:w-40">
          <Progress percent={task.progress} showInfo={false} strokeWidth={8} />
          <div className="flex justify-between text-xs text-muted-foreground mt-1">
            <span>{task.progress}%</span>
            {task.status === 'running' && task.progressDetails && (
              <span className="truncate ml-1" title={task.progressDetails.current_module}>
                {task.progressDetails.current_module || '扫描中...'}
              </span>
            )}
          </div>
          {task.status === 'running' && task.progressDetails?.estimated_time_left && (
            <div className="text-xs text-muted-foreground">
              剩余: {task.progressDetails.estimated_time_left}
            </div>
          )}
        </div>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 170,
      align: 'right',
      className: 'tabular-nums',
      responsive: ['md'],
      render: (createdAt: string) => formatDate(createdAt),
    },
    {
      title: '操作',
      key: 'actions',
      width: 160,
      render: (_, task) => (
        <div className="flex gap-1">
          {task.status === 'pending' && (
            <Button
              type="text"
              aria-label="启动任务"
              icon={<Play className="h-4 w-4 text-primary" />}
              onClick={() => startMutation.mutate(task.id)}
            />
          )}
          {task.status === 'running' && (
            <Button
              type="text"
              aria-label="暂停任务"
              icon={<Pause className="h-4 w-4 text-amber-600" />}
              onClick={() => pauseMutation.mutate(task.id)}
            />
          )}
          {task.status === 'paused' && (
            <Button
              type="text"
              aria-label="继续任务"
              icon={<Play className="h-4 w-4 text-primary" />}
              onClick={() => resumeMutation.mutate(task.id)}
            />
          )}
          {['running', 'paused'].includes(task.status) && (
            <Button
              type="text"
              danger
              aria-label="停止任务"
              icon={<Square className="h-4 w-4" />}
              onClick={() => cancelMutation.mutate(task.id)}
            />
          )}
          {(task.status === 'failed' || task.status === 'cancelled') && (
            <Button
              type="text"
              aria-label="重试任务"
              icon={<RotateCw className="h-4 w-4 text-muted-foreground" />}
              onClick={() => retryMutation.mutate(task.id)}
            />
          )}
          <Link to={`/tasks/${task.id}`}>
            <Button type="text" aria-label="查看任务" icon={<Eye className="h-4 w-4" />} />
          </Link>
          <Button
            type="text"
            danger
            aria-label="删除任务"
            title="删除任务"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
              const ok = await confirm({
                title: `删除任务「${task.name}」？`,
                description: '任务及其结果索引将被删除，结果历史不可恢复。',
                destructive: true,
              })
              if (ok) deleteMutation.mutate(task.id)
            }}
            disabled={task.status === 'running'}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">任务管理</h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button type="primary" size="small" onClick={() => setCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            创建任务
          </Button>
        </div>
      </div>

      {/* 创建任务弹窗 */}
      <TaskCreateDialog open={createDialogOpen} onOpenChange={setCreateDialogOpen} />

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索任务..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select
          className="w-40"
          value={statusFilter}
          placeholder="选择状态"
          onChange={(v) => setStatusFilter(v)}
          options={[
            { value: 'all', label: '全部状态' },
            { value: 'pending', label: '等待中' },
            { value: 'running', label: '运行中' },
            { value: 'paused', label: '已暂停' },
            { value: 'completed', label: '已完成' },
            { value: 'failed', label: '失败' },
            { value: 'cancelled', label: '已取消' },
          ]}
        />
      </div>

      {/* Table */}
      <div className="rounded-lg border">
        <Table<Task>
          columns={columns}
          dataSource={tasks}
          rowKey="id"
          loading={isLoading}
          locale={{
            emptyText: <EmptyState title="暂无数据" className="border-0" />,
          }}
          pagination={false}
        />
      </div>

      {/* Pagination：游标分页（服务端无 total），保留上一页/下一页 */}
      {(page > 1 || hasMore) && (
        <div className="flex items-center justify-center gap-2">
          <Button
            size="small"
            disabled={page <= 1}
            onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
          >
            上一页
          </Button>
          <span className="px-4 py-2 text-sm text-muted-foreground">
            第 {page} 页 · 本页 {tasks.length} 条
          </span>
          <Button
            size="small"
            disabled={!hasMore || !nextCursor}
            onClick={() => setCursorStack((stack) => [...stack, nextCursor])}
          >
            下一页
          </Button>
        </div>
      )}
    </div>
  )
}

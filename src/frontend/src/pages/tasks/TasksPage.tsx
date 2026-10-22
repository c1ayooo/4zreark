import { useEffect, useState } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { taskApi, Task } from '@/api/tasks'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Progress } from '@/components/ui/progress'
import { useToast } from '@/components/ui/use-toast'
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

export default function TasksPage() {
  const { toast } = useToast()
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
    refetchInterval: 5000, // Auto refresh every 5s for running tasks
  })

  const startMutation = useMutation({
    mutationFn: taskApi.startTask,
    onSuccess: () => {
      toast({ title: '任务已启动' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '启动任务失败', variant: 'destructive' })
    },
  })

  const pauseMutation = useMutation({
    mutationFn: taskApi.pauseTask,
    onSuccess: () => {
      toast({ title: '任务已暂停' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '暂停任务失败', variant: 'destructive' })
    },
  })

  const cancelMutation = useMutation({
    mutationFn: taskApi.cancelTask,
    onSuccess: () => {
      toast({ title: '任务已取消' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '取消任务失败', variant: 'destructive' })
    },
  })

  const resumeMutation = useMutation({
    mutationFn: taskApi.resumeTask,
    onSuccess: () => {
      toast({ title: '任务已恢复' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '恢复任务失败', variant: 'destructive' })
    },
  })

  const retryMutation = useMutation({
    mutationFn: taskApi.retryTask,
    onSuccess: () => {
      toast({ title: '任务已重试' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '重试任务失败', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: taskApi.deleteTask,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
    onError: () => {
      toast({ title: '删除任务失败', variant: 'destructive' })
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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">任务管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
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
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="选择状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="pending">等待中</SelectItem>
            <SelectItem value="running">运行中</SelectItem>
            <SelectItem value="paused">已暂停</SelectItem>
            <SelectItem value="completed">已完成</SelectItem>
            <SelectItem value="failed">失败</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>任务名称</TableHead>
              <TableHead className="hidden md:table-cell">类型</TableHead>
              <TableHead>状态</TableHead>
              <TableHead className="hidden text-right sm:table-cell">进度</TableHead>
              <TableHead className="hidden text-right md:table-cell">创建时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : tasks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              tasks.map((task) => (
                <TableRow key={task.id}>
                  <TableCell className="font-medium">
                    {task.name}
                    <div className="mt-1 text-[13px] tabular-nums text-muted-foreground sm:hidden">
                      {task.progress}%
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{task.type}</TableCell>
                  <TableCell>
                    <Badge className={cn(getStatusColor(task.status))}>
                      {getStatusLabel(task.status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="hidden text-right sm:table-cell">
                    <div className="w-28 text-left md:w-40">
                      <Progress value={task.progress} className="h-2" />
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
                  </TableCell>
                  <TableCell className="hidden text-right tabular-nums md:table-cell">{formatDate(task.createdAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      {task.status === 'pending' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="启动任务"
                          onClick={() => startMutation.mutate(task.id)}
                        >
                          <Play className="h-4 w-4 text-primary" />
                        </Button>
                      )}
                      {task.status === 'running' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="暂停任务"
                          onClick={() => pauseMutation.mutate(task.id)}
                        >
                          <Pause className="h-4 w-4 text-amber-600" />
                        </Button>
                      )}
                      {task.status === 'paused' && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="继续任务"
                          onClick={() => resumeMutation.mutate(task.id)}
                        >
                          <Play className="h-4 w-4 text-primary" />
                        </Button>
                      )}
                      {['running', 'paused'].includes(task.status) && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="停止任务"
                          onClick={() => cancelMutation.mutate(task.id)}
                        >
                          <Square className="h-4 w-4 text-destructive" />
                        </Button>
                      )}
                      {(task.status === 'failed' || task.status === 'cancelled') && (
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="重试任务"
                          onClick={() => retryMutation.mutate(task.id)}
                        >
                          <RotateCw className="h-4 w-4 text-muted-foreground" />
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" asChild aria-label="查看任务">
                        <Link to={`/tasks/${task.id}`}>
                          <Eye className="h-4 w-4" />
                        </Link>
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label="删除任务"
                        onClick={() => deleteMutation.mutate(task.id)}
                        disabled={task.status === 'running'}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {(page > 1 || hasMore) && (
        <div className="flex items-center justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1}
            onClick={() => setCursorStack((stack) => stack.slice(0, -1))}
          >
            上一页
          </Button>
          <span className="px-4 py-2 text-sm text-muted-foreground">
            第 {page} 页 · 本页 {tasks.length} 条
          </span>
          <Button
            variant="outline"
            size="sm"
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

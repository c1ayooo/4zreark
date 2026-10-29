import { useEffect, useState } from 'react'
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Eraser, ScrollText, Settings, RefreshCw } from 'lucide-react'

import { taskLogApi, taskLogCategories, type ActionLogRow } from '@/api/tasklogs'
import { taskApi } from '@/api/tasks'
import { projectApi } from '@/api/projects'
import { useAuthStore } from '@/store/auth'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { statusTagClass } from '@/components/ui/StatusTag'
import { cn, formatDate } from '@/lib/utils'

const PAGE_SIZE = 50

interface TaskLogListResponse {
  code: number
  message: string
  data: ActionLogRow[]
  total: number
}

const levelLabel: Record<string, string> = {
  info: '信息',
  success: '成功',
  warn: '警告',
  warning: '警告',
  error: '错误',
}

const jobStatusLabel: Record<string, string> = {
  running: '运行中',
  done: '已完成',
  error: '失败',
  canceled: '已取消',
  queued: '排队中',
  completed: '已完成',
  failed: '失败',
  canceled_icp: '已取消',
}

// 任务日志：跨源聚合所有动作（task_logs / ICP 查询 / 企业采集），
// 按功能分类筛选，支持自动清空时段。
export default function TaskLogsPage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'

  const [projectId, setProjectId] = useState('0')
  const [category, setCategory] = useState('')
  const [level, setLevel] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [retentionDays, setRetentionDays] = useState(14)
  const [detailRow, setDetailRow] = useState<ActionLogRow | null>(null)

  useEffect(() => { setPage(1) }, [category, level, projectId])

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })

  const logs = useQuery({
    queryKey: ['task-logs', projectId, category, level, page],
    queryFn: () =>
      taskLogApi.list({
        project_id: Number(projectId) || undefined,
        category: category || undefined,
        level: level || undefined,
        page,
        page_size: PAGE_SIZE,
      }) as unknown as Promise<TaskLogListResponse>,
    placeholderData: keepPreviousData,
    // 有运行中任务时自动刷新（后台任务列表同款节奏）
    refetchInterval: 10000,
  })

  const settings = useQuery({
    queryKey: ['tasklog-settings'],
    queryFn: () => taskLogApi.settings(),
    enabled: settingsOpen,
  })

  
  const rows = logs.data?.data ?? []
  const total = (logs.data as unknown as TaskLogListResponse)?.total ?? 0

  const saveSettings = useMutation({
    mutationFn: () => taskLogApi.saveSettings(retentionDays),
    onSuccess: (res) => {
      toast({ title: '自动清空时段已保存', description: `按新时段清理了 ${res.data?.purged ?? 0} 条过期日志` })
      queryClient.invalidateQueries({ queryKey: ['tasklog-settings'] })
      setSettingsOpen(false)
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const purge = useMutation({
    mutationFn: () => taskLogApi.purge(),
    onSuccess: (res) => {
      toast({ title: '已清空', description: `${res.data?.purged ?? 0} 条日志` })
      queryClient.invalidateQueries({ queryKey: ['task-logs'] })
    },
    onError: (e: any) =>
      toast({ title: '清空失败', description: e?.message, variant: 'destructive' }),
  })

  const columns: TableProps<ActionLogRow>['columns'] = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (_, r) => <span className="font-mono text-xs text-muted-foreground">{formatDate(r.created_at)}</span>,
    },
    {
      title: '功能',
      dataIndex: 'category',
      key: 'category',
      width: 110,
      render: (_, r) => {
        const cat = taskLogCategories.find((c) => c.value === r.category)
        return <Tag className={statusTagClass('outline')}>{cat?.label ?? r.category}</Tag>
      },
    },
    {
      title: '动作',
      dataIndex: 'title',
      key: 'title',
      render: (_, r) => <span className="text-sm">{r.title}</span>,
    },
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 80,
      render: (_, r) => (
        <Tag
          className={statusTagClass(
            r.level === 'error' ? 'destructive' : r.level === 'success' ? 'success' : r.level === 'warn' || r.level === 'warning' ? 'warning' : 'outline'
          )}
        >
          {levelLabel[r.level] ?? r.level}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, r) => (r.status ? <span className="text-xs text-muted-foreground">{jobStatusLabel[r.status] ?? r.status}</span> : <span className="text-muted-foreground/50">—</span>),
    },
    {
      title: '详情',
      dataIndex: 'detail',
      key: 'detail',
      ellipsis: true,
      render: (_, r) => <span className="text-muted-foreground text-xs">{r.detail || '—'}</span>,
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold">
            <ScrollText className="h-6 w-6" /> 任务日志
          </h1>
          <p className="text-muted-foreground mt-1 text-sm">
            跨源聚合所有动作：扫描任务运行日志、ICP 查询、企业采集，按功能筛选
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="small" onClick={() => logs.refetch()} disabled={logs.isFetching}>
            <RefreshCw className={cn('mr-2 h-4 w-4', logs.isFetching && 'animate-spin')} /> 刷新
          </Button>
          {isAdmin && (
            <>
              <Button size="small" onClick={() => setSettingsOpen(true)}>
                <Settings className="mr-2 h-4 w-4" /> 自动清空
              </Button>
              <Button
                size="small"
                danger
                onClick={async () => {
                  if (await confirm('清空全部任务运行日志？此操作不可恢复。')) purge.mutate()
                }}
                disabled={purge.isPending}
              >
                <Eraser className="mr-2 h-4 w-4" /> 清空日志
              </Button>
            </>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          className="w-44"
          placeholder="全部功能"
          value={category || undefined}
          onChange={(v) => setCategory(v || '')}
          allowClear
          options={taskLogCategories}
        />
        <Select
          className="w-36"
          placeholder="全部项目"
          value={projectId === '0' ? undefined : projectId}
          onChange={(v) => setProjectId(v || '0')}
          allowClear
          options={(projects.data?.data ?? []).map((p) => ({ value: String(p.id), label: p.name }))}
          showSearch
          optionFilterProp="label"
        />
        <Select
          className="w-32"
          placeholder="全部级别"
          value={level || undefined}
          onChange={(v) => setLevel(v || '')}
          allowClear
          options={[
            { value: 'info', label: '信息' },
            { value: 'success', label: '成功' },
            { value: 'warn', label: '警告' },
            { value: 'error', label: '错误' },
          ]}
        />
        <Input
          className="w-64"
          placeholder="搜索动作 / 详情"
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPage(1)
          }}
          allowClear
        />
        <span className="text-muted-foreground ml-auto text-sm">{total} 条</span>
      </div>

      <div className="rounded-lg border">
        <Table<ActionLogRow>
          columns={columns}
          dataSource={rows}
          rowKey={(r) => `${r.created_at}-${r.ref}-${r.category}`}
          loading={logs.isLoading}
          size="small"
          locale={{ emptyText: '暂无日志（任务执行的动作会实时写入）' }}
          onRow={(r) => ({
            className: 'cursor-pointer',
            onClick: () => setDetailRow(r),
          })}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showSizeChanger: false,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      <Modal open={settingsOpen} onCancel={() => setSettingsOpen(false)} title="日志自动清空" footer={null} width={420}>
        <div className="space-y-4">
          <div className="space-y-1">
            <label className="text-sm font-medium">留存时段（天）</label>
            <div className="flex items-center gap-2">
              <Input
                type="number"
                min={1}
                max={365}
                value={retentionDays}
                onChange={(e) => setRetentionDays(Number(e.target.value) || 14)}
              />
              <span className="text-muted-foreground text-sm">天前的日志自动删除</span>
            </div>
            <p className="text-muted-foreground text-xs">
              每小时自动清理一次；保存时会立即按新时段清理一次。当前设置：{settings.data?.data?.retention_days ?? 14} 天。
            </p>
          </div>
          <Button type="primary" block loading={saveSettings.isPending} onClick={() => saveSettings.mutate()}>
            保存并立即清理
          </Button>
        </div>
      </Modal>

      <Modal
        open={!!detailRow}
        onCancel={() => setDetailRow(null)}
        footer={
          <Button onClick={() => setDetailRow(null)}>关闭</Button>
        }
        title={
          <span className="flex items-center gap-2">
            <ScrollText className="h-4 w-4" />
            任务日志详情
            {detailRow && <Tag className={statusTagClass('outline')}>{detailRow.title}</Tag>}
          </span>
        }
        width={720}
      >
        {detailRow && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Tag className={statusTagClass(
                detailRow.level === 'error' ? 'destructive' : detailRow.level === 'success' ? 'success' : detailRow.level === 'warn' || detailRow.level === 'warning' ? 'warning' : 'outline'
              )}>
                {levelLabel[detailRow.level] ?? detailRow.level}
              </Tag>
              {detailRow.status && (
                <span className="text-muted-foreground text-xs">状态：{jobStatusLabel[detailRow.status] ?? detailRow.status}</span>
              )}
              <span className="text-muted-foreground text-xs">{formatDate(detailRow.created_at)}</span>
            </div>
            {detailRow.detail && (
              <div className="text-muted-foreground rounded-md bg-muted/50 px-3 py-2 text-xs">{detailRow.detail}</div>
            )}
            {/* 运行明细（该任务的 task_logs，支持检索） */}
            <TaskLogLines taskId={detailRow.ref} />
          </div>
        )}
      </Modal>
    </div>
  )
}


// 任务运行明细：拉取该任务的 task_logs 行，支持关键词过滤（客户端检索）
function TaskLogLines({ taskId }: { taskId: string }) {
  const [q, setQ] = useState('')
  const logs = useQuery({
    queryKey: ['tasklog-lines', taskId],
    queryFn: () => taskApi.getTaskLogs(taskId, { pageSize: 200 }),
    staleTime: 30_000,
  })
  const lines = (logs.data?.data?.list ?? []).filter((l) =>
    !q.trim() || (l.message || '').toLowerCase().includes(q.trim().toLowerCase())
  )
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground text-xs">运行明细（{lines.length} 行）</span>
        <Input
          className="w-52"
          size="small"
          placeholder="检索日志…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          allowClear
        />
      </div>
      <div className="max-h-72 space-y-1 overflow-auto rounded-md border p-2">
        {logs.isLoading ? (
          <p className="text-muted-foreground p-2 text-sm">加载中…</p>
        ) : lines.length === 0 ? (
          <p className="text-muted-foreground p-2 text-sm">该任务暂无运行明细</p>
        ) : (
          lines.map((l, i) => (
            <div key={l.id ?? i} className="flex items-start gap-2 rounded px-1.5 py-1 text-xs hover:bg-muted/60">
              <span className="text-muted-foreground/70 shrink-0 font-mono">{formatDate(l.timestamp)}</span>
              <span className="shrink-0">{l.level === 'error' ? '✗' : l.level === 'warn' ? '⚠' : '·'}</span>
              <span className="whitespace-pre-wrap break-all">{l.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
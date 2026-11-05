import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { RefreshCw, ScrollText } from 'lucide-react'
import { Button, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { auditApi, type OperationLog } from '@/api/audit'
import RecordDetailDrawer from '@/components/common/RecordDetailDrawer'
import { formatDate } from '@/lib/utils'

const pageSize = 50

// detail 是后端拼的字符串：能解析成对象时走 raw pretty 展示，否则当长文本全量展示
function parseDetailObject(detail: string): Record<string, unknown> | undefined {
  if (!detail) return undefined
  try {
    const parsed: unknown = JSON.parse(detail)
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : undefined
  } catch {
    return undefined
  }
}

export default function AuditPage() {
  const [username, setUsername] = useState('')
  const [action, setAction] = useState('')
  const [module, setModule] = useState('')
  const [status, setStatus] = useState<'all' | '1' | '0'>('all')
  const [applied, setApplied] = useState<{
    username: string
    action: string
    module: string
    status: 'all' | '1' | '0'
  }>({ username: '', action: '', module: '', status: 'all' })
  const [page, setPage] = useState(1)
  // 行点击打开的详情抽屉：受控存当前日志，truncate 掉的 target/detail 全文在这里看
  const [detailLog, setDetailLog] = useState<OperationLog | null>(null)

  const list = useQuery({
    queryKey: ['audit', applied, page],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      auditApi.list({
        username: applied.username || undefined,
        action: applied.action || undefined,
        module: applied.module || undefined,
        status: applied.status === 'all' ? undefined : applied.status,
        page,
        page_size: pageSize,
      }),
  })

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0

  const apply = () => {
    setApplied({ username, action, module, status })
    setPage(1)
  }

  // /audit 无排序参数，时间列走客户端排序
  // 行点击看详情：写法同 DiscoveryCandidatesPanel 的 onRow
  const onRow: TableProps<OperationLog>['onRow'] = (l) => ({
    className: 'cursor-pointer',
    onClick: () => setDetailLog(l),
  })

  const detailRaw = detailLog ? parseDetailObject(detailLog.detail) : undefined
  const detailFields = detailLog
    ? [
        { label: '时间', value: formatDate(detailLog.created_at) },
        { label: '用户', value: detailLog.username || '' },
        { label: '动作', value: detailLog.action || '' },
        { label: '模块', value: detailLog.module || '' },
        { label: '目标', value: detailLog.target || '' },
        // detail 能解析成 JSON 对象时由 raw 区展示全文，字段区不重复
        ...(detailLog.detail && !detailRaw
          ? [{ label: '详情', value: detailLog.detail }]
          : []),
        { label: 'IP', value: detailLog.ip || '' },
        { label: 'User-Agent', value: detailLog.user_agent || '' },
        { label: '结果', value: detailLog.status === 1 ? '成功' : '失败' },
      ]
    : []

  const columns: TableProps<OperationLog>['columns'] = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (v: string) => <span className="text-xs text-muted-foreground">{formatDate(v)}</span>,
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: '用户',
      dataIndex: 'username',
      key: 'username',
      width: 120,
      render: (v: string) => <span className="text-sm">{v || '—'}</span>,
    },
    {
      title: '动作',
      dataIndex: 'action',
      key: 'action',
      width: 110,
      render: (v: string) => <span className="font-mono text-xs">{v || '—'}</span>,
    },
    {
      title: '模块',
      dataIndex: 'module',
      key: 'module',
      width: 110,
      render: (v: string) => <span className="font-mono text-xs text-muted-foreground">{v || '—'}</span>,
    },
    {
      title: '目标 / 详情',
      key: 'target',
      render: (_, l) => (
        <div className="max-w-[360px]">
          <div className="truncate font-mono text-xs">{l.target || '—'}</div>
          {l.detail && <div className="truncate text-xs text-muted-foreground">{l.detail}</div>}
        </div>
      ),
    },
    {
      title: 'IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 130,
      render: (v: string) => <span className="font-mono text-xs text-muted-foreground">{v || '—'}</span>,
    },
    {
      title: '结果',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (v: number) => (v === 1 ? <Tag>成功</Tag> : <Tag color="red">失败</Tag>),
    },
  ]

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">审计日志</h1>
          <p className="text-sm text-muted-foreground">
            所有写操作的留痕（项目/资产删除、数据源、用户管理、强制复验等），只读
          </p>
        </div>
        <Button onClick={() => list.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">用户</span>
          <Input
            className="w-[160px]"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="用户名"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">动作</span>
          <Input
            className="w-[160px]"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="如 delete / update"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">模块</span>
          <Input
            className="w-[160px]"
            value={module}
            onChange={(e) => setModule(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="如 assets / users"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">结果</span>
          <Select
            className="w-[110px]"
            value={status}
            onChange={(v) => setStatus(v as 'all' | '1' | '0')}
            options={[
              { value: 'all', label: '全部' },
              { value: '1', label: '成功' },
              { value: '0', label: '失败' },
            ]}
          />
        </div>
        <Button onClick={apply}>查询</Button>
        <span className="ml-auto text-sm text-muted-foreground">共 {total.toLocaleString()} 条</span>
      </div>

      <div className="overflow-hidden rounded-md border">
        <Table<OperationLog>
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={list.isLoading}
          onRow={onRow}
          locale={{
            emptyText: list.isError ? (
              <div className="py-10 text-center text-destructive">
                <ScrollText className="mx-auto mb-2 h-6 w-6 opacity-60" />
                审计日志加载失败
                <div>
                  <Button type="link" size="small" onClick={() => list.refetch()}>重试</Button>
                </div>
              </div>
            ) : (
              <div className="py-10 text-center text-muted-foreground">
                <ScrollText className="mx-auto mb-2 h-6 w-6 opacity-40" />
                没有匹配的审计日志
              </div>
            ),
          }}
          pagination={{
            current: page,
            pageSize,
            total,
            showQuickJumper: true,
            // page_size 固定 50、无独立 pageSize 状态，不展示切换器
            showSizeChanger: false,
            hideOnSinglePage: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      <RecordDetailDrawer
        open={detailLog !== null}
        onClose={() => setDetailLog(null)}
        title="审计日志详情"
        fields={detailFields}
        raw={detailRaw}
      />
    </div>
  )
}

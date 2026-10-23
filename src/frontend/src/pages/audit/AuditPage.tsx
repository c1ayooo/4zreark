import { useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { RefreshCw, ScrollText } from 'lucide-react'
import { Button, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { auditApi, type OperationLog } from '@/api/audit'
import { formatDate } from '@/lib/utils'

const pageSize = 50

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
          locale={{
            emptyText: (
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
    </div>
  )
}

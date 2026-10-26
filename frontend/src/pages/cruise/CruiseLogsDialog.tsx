import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { cruiseApi, CruiseTask, CruiseLog } from '@/api/cruise'
import { Modal, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import EmptyState from '@/components/common/EmptyState'
import { formatDate } from '@/lib/utils'
import {
  CheckCircle,
  XCircle,
  Clock,
  Loader2,
  ExternalLink,
} from 'lucide-react'
import { Link } from 'react-router-dom'

interface CruiseLogsDialogProps {
  cruise: CruiseTask
  open: boolean
  onOpenChange: (open: boolean) => void
}

export default function CruiseLogsDialog({
  cruise,
  open,
  onOpenChange,
}: CruiseLogsDialogProps) {
  const [page, setPage] = useState(1)

  const { data, isLoading } = useQuery({
    queryKey: ['cruiseLogs', cruise.id, page],
    queryFn: () => cruiseApi.getCruiseLogs(cruise.id, { page, pageSize: 10 }),
    enabled: open,
  })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return (
          <Tag className="border-transparent bg-green-500 text-white">
            <CheckCircle className="h-3 w-3 mr-1" />
            成功
          </Tag>
        )
      case 'failed':
        return (
          <Tag className="border-transparent bg-destructive text-destructive-foreground">
            <XCircle className="h-3 w-3 mr-1" />
            失败
          </Tag>
        )
      case 'running':
        return (
          <Tag className="border-transparent bg-blue-500 text-white">
            <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            执行中
          </Tag>
        )
      case 'timeout':
        return (
          <Tag className="border-transparent bg-secondary text-secondary-foreground">
            <Clock className="h-3 w-3 mr-1" />
            超时
          </Tag>
        )
      case 'cancelled':
        return <Tag className="border-transparent bg-secondary text-secondary-foreground">已取消</Tag>
      default:
        return <Tag>{status}</Tag>
    }
  }

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}秒`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}分${seconds % 60}秒`
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    return `${hours}时${mins}分`
  }

  const columns: TableProps<CruiseLog>['columns'] = [
    {
      title: '开始时间',
      dataIndex: 'start_time',
      key: 'start_time',
      width: 160,
      render: (v: string) => <span className="text-sm">{formatDate(v)}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => getStatusBadge(v),
    },
    {
      title: '耗时',
      dataIndex: 'duration',
      key: 'duration',
      width: 100,
      render: (v: number) => <span className="text-sm">{v > 0 ? formatDuration(v) : '-'}</span>,
    },
    {
      title: '发现资产',
      dataIndex: 'result_count',
      key: 'result_count',
      width: 90,
    },
    {
      title: '发现漏洞',
      dataIndex: 'vuln_count',
      key: 'vuln_count',
      width: 90,
      render: (v: number) =>
        v > 0 ? <span className="text-red-500 font-medium">{v}</span> : 0,
    },
    {
      title: '错误信息',
      dataIndex: 'error',
      key: 'error',
      ellipsis: true,
      render: (v?: string) =>
        v ? (
          <span className="text-red-500 text-sm" title={v}>
            {v}
          </span>
        ) : (
          '-'
        ),
    },
    {
      title: '关联任务',
      dataIndex: 'task_id',
      key: 'task_id',
      width: 90,
      render: (v: string) =>
        v && v !== '000000000000000000000000' ? (
          <Link
            to={`/tasks/${v}`}
            className="text-blue-500 hover:underline inline-flex items-center"
          >
            查看
            <ExternalLink className="h-3 w-3 ml-1" />
          </Link>
        ) : (
          '-'
        ),
    },
  ]

  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      title={`执行日志 - ${cruise.name}`}
      width={896}
      footer={null}
    >
      <Table
        columns={columns}
        dataSource={data?.items ?? []}
        rowKey="id"
        loading={isLoading}
        locale={{ emptyText: <EmptyState title="暂无执行记录" className="border-0" /> }}
        pagination={{
          current: page,
          pageSize: 10,
          total: data?.total ?? 0,
          hideOnSinglePage: true,
          showTotal: (t) => `共 ${t} 条记录`,
          onChange: (p) => setPage(p),
        }}
      />
    </Modal>
  )
}

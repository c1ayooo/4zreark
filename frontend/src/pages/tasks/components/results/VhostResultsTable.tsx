import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { indexColumn, ResultTable } from './shared'
import type { ResultsTableCtx } from './shared'

// VhostResultsTable vhost 绑定发现结果：IP:端口 上改 Host 探测出的隐藏绑定。
// 弱证据（响应不同形），只做人工线索，不自动进资产域。
export default function VhostResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: '域名',
      key: 'domain',
      width: 220,
      className: 'font-mono text-xs break-all',
      render: (_, item) => item.domain as string,
    },
    {
      title: '服务地址',
      key: 'url',
      width: 220,
      className: 'font-mono text-xs break-all',
      render: (_, item) => `${item.ip}:${item.port}`,
    },
    {
      title: '标题',
      key: 'title',
      width: 220,
      ellipsis: true,
      render: (_, item) => (item.title as string) || '-',
    },
    { title: '状态', key: 'status_code', width: 80, className: 'tabular-nums', render: (_, item) => (item.status_code as number) || '-' },
    { title: '长度', key: 'length', width: 90, className: 'tabular-nums', render: (_, item) => (item.length as number) || '-' },
    { title: 'TAG', key: 'tags', width: 160, render: () => <Tag>vhost</Tag> },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1000} />
}

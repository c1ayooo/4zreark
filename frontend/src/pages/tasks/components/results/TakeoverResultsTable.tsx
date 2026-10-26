import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'

// 子域名接管检测结果表格
export default function TakeoverResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    { title: '子域名', key: 'subdomain', width: 220, className: 'font-mono', render: (_, item) => item.subdomain as string },
    { title: 'CNAME', key: 'cname', width: 200, ellipsis: true, className: 'font-mono text-xs', render: (_, item) => item.cname as string || '-' },
    { title: '服务商', key: 'provider', width: 120, render: (_, item) => <Tag>{item.provider as string || '-'}</Tag> },
    {
      title: '风险等级',
      key: 'severity',
      width: 100,
      render: (_, item) => (
        <Tag
          className={
            (item.severity as string) === 'high'
              ? TAG_DESTRUCTIVE
              : (item.severity as string) === 'medium'
                ? TAG_SECONDARY
                : undefined
          }
        >
          {(item.severity as string) || '高'}
        </Tag>
      ),
    },
    {
      title: '原因',
      key: 'reason',
      width: 300,
      ellipsis: true,
      render: (_, item) => <span title={item.reason as string}>{item.reason as string || '-'}</span>,
    },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return (
    <ResultTable
      ctx={ctx}
      rowKey="id"
      columns={columns}
      scrollX={1000}
      rowClassName={(item) => ((item.vulnerable as boolean) ? 'bg-destructive/5' : '')}
    />
  )
}

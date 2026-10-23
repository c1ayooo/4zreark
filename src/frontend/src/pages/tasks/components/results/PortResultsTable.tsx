import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { cn, formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'

export default function PortResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    { title: 'IP', key: 'ip', width: 160, className: 'font-mono', render: (_, item) => item.ip as string },
    {
      title: '端口',
      key: 'ports',
      render: (_, item) => {
        const ports = (item.ports as string[]) || []
        return (
          <div className="flex flex-wrap gap-1">
            {ports.slice(0, 10).map((port, i) => (
              <Tag key={i} className="text-xs">
                {port}
              </Tag>
            ))}
            {ports.length > 10 && (
              <Tag className={cn(TAG_SECONDARY, 'text-xs')}>+{ports.length - 10}</Tag>
            )}
          </div>
        )
      },
    },
    {
      title: '服务',
      key: 'services',
      render: (_, item) => {
        const services = (item.services as string[]) || []
        return (
          <div className="flex flex-wrap gap-1">
            {[...new Set(services.filter(Boolean))].slice(0, 5).map((s: string, i) => (
              <Tag key={i} className={cn(TAG_SECONDARY, 'text-xs')}>{s}</Tag>
            ))}
            {[...new Set(services.filter(Boolean))].length > 5 && (
              <Tag className="text-xs">+{[...new Set(services.filter(Boolean))].length - 5}</Tag>
            )}
          </div>
        )
      },
    },
    { title: '时间', key: 'created_at', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.created_at as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="ip" columns={columns} scrollX={900} />
}

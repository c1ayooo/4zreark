import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'
import { safeExternalURL } from '@/lib/safeUrl'

export default function SensitiveResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: 'URL',
      key: 'url',
      width: 300,
      ellipsis: true,
      render: (_, item) => (
        <a
          href={safeExternalURL(item.url as string) ?? undefined}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline"
        >
          {item.url as string}
        </a>
      ),
    },
    { title: '类型', key: 'type', width: 110, render: (_, item) => <Tag>{item.type as string}</Tag> },
    { title: '模式', key: 'pattern', width: 140, className: 'text-muted-foreground', render: (_, item) => item.pattern as string },
    {
      title: '匹配内容',
      key: 'matches',
      width: 200,
      ellipsis: true,
      className: 'font-mono text-xs',
      render: (_, item) => (
        <span title={Array.isArray(item.matches) ? (item.matches as string[]).join(', ') : ''}>
          {Array.isArray(item.matches) ? (item.matches as string[]).slice(0, 2).join(', ') : '-'}
          {Array.isArray(item.matches) && (item.matches as string[]).length > 2 && '...'}
        </span>
      ),
    },
    {
      title: '级别',
      key: 'severity',
      width: 100,
      render: (_, item) => (
        <Tag
          className={
            (item.severity as string) === 'critical' || (item.severity as string) === 'high' ? TAG_DESTRUCTIVE :
            (item.severity as string) === 'medium' ? TAG_PRIMARY : TAG_SECONDARY
          }
        >
          {item.severity as string}
        </Tag>
      ),
    },
    { title: '位置', key: 'location', width: 110, className: 'text-muted-foreground', render: (_, item) => item.location as string },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1100} />
}

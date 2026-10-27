import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'
import { safeExternalURL } from '@/lib/safeUrl'

export default function UrlResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: 'URL',
      key: 'url',
      width: 400,
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
    { title: '方法', key: 'method', width: 90, render: (_, item) => <Tag>{(item.method as string) || 'GET'}</Tag> },
    {
      title: '状态码',
      key: 'statusCode',
      width: 90,
      render: (_, item) => (
        <Tag className={(item.statusCode as number) === 200 ? TAG_PRIMARY : TAG_SECONDARY}>
          {item.statusCode as number || '-'}
        </Tag>
      ),
    },
    { title: '类型', key: 'contentType', width: 160, className: 'text-muted-foreground', render: (_, item) => item.contentType as string || '-' },
    { title: '长度', key: 'length', width: 90, className: 'text-muted-foreground', render: (_, item) => item.length as number || '-' },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1000} />
}

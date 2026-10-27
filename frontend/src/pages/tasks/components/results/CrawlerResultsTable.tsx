import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'
import { safeExternalURL } from '@/lib/safeUrl'

export default function CrawlerResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: 'URL',
      key: 'url',
      width: 400,
      ellipsis: true,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (
          <a
            href={safeExternalURL(data.url as string) ?? undefined}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline"
          >
            {data.url as string}
          </a>
        )
      },
    },
    {
      title: '方法',
      key: 'method',
      width: 90,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return <Tag>{(data.method as string) || 'GET'}</Tag>
      },
    },
    {
      title: '状态码',
      key: 'status_code',
      width: 90,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return data.status_code ? (
          <Tag
            className={
              (data.status_code as number) === 200 ? TAG_PRIMARY :
              (data.status_code as number) >= 400 ? TAG_DESTRUCTIVE : TAG_SECONDARY
            }
          >
            {data.status_code as number}
          </Tag>
        ) : '-'
      },
    },
    {
      title: '爬虫',
      key: 'crawler',
      width: 120,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (
          <Tag className="text-xs">
            {(data.crawler as string) || (item.source as string) || '-'}
          </Tag>
        )
      },
    },
    {
      title: '目标',
      key: 'target',
      width: 150,
      ellipsis: true,
      className: 'text-muted-foreground',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return data.target as string || '-'
      },
    },
    {
      title: '时间',
      key: 'createdAt',
      width: 160,
      className: 'text-muted-foreground',
      render: (_, item) => formatDate(item.createdAt as string),
    },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1000} />
}

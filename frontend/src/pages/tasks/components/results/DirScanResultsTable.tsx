import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'
import { safeExternalURL } from '@/lib/safeUrl'

export default function DirScanResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: 'URL',
      key: 'url',
      width: 400,
      ellipsis: true,
      render: (_, item) => {
        // 从 data 字段中提取数据
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
      title: '状态码',
      key: 'status',
      width: 90,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return data.status ? (
          <Tag
            className={
              (data.status as number) >= 200 && (data.status as number) < 300 ? TAG_PRIMARY :
              (data.status as number) >= 400 ? TAG_DESTRUCTIVE : TAG_SECONDARY
            }
          >
            {data.status as number}
          </Tag>
        ) : '-'
      },
    },
    {
      title: '大小',
      key: 'size',
      width: 90,
      className: 'text-muted-foreground',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return data.size ? `${data.size}` : '-'
      },
    },
    {
      title: '类型',
      key: 'content_type',
      width: 140,
      className: 'text-muted-foreground text-xs',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return data.content_type as string || '-'
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

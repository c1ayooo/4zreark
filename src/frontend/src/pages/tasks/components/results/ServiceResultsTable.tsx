import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ExternalLink } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'

export default function ServiceResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: 'URL',
      key: 'url',
      render: (_, item) => (
        <a
          href={item.url as string}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline flex items-center gap-1 max-w-xs truncate"
        >
          {item.url as string}
          <ExternalLink className="h-3 w-3 flex-shrink-0" />
        </a>
      ),
    },
    {
      title: '标题',
      key: 'title',
      width: 200,
      ellipsis: true,
      render: (_, item) => <span title={item.title as string}>{item.title as string || '-'}</span>,
    },
    {
      title: '状态码',
      key: 'status_code',
      width: 90,
      render: (_, item) => (
        <Tag
          className={
            (item.status_code as number) >= 200 && (item.status_code as number) < 300 ? TAG_PRIMARY :
            (item.status_code as number) >= 300 && (item.status_code as number) < 400 ? TAG_SECONDARY :
            (item.status_code as number) >= 400 ? TAG_DESTRUCTIVE : undefined
          }
        >
          {item.status_code as number || '-'}
        </Tag>
      ),
    },
    { title: 'Server', key: 'server', width: 140, className: 'text-muted-foreground', render: (_, item) => item.server as string || '-' },
    {
      title: '技术栈',
      key: 'technologies',
      width: 180,
      render: (_, item) => (
        (item.technologies as string[])?.slice(0, 3).map((tech: string) => (
          <Tag key={tech} className="mr-1 text-xs">{tech}</Tag>
        ))
      ),
    },
    {
      title: '指纹',
      key: 'fingerprints',
      width: 160,
      render: (_, item) => (
        (item.fingerprints as string[])?.slice(0, 2).map((fp: string) => (
          <Tag key={fp} className={cn(TAG_SECONDARY, 'mr-1 text-xs')}>{fp}</Tag>
        ))
      ),
    },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1100} />
}

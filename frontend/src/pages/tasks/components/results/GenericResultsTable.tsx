import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable } from './shared'
import type { ResultsTableCtx } from './shared'

export default function GenericResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: '数据',
      key: 'data',
      width: 400,
      ellipsis: true,
      className: 'font-mono text-xs',
      render: (_, item) => JSON.stringify(item.data || item),
    },
    { title: '项目', key: 'project', width: 140, render: (_, item) => item.project as string || '-' },
    {
      title: 'TAG',
      key: 'tags',
      width: 200,
      render: (_, item) => (
        (item.tags as string[])?.length > 0 ? (
          (item.tags as string[]).map((tag: string) => (
            <Tag key={tag} className="mr-1">{tag}</Tag>
          ))
        ) : '-'
      ),
    },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1000} />
}

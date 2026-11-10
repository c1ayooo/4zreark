import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_DESTRUCTIVE, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'
import { safeExternalURL } from '@/lib/safeUrl'

const kindLabels: Record<string, string> = {
  git: 'Git 仓库',
  svn: 'SVN 仓库',
  env: '环境变量',
  backup: '备份文件',
  docs: 'API 文档',
  debug: '调试端点',
}

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}

// FileLeakResultsTable 备份/敏感文件泄露结果：强特征命中的文件直链 + 证据摘要。
export default function FileLeakResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: '文件',
      key: 'url',
      width: 320,
      ellipsis: true,
      render: (_, item) => (
        <a
          href={safeExternalURL(item.url as string) ?? undefined}
          target="_blank"
          rel="noopener noreferrer"
          className="break-all font-mono text-primary hover:underline"
        >
          {item.url as string}
        </a>
      ),
    },
    {
      title: '类别',
      key: 'kind',
      width: 100,
      render: (_, item) => <Tag>{kindLabels[item.kind as string] ?? (item.kind as string)}</Tag>,
    },
    { title: '规则', key: 'name', width: 170, render: (_, item) => item.name as string },
    {
      title: '级别',
      key: 'severity',
      width: 90,
      render: (_, item) => {
        const sev = item.severity as string
        return (
          <Tag className={sev === 'critical' || sev === 'high' ? TAG_DESTRUCTIVE : sev === 'medium' ? TAG_PRIMARY : TAG_SECONDARY}>
            {severityLabels[sev] ?? sev}
          </Tag>
        )
      },
    },
    {
      title: '证据',
      key: 'evidence',
      width: 200,
      ellipsis: true,
      className: 'font-mono text-xs text-muted-foreground',
      render: (_, item) => (
        <span title={item.evidence as string}>{(item.evidence as string) || '-'}</span>
      ),
    },
    { title: '状态', key: 'status_code', width: 70, className: 'tabular-nums', render: (_, item) => (item.status_code as number) || '-' },
    { title: '长度', key: 'length', width: 90, className: 'tabular-nums', render: (_, item) => (item.length as number) || '-' },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt as string) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1200} />
}

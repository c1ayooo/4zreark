import { Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ExternalLink } from 'lucide-react'
import type { SubdomainResult } from '@/api/results'
import { formatDate } from '@/lib/utils'
import { indexColumn, ResultTable, TAG_PRIMARY, TAG_SECONDARY } from './shared'
import type { ResultsTableCtx } from './shared'

export default function SubdomainResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<SubdomainResult> = [
    indexColumn(ctx.page, ctx.pageSize),
    {
      title: '子域名',
      key: 'subdomain',
      render: (_, item) => {
        // 兼容不同数据格式：subdomain 或 domain 字段
        const subdomainName = item.subdomain || item.domain || '-'
        return (
          <a
            href={`https://${subdomainName}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary hover:underline flex items-center gap-1"
          >
            {subdomainName}
            <ExternalLink className="h-3 w-3" />
          </a>
        )
      },
    },
    {
      title: 'IP',
      key: 'ips',
      width: 150,
      className: 'text-muted-foreground font-mono text-xs',
      render: (_, item) => item.ips?.join(', ') || (item as unknown as { ip?: string }).ip || '-',
    },
    { title: '标题', key: 'title', width: 200, ellipsis: true, render: (_, item) => item.title || '-' },
    {
      title: '状态码',
      key: 'statusCode',
      width: 90,
      render: (_, item) => (
        item.statusCode && item.statusCode > 0 ? (
          <Tag className={item.statusCode === 200 ? TAG_PRIMARY : TAG_SECONDARY}>
            {item.statusCode}
          </Tag>
        ) : (
          <Tag className="text-muted-foreground">-</Tag>
        )
      ),
    },
    {
      title: 'CDN',
      key: 'cdn',
      width: 120,
      render: (_, item) => (
        item.cdn ? (
          <Tag>{item.cdnName || item.cdnProvider || 'CDN'}</Tag>
        ) : '-'
      ),
    },
    {
      title: '指纹',
      key: 'fingerprint',
      width: 200,
      render: (_, item) => (
        (item.technologies?.slice(0, 2) || item.fingerprint?.slice(0, 2))?.map((fp: string) => (
          <Tag key={fp} className="mr-1 text-xs">{fp}</Tag>
        )) || '-'
      ),
    },
    { title: '时间', key: 'createdAt', width: 160, className: 'text-muted-foreground', render: (_, item) => formatDate(item.createdAt) },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1000} />
}

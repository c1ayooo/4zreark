import { Button, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Eye } from 'lucide-react'
import { cn, getSeverityColor } from '@/lib/utils'
import { ResultTable } from './shared'
import type { ResultsTableCtx } from './shared'

export default function VulnResultsTable({ ctx }: { ctx: ResultsTableCtx }) {
  const columns: ColumnsType<Record<string, unknown>> = [
    {
      title: '等级',
      key: 'severity',
      width: 80,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        const severity = String(data.severity || '').toLowerCase()
        return (
          <Tag className={cn(getSeverityColor(severity), 'text-xs')}>
            {severity || 'unknown'}
          </Tag>
        )
      },
    },
    {
      title: '漏洞名称',
      key: 'name',
      width: 320,
      ellipsis: true,
      className: 'font-medium',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (data.name as string) || (data.vuln_id as string) || '-'
      },
    },
    {
      title: '目标',
      key: 'target',
      width: 240,
      ellipsis: true,
      className: 'font-mono text-xs',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (data.target as string) || '-'
      },
    },
    {
      title: '匹配位置',
      key: 'matched_at',
      width: 260,
      ellipsis: true,
      className: 'font-mono text-xs text-muted-foreground',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (data.matched_at as string) || '-'
      },
    },
    {
      title: '来源',
      key: 'source',
      width: 112,
      className: 'text-muted-foreground',
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (item.source as string) || (data.source as string) || '-'
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 96,
      render: (_, item) => {
        const data = (item.data || item) as Record<string, unknown>
        return (
          <Button
            type="text"
            size="small"
            onClick={() => ctx.onViewVuln(data)}
          >
            <Eye className="h-4 w-4 mr-1" />
            详情
          </Button>
        )
      },
    },
  ]
  return <ResultTable ctx={ctx} rowKey="id" columns={columns} scrollX={1100} emptyText="暂无漏洞" />
}

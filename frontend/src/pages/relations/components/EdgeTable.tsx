import { Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Network } from 'lucide-react'

import { relationTypeLabel, type RelationEdge } from '@/api/relations'
import EmptyState from '@/components/common/EmptyState'

// 关系边清单表格：从 RelationsPage 抽出，行级精确浏览用（图谱视图的互补面）。

const edgeColumns: TableProps<RelationEdge>['columns'] = [
  {
    title: '类型',
    dataIndex: 'type',
    key: 'type',
    width: 110,
    render: (v: string) => <Tag>{relationTypeLabel[v] ?? v}</Tag>,
  },
  {
    title: '聚类键',
    dataIndex: 'key',
    key: 'key',
    render: (v: string) => <span className="font-mono text-xs text-muted-foreground">{v}</span>,
  },
  {
    title: '站点 A',
    key: 'left',
    render: (_, e) => (
      <div>
        <div className="text-sm font-mono">{e.left.host}</div>
        <div className="text-xs text-muted-foreground">
          {e.left.title || '—'} · {e.left.ip || '—'}
        </div>
      </div>
    ),
  },
  {
    title: '站点 B',
    key: 'right',
    render: (_, e) => (
      <div>
        <div className="text-sm font-mono">{e.right.host}</div>
        <div className="text-xs text-muted-foreground">
          {e.right.title || '—'} · {e.right.ip || '—'}
        </div>
      </div>
    ),
  },
  {
    title: '置信度',
    dataIndex: 'confidence',
    key: 'confidence',
    width: 90,
    render: (v: number) => <span className="text-sm tabular-nums">{v.toFixed(2)}</span>,
  },
]

export function EdgeTable({ edges, loading }: { edges: RelationEdge[]; loading: boolean }) {
  return (
    <div className="rounded-md border">
      <Table
        columns={edgeColumns}
        dataSource={edges}
        rowKey="id"
        loading={loading}
        pagination={false}
        locale={{
          emptyText: (
            <EmptyState
              icon={Network}
              title="还没有关系边"
              description="导入资产后点右上角「重建图谱」；同 IP/父子域/同图标/同技术栈会生成聚类。"
              className="border-0"
            />
          ),
        }}
      />
    </div>
  )
}

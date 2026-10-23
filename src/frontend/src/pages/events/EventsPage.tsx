import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { Button, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { assetEventApi, eventTypeLabel, eventTypeVariant, type AssetEvent } from '@/api/relations'
import { formatDate } from '@/lib/utils'

const eventFilter = [
  { value: '', label: '全部' },
  { value: 'first_seen', label: '首次发现' },
  { value: 'attribute_change', label: '属性变化' },
  { value: 'reappear', label: '重新出现' },
]

// shadcn Badge variant → Tag 的类名配色（Tag 无 variant，用 Tailwind 类保留原色）
const variantClass: Record<string, string> = {
  default: 'border-transparent bg-primary/15 text-primary',
  secondary: 'border-transparent bg-muted text-muted-foreground',
  destructive: 'border-transparent bg-red-500/15 text-red-500',
  outline: '',
}

export default function EventsPage() {
  const [type, setType] = useState('')
  const limit = type ? 200 : 100
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['asset-events', limit],
    queryFn: () => assetEventApi.list(limit),
  })

  const items = (data?.data?.items ?? []).filter((e) => type === '' || e.event_type === type)

  const diff = (before: Record<string, unknown>, after: Record<string, unknown>) => {
    const keys = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])
    const rows: { key: string; from: string; to: string }[] = []
    keys.forEach((key) => {
      const b = before?.[key]
      const a = after?.[key]
      if (JSON.stringify(b) === JSON.stringify(a)) return
      rows.push({
        key,
        from: formatValue(b),
        to: formatValue(a),
      })
    })
    return rows
  }

  // /events 只有 limit 参数、无服务端排序，时间列走客户端排序
  const columns: TableProps<AssetEvent>['columns'] = [
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (v: string) => <span className="text-xs text-muted-foreground">{formatDate(v)}</span>,
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: '类型',
      dataIndex: 'event_type',
      key: 'event_type',
      width: 120,
      render: (v: string) => (
        <Tag className={variantClass[eventTypeVariant(v)]}>{eventTypeLabel[v] ?? v}</Tag>
      ),
    },
    {
      title: '站点',
      dataIndex: 'site_id',
      key: 'site_id',
      width: 90,
      render: (v: number) => <span className="font-mono text-sm">#{v}</span>,
    },
    {
      title: '说明',
      dataIndex: 'title',
      key: 'title',
      render: (v: string) => <span className="text-sm">{v}</span>,
    },
    {
      title: '变化',
      key: 'diff',
      render: (_, e) => {
        const rows = e.event_type === 'attribute_change' ? diff(e.before ?? {}, e.after ?? {}) : []
        if (rows.length === 0) {
          return <span className="text-xs text-muted-foreground">—</span>
        }
        return (
          <div className="space-y-0.5 text-xs text-muted-foreground">
            {rows.slice(0, 3).map((r) => (
              <div key={r.key}>
                <span className="font-medium">{r.key}</span> {r.from} → {r.to}
              </div>
            ))}
            {rows.length > 3 && <div>…共 {rows.length} 项</div>}
          </div>
        )
      },
    },
  ]

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">变更时间线</h1>
          <p className="text-sm text-muted-foreground">
            站点首次发现、属性变化、失联后重现；保留最近 1 万条 / 7 天（策略随资产治理配置）
          </p>
        </div>
        <Button onClick={() => refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {eventFilter.map((f) => (
          <button
            key={f.value}
            className={
              'rounded-full border px-3 py-1 text-sm ' +
              (type === f.value
                ? 'border-primary bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-muted')
            }
            onClick={() => setType(f.value)}
          >
            {f.label}
          </button>
        ))}
        <span className="ml-auto text-sm text-muted-foreground">{items.length} 条</span>
      </div>

      <div className="overflow-hidden rounded-md border">
        <Table<AssetEvent>
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={isLoading}
          pagination={false}
          locale={{
            emptyText: (
              <div className="py-8 text-center text-sm text-muted-foreground">
                没有事件（导入资产或探测站点后会产生 first_seen / attribute_change）
              </div>
            ),
          }}
        />
      </div>
    </div>
  )
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '空'
  if (Array.isArray(v)) return v.length === 0 ? '空' : v.join(', ')
  return String(v)
}

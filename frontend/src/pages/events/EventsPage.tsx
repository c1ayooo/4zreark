import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { Button, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { assetEventApi, eventTypeLabel, eventTypeVariant, type AssetEvent } from '@/api/relations'
import RecordDetailDrawer from '@/components/common/RecordDetailDrawer'
import { formatDate, siteHostLabel } from '@/lib/utils'

const eventFilter = [
  { value: '', label: '全部' },
  { value: 'first_seen', label: '首次发现' },
  { value: 'attribute_change', label: '属性变化' },
  { value: 'fingerprint_change', label: '指纹变化' },
  { value: 'content_change', label: '内容变化' },
  { value: 'reappear', label: '重新出现' },
  { value: 'takeover', label: '接管风险' },
  { value: 'archived', label: '已归档' },
]

// shadcn Badge variant → Tag 的类名配色（Tag 无 variant，用 Tailwind 类保留原色）
const variantClass: Record<string, string> = {
  default: 'border-transparent bg-primary/15 text-primary',
  secondary: 'border-transparent bg-muted text-muted-foreground',
  destructive: 'border-transparent bg-red-500/15 text-red-500',
  outline: '',
}

export default function EventsPage() {
  // 仪表盘下钻入口：/events?type=content_change 直接落到对应过滤视图
  const [searchParams, setSearchParams] = useSearchParams()
  const [type, setType] = useState(() => searchParams.get('type') ?? '')
  // 行点击打开的详情抽屉：受控存当前事件，before/after 全文在抽屉里看不截断
  const [detailEvent, setDetailEvent] = useState<AssetEvent | null>(null)
  const limit = 200
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['asset-events-changes', type, limit],
    queryFn: () => assetEventApi.changes({ event_type: type || undefined, limit }),
  })

  const changeType = (next: string) => {
    setType(next)
    setSearchParams(next ? { type: next } : {}, { replace: true })
  }

  const items = data?.data?.items ?? []

  const diff = (before: Record<string, unknown>, after: Record<string, unknown>) => {
    const keys = new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])
    const rows: { key: string; from: string; to: string }[] = []
    keys.forEach((key) => {
      const b = before?.[key]
      const a = after?.[key]
      if (JSON.stringify(b) === JSON.stringify(a)) return
      rows.push({
        key: diffKeyLabel[key] ?? key,
        from: formatValue(b),
        to: formatValue(a),
      })
    })
    return rows
  }

  // /events 只有 limit 参数、无服务端排序，时间列走客户端排序
  // 行点击看详情：写法同 DiscoveryCandidatesPanel 的 onRow
  const onRow: TableProps<AssetEvent>['onRow'] = (e) => ({
    className: 'cursor-pointer',
    onClick: () => setDetailEvent(e),
  })

  const detailFields = detailEvent
    ? [
        { label: '时间', value: formatDate(detailEvent.created_at) },
        {
          label: '类型',
          value: eventTypeLabel[detailEvent.event_type] ?? detailEvent.event_type,
        },
        { label: '项目', value: detailEvent.project_name || '' },
        { label: '站点', value: detailEvent.asset_value || '' },
        { label: '说明', value: detailEvent.title },
      ]
    : []

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
      title: '项目',
      dataIndex: 'project_name',
      key: 'project_name',
      width: 140,
      ellipsis: true,
      render: (v: string) => <span className="text-sm text-muted-foreground">{v || '—'}</span>,
    },
    {
      title: '域名',
      dataIndex: 'asset_value',
      key: 'asset_value',
      width: 220,
      ellipsis: true,
      render: (v: string) => <span className="font-mono text-sm">{siteHostLabel(undefined, v)}</span>,
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
        // 所有事件类型都可能带 before/after（属性/指纹/内容变化、重现、接管等），
        // 有差异就展示，不再只认 attribute_change——此前其它类型一律显示「—」。
        const rows = diff(e.before ?? {}, e.after ?? {})
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
            首次发现、属性/指纹/内容变化、失联重现、接管与归档；保留最近 1 万条 / 7 天（策略随资产治理配置）
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
            onClick={() => changeType(f.value)}
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
          onRow={onRow}
          pagination={{ pageSize: 50, hideOnSinglePage: true }}
          locale={{
            emptyText: (
              <div className="py-8 text-center text-sm text-muted-foreground">
                没有事件（导入资产或探测站点后会产生 first_seen / attribute_change）
              </div>
            ),
          }}
        />
      </div>

      <RecordDetailDrawer
        open={detailEvent !== null}
        onClose={() => setDetailEvent(null)}
        title="变更事件详情"
        fields={detailFields}
        raw={detailEvent ? { before: detailEvent.before, after: detailEvent.after } : undefined}
      />
    </div>
  )
}

// before/after 字段名 → 中文标签（各事件写入方的常见键；未登记的回落原键名）。
const diffKeyLabel: Record<string, string> = {
  title: '标题',
  http_status: '状态码',
  ip: 'IP',
  technology: '技术栈',
  technologies: '技术栈',
  icon_sha256: '图标指纹',
  state: '状态',
  text_hash: '内容指纹',
  url: 'URL',
  domain: '域名',
  cname: 'CNAME',
  provider: '服务',
  reason: '原因',
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '空'
  if (Array.isArray(v)) return v.length === 0 ? '空' : v.join(', ')
  return String(v)
}

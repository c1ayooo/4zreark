import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { RefreshCw } from 'lucide-react'

import { assetEventApi, eventTypeLabel, eventTypeVariant } from '@/api/relations'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate } from '@/lib/utils'

const eventFilter = [
  { value: '', label: '全部' },
  { value: 'first_seen', label: '首次发现' },
  { value: 'attribute_change', label: '属性变化' },
  { value: 'reappear', label: '重新出现' },
]

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

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">变更时间线</h1>
          <p className="text-sm text-muted-foreground">
            站点首次发现、属性变化、失联后重现；保留最近 1 万条 / 7 天（策略随资产治理配置）
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()}>
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

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[150px]">时间</TableHead>
              <TableHead className="w-[120px]">类型</TableHead>
              <TableHead className="w-[90px]">站点</TableHead>
              <TableHead>说明</TableHead>
              <TableHead>变化</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  没有事件（导入资产或探测站点后会产生 first_seen / attribute_change）
                </TableCell>
              </TableRow>
            )}
            {items.map((e) => {
              const rows = e.event_type === 'attribute_change' ? diff(e.before ?? {}, e.after ?? {}) : []
              return (
                <TableRow key={e.id}>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatDate(e.created_at)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={eventTypeVariant(e.event_type)}>
                      {eventTypeLabel[e.event_type] ?? e.event_type}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm font-mono">#{e.site_id}</TableCell>
                  <TableCell className="text-sm">{e.title}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {rows.length === 0 ? (
                      <span className="text-muted-foreground">—</span>
                    ) : (
                      <div className="space-y-0.5">
                        {rows.slice(0, 3).map((r) => (
                          <div key={r.key}>
                            <span className="font-medium">{r.key}</span> {r.from} → {r.to}
                          </div>
                        ))}
                        {rows.length > 3 && <div>…共 {rows.length} 项</div>}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

function formatValue(v: unknown): string {
  if (v === null || v === undefined || v === '') return '空'
  if (Array.isArray(v)) return v.length === 0 ? '空' : v.join(', ')
  return String(v)
}

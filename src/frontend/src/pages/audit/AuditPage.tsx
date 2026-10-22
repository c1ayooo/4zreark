import { useState } from 'react'
import {keepPreviousData, useQuery} from '@tanstack/react-query'
import { RefreshCw, ScrollText } from 'lucide-react'

import { auditApi, type OperationLog } from '@/api/audit'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { formatDate } from '@/lib/utils'

const pageSize = 50

export default function AuditPage() {
  const [username, setUsername] = useState('')
  const [action, setAction] = useState('')
  const [module, setModule] = useState('')
  const [status, setStatus] = useState<'all' | '1' | '0'>('all')
  const [applied, setApplied] = useState<{
    username: string
    action: string
    module: string
    status: 'all' | '1' | '0'
  }>({ username: '', action: '', module: '', status: 'all' })
  const [page, setPage] = useState(1)

  const list = useQuery({
    queryKey: ['audit', applied, page],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      auditApi.list({
        username: applied.username || undefined,
        action: applied.action || undefined,
        module: applied.module || undefined,
        status: applied.status === 'all' ? undefined : applied.status,
        page,
        page_size: pageSize,
      }),
  })

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))

  const apply = () => {
    setApplied({ username, action, module, status })
    setPage(1)
  }

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">审计日志</h1>
          <p className="text-sm text-muted-foreground">
            所有写操作的留痕（项目/资产删除、数据源、用户管理、强制复验等），只读
          </p>
        </div>
        <Button variant="outline" onClick={() => list.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">用户</span>
          <Input
            className="w-[160px]"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="用户名"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">动作</span>
          <Input
            className="w-[160px]"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="如 delete / update"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">模块</span>
          <Input
            className="w-[160px]"
            value={module}
            onChange={(e) => setModule(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && apply()}
            placeholder="如 assets / users"
          />
        </div>
        <div className="space-y-1">
          <span className="text-xs text-muted-foreground">结果</span>
          <Select value={status} onValueChange={(v) => setStatus(v as typeof status)}>
            <SelectTrigger className="w-[110px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">全部</SelectItem>
              <SelectItem value="1">成功</SelectItem>
              <SelectItem value="0">失败</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button onClick={apply}>查询</Button>
        <span className="ml-auto text-sm text-muted-foreground">共 {total.toLocaleString()} 条</span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[160px]">时间</TableHead>
              <TableHead className="w-[120px]">用户</TableHead>
              <TableHead className="w-[110px]">动作</TableHead>
              <TableHead className="w-[110px]">模块</TableHead>
              <TableHead>目标 / 详情</TableHead>
              <TableHead className="w-[130px]">IP</TableHead>
              <TableHead className="w-[80px]">结果</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isLoading && (
              <TableRow>
                <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!list.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="py-10 text-center text-muted-foreground">
                  <ScrollText className="mx-auto mb-2 h-6 w-6 opacity-40" />
                  没有匹配的审计日志
                </TableCell>
              </TableRow>
            )}
            {items.map((l: OperationLog) => (
              <TableRow key={l.id}>
                <TableCell className="text-xs text-muted-foreground">{formatDate(l.created_at)}</TableCell>
                <TableCell className="text-sm">{l.username || '—'}</TableCell>
                <TableCell className="font-mono text-xs">{l.action || '—'}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{l.module || '—'}</TableCell>
                <TableCell className="max-w-[360px] text-sm">
                  <div className="truncate font-mono text-xs">{l.target || '—'}</div>
                  {l.detail && <div className="truncate text-xs text-muted-foreground">{l.detail}</div>}
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{l.ip || '—'}</TableCell>
                <TableCell>
                  <Badge variant={l.status === 1 ? 'secondary' : 'destructive'}>
                    {l.status === 1 ? '成功' : '失败'}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {pages > 1 && (
        <div className="flex items-center justify-end gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            上一页
          </Button>
          <span className="text-sm text-muted-foreground">{page} / {pages}</span>
          <Button variant="outline" size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>
            下一页
          </Button>
        </div>
      )}
    </div>
  )
}

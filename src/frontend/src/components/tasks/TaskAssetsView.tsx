import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Check, Copy, Download, ExternalLink, Radar, RefreshCw, Rocket, Search, X } from 'lucide-react'

import { taskAssetApi, type TaskAsset } from '@/api/tasks'
import EmptyState from '@/components/common/EmptyState'
import CreateTaskFromAssetsDialog from '@/components/tasks/CreateTaskFromAssetsDialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { useToast } from '@/components/ui/use-toast'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

interface TaskAssetsViewProps {
  taskId: string
  /** 任务状态决定空态文案：没开始跑 / 正在跑 / 跑完了但没资产，三种提示完全不同 */
  taskStatus?: string
  /** 结果统计，用来告诉用户「原始结果已经有 N 条，资产还在归并」 */
  stats?: Record<string, number>
  /** 点击「查看原始结果」时切到对应结果页签 */
  onOpenTab?: (tab: string) => void
  /** 任务所属项目，新建任务默认落这个项目 */
  projectId?: number | string
}

const PAGE_SIZE = 20
const FETCH_ALL_PAGE_SIZE = 200

// TaskAssetsView 是任务详情里的「本次任务资产」视图：
// 数据按 raw_records.task_id 精确口径 + scan_results 主机对齐兜底口径取归并站点，
// 与项目级资产页同一批数据。带行选择与批量导出，供人工挑资产。
export default function TaskAssetsView({ taskId, taskStatus, stats, onOpenTab, projectId }: TaskAssetsViewProps) {
  const { toast } = useToast()
  const [page, setPage] = useState(1)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [busy, setBusy] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['task-assets', taskId, page, search],
    queryFn: () => taskAssetApi.list(taskId, { page, pageSize: PAGE_SIZE, q: search }),
    enabled: !!taskId,
  })

  const items = data?.data?.list || []
  const total = data?.data?.total || 0
  const maxPage = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const pageIds = useMemo(() => items.map((i) => i.id), [items])
  const allOnPage = pageIds.length > 0 && pageIds.every((id) => selected.has(id))
  const someOnPage = pageIds.some((id) => selected.has(id)) && !allOnPage

  const toggleRow = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const togglePage = () => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (allOnPage) pageIds.forEach((id) => next.delete(id))
      else pageIds.forEach((id) => next.add(id))
      return next
    })
  }

  // 全选当前过滤条件下的全部资产：按 200/页 翻页拉完 id。
  const selectAllMatching = async () => {
    setBusy(true)
    try {
      const ids: number[] = []
      let p = 1
      for (;;) {
        const res = await taskAssetApi.list(taskId, { page: p, pageSize: FETCH_ALL_PAGE_SIZE, q: search })
        const list = res.data?.list || []
        ids.push(...list.map((i) => i.id))
        if (list.length < FETCH_ALL_PAGE_SIZE) break
        p += 1
        if (p > 50) break
      }
      setSelected(new Set(ids))
      toast({ title: `已选中 ${ids.length} 个资产` })
    } catch (err) {
      toast({ title: '全选失败', description: String(err), variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  const pickRows = (list: TaskAsset[]) => {
    const picked = list.filter((i) => selected.has(i.id))
    return picked.length ? picked : list
  }

  const copyHosts = async () => {
    const rows = pickRows(items)
    if (rows.length === 0) return
    try {
      await navigator.clipboard.writeText(rows.map((i) => i.host).join('\n'))
      toast({ title: `已复制 ${rows.length} 个 host` })
    } catch {
      toast({ title: '复制失败，浏览器未授予剪贴板权限', variant: 'destructive' })
    }
  }

  const exportCSV = () => {
    const rows = pickRows(items)
    if (rows.length === 0) return
    const header = ['host', 'protocol', 'port', 'http_status', 'title', 'technology_stack', 'endpoints', 'task_hits', 'last_seen']
    const body = rows.map((i) =>
      [
        i.host,
        i.protocol,
        i.port,
        i.http_status,
        `"${(i.title || '').replace(/"/g, '""')}"`,
        `"${(i.technology_stack || []).join(';')}"`,
        i.endpoints,
        i.task_hits,
        i.last_seen,
      ].join(',')
    )
    const csv = '\ufeff' + [header.join(','), ...body].join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `task-assets-${taskId.slice(0, 8)}.csv`
    a.click()
    URL.revokeObjectURL(url)
    toast({ title: `已导出 ${rows.length} 条` })
  }

  // 空态分三种：未开始 / 进行中（有原始结果但还没归并）/ 已结束但没有资产。
  const rawResultCount = Object.values(stats || {}).reduce((a, b) => a + b, 0)
  const firstResultTab = Object.entries(stats || {}).find(([, v]) => v > 0)?.[0]
  const isPending = taskStatus === 'pending' || taskStatus === 'queued' || taskStatus === 'created'
  const isRunning = taskStatus === 'running' || taskStatus === 'paused'
  const isDone = ['completed', 'failed', 'cancelled'].includes(taskStatus || '')

  const emptyState = isPending ? (
    <EmptyState
      icon={Radar}
      title="任务还没开始跑"
      description="资产是任务结果的归并产物，任务开始执行后才会出现。"
      hints={[
        '任务派单给节点后，子域/端口/URL 结果会先落原始结果',
        '原始结果经入口探测与指纹识别后，才归并成站点资产',
        '项目刚建、第一个任务刚创建时这里为空是正常的',
      ]}
    />
  ) : isRunning ? (
    <EmptyState
      icon={Radar}
      title="正在采集，资产还在归并"
      description={
        rawResultCount > 0
          ? `本次任务已有 ${rawResultCount} 条原始结果，归并成站点后会出现在这里（通常 1–3 分钟）。`
          : '任务已开始，还没有原始结果落库。刚派单或目标响应慢时会出现这种情况。'
      }
      hints={[
        '资产按 host 归并，同一 host 的多协议与端口算一个站点',
        '子域结果要经过入口探测才会升级为站点，只做被动枚举时归并会慢一些',
        '可以点下面的按钮先看原始结果，确认采集确实在推进',
      ]}
      actions={
        firstResultTab && onOpenTab ? (
          <Button variant="outline" size="sm" onClick={() => onOpenTab(firstResultTab)}>
            查看原始结果（{rawResultCount} 条）
          </Button>
        ) : undefined
      }
    />
  ) : isDone ? (
    <EmptyState
      icon={Radar}
      title="任务已结束，没有归并出资产"
      description="任务正常跑完但资产表为空，通常是目标侧或配置侧的原因，不是数据丢了。"
      hints={[
        '目标全部无响应：域名解析失败或端口不通，不会产生站点资产',
        '扫描类型不含端口/指纹：只做了被动子域枚举，缺少入口探测就不会归并',
        '结果已被项目内其它任务归并：相同 host 会合并成一个站点，本任务证据仍记录在结果里',
      ]}
      actions={
        firstResultTab && onOpenTab ? (
          <Button variant="outline" size="sm" onClick={() => onOpenTab(firstResultTab)}>
            查看原始结果（{rawResultCount} 条）
          </Button>
        ) : undefined
      }
    />
  ) : (
    <EmptyState
      icon={Radar}
      title="该任务还没有归并资产"
      description="资产由任务结果归并而来：子域/端口/URL 结果经入口探测与指纹识别后成为站点。"
      hints={['先确认任务状态与原始结果条数', '若结果为空，检查目标连通性与任务的扫描类型']}
    />
  )

  return (
    <div className="flex h-full flex-col gap-3 p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm">
          本次任务贡献的资产，共 <span className="text-foreground font-medium">{total}</span> 个站点。
          资产按 host 归并，同一 host 的多协议/端口算一个站点。
        </p>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="text-muted-foreground absolute top-1/2 left-2 h-4 w-4 -translate-y-1/2" />
            <Input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  setPage(1)
                  setSearch(searchInput.trim())
                }
              }}
              placeholder="按 host 过滤"
              className="h-8 w-56 pl-8"
            />
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setPage(1)
              setSearch(searchInput.trim())
            }}
          >
            查询
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={isFetching ? 'mr-1 h-4 w-4 animate-spin' : 'mr-1 h-4 w-4'} />
            刷新
          </Button>
        </div>
      </div>

      {/* 选择工具条：选中数常驻可见，未选中也能一键全选 */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-3 py-2 text-sm">
        <span className="text-muted-foreground">
          已选 <span className="text-foreground font-medium">{selected.size}</span> / {total}
        </span>
        <Button variant="outline" size="sm" onClick={togglePage} disabled={pageIds.length === 0}>
          {allOnPage ? '取消本页' : '选中本页'}
        </Button>
        <Button variant="outline" size="sm" onClick={selectAllMatching} disabled={busy || total === 0}>
          {busy ? '全选中…' : `全选全部 ${total}`}
        </Button>
        <Button variant="outline" size="sm" onClick={() => setSelected(new Set())} disabled={selected.size === 0}>
          <X className="mr-1 h-4 w-4" />
          清空选择
        </Button>
        <div className="grow" />
        <Button variant="outline" size="sm" onClick={copyHosts} disabled={items.length === 0}>
          <Copy className="mr-1 h-4 w-4" />
          复制 host
        </Button>
        <Button variant="outline" size="sm" onClick={exportCSV} disabled={items.length === 0}>
          <Download className="mr-1 h-4 w-4" />
          导出 CSV
        </Button>
        <Button size="sm" onClick={() => setCreateOpen(true)} disabled={selected.size === 0}>
          <Rocket className="mr-1 h-4 w-4" />
          用选中资产创建任务{selected.size > 0 ? `（${selected.size}）` : ''}
        </Button>
      </div>

      <div className="bg-background flex-1 overflow-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-10">
                <Checkbox
                  checked={allOnPage ? true : someOnPage ? 'indeterminate' : false}
                  onCheckedChange={togglePage}
                  aria-label="选中本页"
                />
              </TableHead>
              <TableHead>站点</TableHead>
              <TableHead className="w-24">协议/端口</TableHead>
              <TableHead className="w-20">状态码</TableHead>
              <TableHead>标题</TableHead>
              <TableHead className="w-64">技术栈</TableHead>
              <TableHead className="w-20">入口数</TableHead>
              <TableHead className="w-24">本任务证据</TableHead>
              <TableHead className="w-40">最近发现</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-muted-foreground py-10 text-center">
                  加载中…
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="p-0">
                  {emptyState}
                </TableCell>
              </TableRow>
            ) : (
              items.map((item) => (
                <TableRow
                  key={item.id}
                  data-state={selected.has(item.id) ? 'selected' : undefined}
                  className="cursor-pointer"
                  onClick={() => toggleRow(item.id)}
                >
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <Checkbox
                      checked={selected.has(item.id)}
                      onCheckedChange={() => toggleRow(item.id)}
                      aria-label={`选择 ${item.host}`}
                    />
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    <a
                      href={`${item.protocol}://${item.host}${item.port && item.port !== 80 && item.port !== 443 ? `:${item.port}` : ''}`}
                      target="_blank"
                      rel="noreferrer"
                      className="text-primary inline-flex items-center gap-1 hover:underline"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {item.host}
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  </TableCell>
                  <TableCell className="text-xs">
                    {item.protocol}/{item.port}
                  </TableCell>
                  <TableCell className="text-xs">{item.http_status || '-'}</TableCell>
                  <TableCell className="max-w-[280px] truncate text-xs" title={item.title}>
                    {item.title || '-'}
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {(item.technology_stack || []).slice(0, 4).map((t) => (
                        <Badge key={t} variant="secondary" className="text-[10px]">
                          {t}
                        </Badge>
                      ))}
                      {(item.technology_stack || []).length === 0 && (
                        <span className="text-muted-foreground text-xs">-</span>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{item.endpoints}</TableCell>
                  <TableCell className="text-xs">{item.task_hits}</TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {item.last_seen ? new Date(item.last_seen).toLocaleString() : '-'}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between text-sm">
        <span className="text-muted-foreground">
          第 {page} / {maxPage} 页，共 {total} 条
          {selected.size > 0 && (
            <span className="text-foreground ml-2 inline-flex items-center gap-1">
              <Check className="h-3 w-3" />已选 {selected.size}
            </span>
          )}
        </span>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
            上一页
          </Button>
          <Button variant="outline" size="sm" disabled={page >= maxPage} onClick={() => setPage((p) => p + 1)}>
            下一页
          </Button>
        </div>
      </div>

      <CreateTaskFromAssetsDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        hosts={items.filter((i) => selected.has(i.id)).map((i) => i.host)}
        projectId={projectId}
      />
    </div>
  )
}

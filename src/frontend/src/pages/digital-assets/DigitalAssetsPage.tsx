import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, Trash2, Undo2 } from 'lucide-react'

import { projectApi } from '@/api/projects'
import {
  digitalApi,
  digitalKindLabel,
  digitalKinds,
  type DigitalPreview,
} from '@/api/digital'
import { Badge } from '@/components/ui/badge'
import { useConfirm } from '@/components/common/confirm-provider'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const PAGE_SIZE = 50

export default function DigitalAssetsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [projectId, setProjectId] = useState('0')
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)

  const [importOpen, setImportOpen] = useState(false)
  const [importKind, setImportKind] = useState('app')
  const [importText, setImportText] = useState('')
  const [company, setCompany] = useState('')
  const [platform, setPlatform] = useState('')
  const [preview, setPreview] = useState<DigitalPreview | null>(null)

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const list = useQuery({
    queryKey: ['digital-assets', projectId, kind, q, page],
    queryFn: () =>
      digitalApi.list({
        project_id: Number(projectId) || undefined,
        kind: kind || undefined,
        q: q || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  })
  const batches = useQuery({
    queryKey: ['digital-imports', projectId],
    queryFn: () => digitalApi.batches(Number(projectId) || undefined, 20),
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['digital-assets'] })
    queryClient.invalidateQueries({ queryKey: ['digital-imports'] })
  }

  const previewMutation = useMutation({
    mutationFn: () =>
      digitalApi.preview({
        project_id: Number(projectId),
        kind: importKind,
        text: importText,
        company: company || undefined,
        platform: platform || undefined,
        source: 'manual',
      }),
    onSuccess: (res) => setPreview(res.data),
    onError: (e: any) =>
      toast({ title: '预览失败', description: e?.message, variant: 'destructive' }),
  })

  const commit = useMutation({
    mutationFn: () => digitalApi.commit(preview!.token),
    onSuccess: (res) => {
      toast({
        title: '名单已导入',
        description: `回执 #${res.data?.batch?.id} · 新增 ${res.data?.inserted ?? 0} 条`,
      })
      invalidate()
      closeImport()
    },
    onError: (e: any) =>
      toast({ title: '导入失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: number) => digitalApi.remove(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const undo = useMutation({
    mutationFn: (batchId: number) => digitalApi.undo(batchId),
    onSuccess: (res) => {
      toast({ title: '已撤销', description: `回滚 ${res.data?.deleted ?? 0} 条新增名单` })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '撤销失败', description: e?.message, variant: 'destructive' }),
  })

  const closeImport = () => {
    if (preview) digitalApi.cancel(preview.token, 'digital').catch(() => {})
    setImportOpen(false)
    setPreview(null)
    setImportText('')
    setCompany('')
    setPlatform('')
  }

  const projectName = (id: number) =>
    projects.data?.data?.find((p) => p.id === id)?.name ?? `#${id}`

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const receipts = useMemo(() => batches.data?.data?.items ?? [], [batches.data])
  const canImport = Number(projectId) > 0

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">数字资产</h1>
          <p className="text-sm text-muted-foreground">
            APP / 小程序 / 公众号 / 新媒体名单；与站点库解耦，录入不创建站点、不触发 DNS 与验证
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select
            value={projectId}
            onValueChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="全部项目" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">全部项目</SelectItem>
              {(projects.data?.data ?? []).map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button
            onClick={() => setImportOpen(true)}
            disabled={!canImport}
            title={canImport ? undefined : '先选择一个归属项目'}
          >
            <Plus className="mr-2 h-4 w-4" /> 导入名单
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          className={
            'rounded-full border px-3 py-1 text-sm ' +
            (kind === ''
              ? 'border-primary bg-primary/10 text-primary'
              : 'text-muted-foreground hover:bg-muted')
          }
          onClick={() => {
            setKind('')
            setPage(1)
          }}
        >
          全部
        </button>
        {digitalKinds.map((k) => (
          <button
            key={k.value}
            className={
              'rounded-full border px-3 py-1 text-sm ' +
              (kind === k.value
                ? 'border-primary bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-muted')
            }
            onClick={() => {
              setKind(k.value)
              setPage(1)
            }}
          >
            {k.label}
          </button>
        ))}
        <Input
          className="ml-auto w-56"
          placeholder="搜索名称 / 公司 / 平台"
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPage(1)
          }}
        />
        <span className="text-sm text-muted-foreground">{total} 条</span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead className="w-[100px]">类型</TableHead>
              <TableHead className="w-[160px]">公司</TableHead>
              <TableHead className="w-[120px]">平台</TableHead>
              <TableHead className="w-[90px]">来源</TableHead>
              <TableHead className="w-[80px]">状态</TableHead>
              <TableHead className="w-[150px]">入库时间</TableHead>
              <TableHead className="w-[70px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isLoading && (
              <TableRow>
                <TableCell colSpan={8} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!list.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={8} className="py-8 text-center text-muted-foreground">
                  还没有名单（选择项目后点「导入名单」）
                </TableCell>
              </TableRow>
            )}
            {items.map((a) => (
              <TableRow key={a.id}>
                <TableCell className="text-sm font-medium">{a.name}</TableCell>
                <TableCell>
                  <Badge variant="outline">{digitalKindLabel[a.kind] ?? a.kind}</Badge>
                </TableCell>
                <TableCell className="text-sm">{a.company || '—'}</TableCell>
                <TableCell className="text-sm">{a.platform || '—'}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{a.source || '—'}</TableCell>
                <TableCell>
                  <Badge variant={a.status === 'unverified' ? 'outline' : 'secondary'}>
                    {a.status === 'unverified' ? '待核对' : a.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(a.created_at)}
                </TableCell>
                <TableCell>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={async () => {
                      if (await confirm(`删除「${a.name}」？`)) remove.mutate(a.id)
                    }}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-end gap-2 text-sm">
        <Button
          variant="outline"
          size="sm"
          disabled={page <= 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
        >
          上一页
        </Button>
        <span className="text-muted-foreground">
          第 {page} / {totalPages} 页
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => setPage((p) => p + 1)}
        >
          下一页
        </Button>
      </div>

      <div className="rounded-md border">
        <div className="border-b px-4 py-2 text-sm font-medium">最近导入回执</div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[70px]">回执</TableHead>
              <TableHead className="w-[130px]">项目</TableHead>
              <TableHead className="w-[90px]">类型</TableHead>
              <TableHead className="w-[90px]">状态</TableHead>
              <TableHead>摘要</TableHead>
              <TableHead className="w-[150px]">时间</TableHead>
              <TableHead className="w-[90px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {receipts.length === 0 && (
              <TableRow>
                <TableCell colSpan={7} className="py-6 text-center text-muted-foreground">
                  还没有导入回执
                </TableCell>
              </TableRow>
            )}
            {receipts.map((b) => (
              <TableRow key={b.id}>
                <TableCell className="font-mono text-sm">#{b.id}</TableCell>
                <TableCell className="text-sm">{projectName(b.project_id)}</TableCell>
                <TableCell className="text-xs">
                  {b.kind === 'local_doc' ? '本地文档' : '名单'}
                </TableCell>
                <TableCell>
                  <Badge variant={b.status === 'committed' ? 'secondary' : 'outline'}>
                    {b.status === 'committed' ? '已提交' : b.status === 'undone' ? '已撤销' : b.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {Object.entries(b.summary ?? {})
                    .map(([k, v]) => `${k}: ${String(v)}`)
                    .join(' · ')}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(b.created_at)}
                </TableCell>
                <TableCell>
                  {b.status === 'committed' && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={async () => {
                        if (await confirm(`撤销回执 #${b.id} 新增的名单？`)) undo.mutate(b.id)
                      }}
                    >
                      <Undo2 className="mr-1 h-3.5 w-3.5" /> 撤销
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={importOpen} onOpenChange={(o) => (o ? setImportOpen(true) : closeImport())}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>导入数字资产名单</DialogTitle>
            <DialogDescription>
              每行一个名称，也支持逗号分隔；先预览去重与库内对账，确认后才写库（15 分钟内有效）
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1">
                <Label>类型</Label>
                <Select value={importKind} onValueChange={setImportKind}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {digitalKinds.map((k) => (
                      <SelectItem key={k.value} value={k.value}>
                        {k.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>公司（可选）</Label>
                <Input value={company} onChange={(e) => setCompany(e.target.value)} />
              </div>
              <div className="space-y-1">
                <Label>平台（可选）</Label>
                <Input value={platform} onChange={(e) => setPlatform(e.target.value)} />
              </div>
            </div>

            <div className="space-y-1">
              <Label>名单</Label>
              <Textarea
                className="h-40 w-full rounded-md border bg-background p-3 font-mono text-sm"
                placeholder={'示例应用\n另一个应用'}
                value={importText}
                onChange={(e) => {
                  setImportText(e.target.value)
                  setPreview(null)
                }}
              />
            </div>

            {preview && (
              <div className="space-y-2 rounded-md border bg-muted/30 p-3 text-sm">
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">总计 {preview.total}</Badge>
                  <Badge variant="secondary">可导入 {preview.unique}</Badge>
                  <Badge variant="outline">批内重复 {preview.duplicates}</Badge>
                  <Badge variant="outline">库内已有 {preview.existing}</Badge>
                  <Badge variant="outline">无效 {preview.invalid}</Badge>
                </div>
                <div className="text-xs text-muted-foreground">
                  示例：{preview.sample.map((s) => s.name).join('、') || '—'}
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={closeImport}>
              取消
            </Button>
            {!preview ? (
              <Button
                onClick={() => previewMutation.mutate()}
                disabled={previewMutation.isPending || !importText.trim()}
              >
                {previewMutation.isPending ? '预览中…' : '预览'}
              </Button>
            ) : (
              <Button onClick={() => commit.mutate()} disabled={commit.isPending}>
                {commit.isPending ? '导入中…' : `确认导入 ${preview.unique} 条`}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

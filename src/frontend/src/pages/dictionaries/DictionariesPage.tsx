import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Eye, Paperclip, Plus, RefreshCw, Trash2, Upload } from 'lucide-react'

import {
  dictionaryApi,
  dictionaryTypes,
  type Dictionary,
  type DictionaryPreview,
} from '@/api/sources'
import { Badge } from '@/components/ui/badge'
import { useConfirm } from '@/components/common/confirm-provider'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const pageSize = 20

export default function DictionariesPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [type, setType] = useState('')
  const [page, setPage] = useState(1)

  const [importOpen, setImportOpen] = useState(false)
  const [name, setName] = useState('')
  const [dictType, setDictType] = useState('subdomain')
  const [text, setText] = useState('')
  const [format, setFormat] = useState('text')
  const [xlsxFile, setXlsxFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<DictionaryPreview | null>(null)

  const [entriesOf, setEntriesOf] = useState<Dictionary | null>(null)
  const [entryPage, setEntryPage] = useState(1)

  const list = useQuery({
    queryKey: ['dictionaries', type, page],
    queryFn: () => dictionaryApi.list({ type: type || undefined, page, page_size: pageSize }),
  })

  const previewMutation = useMutation({
    mutationFn: async () => {
      if (format === 'xlsx') {
        if (!xlsxFile) throw new Error('请选择 .xlsx 文件')
        const buf = await xlsxFile.arrayBuffer()
        const bytes = new Uint8Array(buf)
        let binary = ''
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
        return dictionaryApi.preview({
          name,
          type: dictType,
          format: 'xlsx',
          content_base64: btoa(binary),
        })
      }
      return dictionaryApi.preview({ name, type: dictType, text, format })
    },
    onSuccess: (res) => setPreview(res.data),
    onError: (e: any) => toast({ title: '预览失败', description: e?.message, variant: 'destructive' }),
  })

  const importMutation = useMutation({
    mutationFn: (token: string) => dictionaryApi.import(token),
    onSuccess: (res) => {
      toast({ title: `字典已导入（${res.data.entries} 条）` })
      setImportOpen(false)
      setPreview(null)
      setName('')
      setText('')
      queryClient.invalidateQueries({ queryKey: ['dictionaries'] })
    },
    onError: (e: any) => toast({ title: '导入失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: string) => dictionaryApi.remove(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      queryClient.invalidateQueries({ queryKey: ['dictionaries'] })
    },
    onError: (e: any) => toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const entries = useQuery({
    queryKey: ['dict-entries', entriesOf?.id, entryPage],
    enabled: !!entriesOf,
    queryFn: () =>
      dictionaryApi.entries(entriesOf!.id, { page: entryPage, page_size: 100 }),
  })

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">字典</h1>
          <p className="text-sm text-muted-foreground">
            词表两段式导入：预览 15 分钟有效，按 5 万行一段物化；被种子引用的字典不可删除。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button onClick={() => setImportOpen(true)}>
            <Upload className="mr-2 h-4 w-4" /> 导入词表
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          className={
            'rounded-full border px-3 py-1 text-sm ' +
            (type === '' ? 'border-primary bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted')
          }
          onClick={() => { setType(''); setPage(1) }}
        >
          全部
        </button>
        {dictionaryTypes.map((t) => (
          <button
            key={t}
            className={
              'rounded-full border px-3 py-1 text-sm ' +
              (type === t ? 'border-primary bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted')
            }
            onClick={() => { setType(t); setPage(1) }}
          >
            {t}
          </button>
        ))}
        <span className="ml-auto text-sm text-muted-foreground">共 {total} 个</span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead className="w-[120px]">类型</TableHead>
              <TableHead className="w-[110px]">行数</TableHead>
              <TableHead className="w-[90px]">来源</TableHead>
              <TableHead className="w-[170px]">创建时间</TableHead>
              <TableHead className="w-[170px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isLoading && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">加载中…</TableCell>
              </TableRow>
            )}
            {!list.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  还没有字典。点右上角「导入词表」，预览确认后入库。
                </TableCell>
              </TableRow>
            )}
            {items.map((d: Dictionary) => (
              <TableRow key={d.id}>
                <TableCell className="text-sm">{d.name}</TableCell>
                <TableCell className="font-mono text-xs">{d.type}</TableCell>
                <TableCell className="text-sm tabular-nums">{d.line_count.toLocaleString()}</TableCell>
                <TableCell>
                  <Badge variant={d.is_builtin ? 'secondary' : 'outline'}>
                    {d.is_builtin ? '内置' : '导入'}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{formatDate(d.created_at)}</TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button size="sm" variant="outline" onClick={() => { setEntriesOf(d); setEntryPage(1) }}>
                      <Eye className="mr-1 h-3.5 w-3.5" /> 条目
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={async () => {
                        if (await confirm(`删除字典 ${d.name}？`)) remove.mutate(d.id)
                      }}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
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

      {/* 导入词表 */}
      <Dialog open={importOpen} onOpenChange={(v) => { setImportOpen(v); if (!v) setPreview(null) }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>导入词表</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1">
                <Label>名称 *</Label>
                <Input
                  value={name}
                  onChange={(e) => { setName(e.target.value); setPreview(null) }}
                  placeholder="例如：常用子域-2026"
                />
              </div>
              <div className="space-y-1">
                <Label>类型</Label>
                <Select value={dictType} onValueChange={(v) => { setDictType(v); setPreview(null) }}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {dictionaryTypes.map((t) => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>格式</Label>
                <Select value={format} onValueChange={(v) => { setFormat(v); setPreview(null) }}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="text">文本（每行一条）</SelectItem>
                    <SelectItem value="csv">CSV（取第一列）</SelectItem>
                    <SelectItem value="tsv">TSV（取第一列）</SelectItem>
                    <SelectItem value="xlsx">Excel（.xlsx，取第一列）</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            {format === 'xlsx' ? (
              <div className="space-y-1">
                <Label>词表文件（取第一列，首行表头自动跳过）</Label>
                {/* 原生 file 控件不可样式化，隐藏后由 Button 触发，与其它上传入口保持一致 */}
                <input
                  id="dict-xlsx-file"
                  type="file"
                  accept=".xlsx"
                  className="hidden"
                  onChange={(e) => {
                    setXlsxFile(e.target.files?.[0] ?? null)
                    setPreview(null)
                  }}
                />
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" asChild>
                    <label htmlFor="dict-xlsx-file" className="cursor-pointer">
                      <Paperclip className="mr-2 h-4 w-4" />
                      选择文件
                    </label>
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    {xlsxFile ? xlsxFile.name : '选择一个 .xlsx 文件'}
                  </p>
                </div>
              </div>
            ) : (
              <div className="space-y-1">
                <Label>词表（每行一条）</Label>
                <Textarea
                  className="min-h-[180px] font-mono text-sm"
                  value={text}
                  onChange={(e) => { setText(e.target.value); setPreview(null) }}
                  placeholder={'www\napi\nmail'}
                />
              </div>
            )}
            {preview && (
              <div className="rounded-md border bg-muted/30 p-3 text-sm">
                <div className="flex flex-wrap gap-4">
                  <span>总行数 <b>{preview.total}</b></span>
                  <span>去重后 <b>{preview.unique}</b></span>
                  <span>重复 <b>{preview.duplicates}</b></span>
                  <span>分段 <b>{preview.segments}</b></span>
                </div>
                <div className="mt-2 font-mono text-xs text-muted-foreground">
                  {preview.sample.join(' · ')}
                  {preview.unique > preview.sample.length ? ' …' : ''}
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  预览 {formatDate(preview.expires_at)} 前有效
                </div>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>取消</Button>
            <Button
              variant="secondary"
              onClick={() => previewMutation.mutate()}
              disabled={
                !name.trim() ||
                (format === 'xlsx' ? !xlsxFile : !text.trim()) ||
                previewMutation.isPending
              }
            >
              <Plus className="mr-1 h-4 w-4" /> 预览
            </Button>
            <Button
              onClick={() => preview && importMutation.mutate(preview.token)}
              disabled={!preview || importMutation.isPending}
            >
              确认导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 条目 */}
      <Dialog open={!!entriesOf} onOpenChange={(v) => !v && setEntriesOf(null)}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>{entriesOf?.name} · 词表条目</DialogTitle>
          </DialogHeader>
          <div className="max-h-[50vh] overflow-auto rounded border p-3 font-mono text-sm">
            {(entries.data?.data ?? []).map((v) => (
              <div key={v} className="border-b py-0.5 last:border-0">{v}</div>
            ))}
            {entries.isLoading && <div className="text-muted-foreground">加载中…</div>}
            {!entries.isLoading && (entries.data?.data ?? []).length === 0 && (
              <div className="text-muted-foreground">没有条目</div>
            )}
          </div>
          <DialogFooter className="items-center justify-between">
            <span className="text-xs text-muted-foreground">
              共 {entries.data?.total ?? 0} 条 · 第 {entryPage} 页
            </span>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" disabled={entryPage <= 1} onClick={() => setEntryPage(entryPage - 1)}>
                上一页
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={(entries.data?.total ?? 0) <= entryPage * 100}
                onClick={() => setEntryPage(entryPage + 1)}
              >
                下一页
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

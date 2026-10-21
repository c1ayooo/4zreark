import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'

import { fpApi, type FpRule } from '@/api/fingerprints'
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
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'

const PAGE_SIZE = 50

type FormState = {
  name: string
  category: string
  version: string
  enabled: boolean
  expression: string
  condition: string
}

const emptyForm: FormState = {
  name: '',
  category: 'other',
  version: '',
  enabled: true,
  expression: '',
  condition: '',
}

export default function FingerprintsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')

  const [q, setQ] = useState('')
  const [category, setCategory] = useState('')
  const [source, setSource] = useState('')
  const [enabled, setEnabled] = useState('')
  const [page, setPage] = useState(1)

  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<FpRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)

  const list = useQuery({
    queryKey: ['fingerprints', q, category, source, enabled, page],
    queryFn: () =>
      fpApi.list({
        q: q || undefined,
        category: category || undefined,
        source: source || undefined,
        enabled: enabled || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  })
  const sources = useQuery({ queryKey: ['fingerprint-sources'], queryFn: () => fpApi.sources() })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['fingerprints'] })
    queryClient.invalidateQueries({ queryKey: ['fingerprint-sources'] })
  }

  const save = useMutation({
    mutationFn: () => {
      let condition: Record<string, unknown> | null = null
      if (form.condition.trim()) {
        try {
          condition = JSON.parse(form.condition)
        } catch {
          throw new Error('条件树不是合法 JSON')
        }
      }
      if (!form.expression.trim() && !condition) {
        throw new Error('表达式与条件树至少填一个')
      }
      return fpApi.upsert({
        name: form.name.trim(),
        category: form.category.trim(),
        version: form.version.trim() || undefined,
        enabled: form.enabled,
        expression: form.expression.trim() || undefined,
        condition_tree: condition,
      })
    },
    onSuccess: () => {
      toast({ title: editing ? '规则已更新' : '规则已创建' })
      setOpen(false)
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const toggle = useMutation({
    mutationFn: ({ rule, next }: { rule: FpRule; next: boolean }) =>
      fpApi.toggle(rule.name, next),
    onSuccess: () => invalidate(),
    onError: (e: any) =>
      toast({ title: '启停失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (name: string) => fpApi.remove(name),
    onSuccess: () => {
      toast({ title: '规则已删除' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const sync = useMutation({
    mutationFn: () => fpApi.sync(),
    onSuccess: () => {
      toast({ title: '内置规则已同步' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '同步失败', description: e?.message, variant: 'destructive' }),
  })

  const openCreate = () => {
    setEditing(null)
    setForm(emptyForm)
    setOpen(true)
  }
  const openEdit = (r: FpRule) => {
    setEditing(r)
    setForm({
      name: r.name,
      category: r.category,
      version: r.version,
      enabled: r.enabled,
      expression: r.expression ?? '',
      condition: r.condition_tree ? JSON.stringify(r.condition_tree, null, 2) : '',
    })
    setOpen(true)
  }

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const counts = sources.data?.data?.counts ?? {}

  const shape = (r: FpRule) => {
    if (r.expression) return '表达式'
    if (r.condition_tree) return '条件树'
    if (r.rules && r.rules.length > 0) return '扁平规则'
    return '—'
  }

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <Fingerprint className="h-6 w-6" /> 指纹库
          </h1>
          <p className="text-sm text-muted-foreground">
            reconkit 表达式与条件树规则共用一张表；改规则会立即失效扫描缓存
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {Object.entries(counts).map(([src, n]) => (
            <Badge key={src} variant="outline">
              {src} {n}
            </Badge>
          ))}
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          {isAdmin && (
            <Button variant="outline" onClick={() => sync.mutate()} disabled={sync.isPending}>
              {sync.isPending ? '同步中…' : '同步内置规则'}
            </Button>
          )}
          {isAdmin && (
            <Button onClick={openCreate}>
              <Plus className="mr-2 h-4 w-4" /> 新建规则
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="w-64"
          placeholder="搜索规则名"
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPage(1)
          }}
        />
        <Input
          className="w-40"
          placeholder="分类"
          value={category}
          onChange={(e) => {
            setCategory(e.target.value)
            setPage(1)
          }}
        />
        <Select
          value={source || 'all'}
          onValueChange={(v) => {
            setSource(v === 'all' ? '' : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部来源</SelectItem>
            <SelectItem value="dddd">dddd</SelectItem>
            <SelectItem value="seed">seed</SelectItem>
            <SelectItem value="governance">governance</SelectItem>
            <SelectItem value="intel">intel</SelectItem>
            <SelectItem value="custom">custom</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={enabled || 'all'}
          onValueChange={(v) => {
            setEnabled(v === 'all' ? '' : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">启用态</SelectItem>
            <SelectItem value="1">已启用</SelectItem>
            <SelectItem value="0">已停用</SelectItem>
          </SelectContent>
        </Select>
        <span className="ml-auto text-sm text-muted-foreground">{total} 条</span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>规则名</TableHead>
              <TableHead className="w-[130px]">分类</TableHead>
              <TableHead className="w-[100px]">来源</TableHead>
              <TableHead className="w-[100px]">形态</TableHead>
              <TableHead className="w-[80px]">启用</TableHead>
              <TableHead className="w-[150px]">更新时间</TableHead>
              <TableHead className="w-[100px]">操作</TableHead>
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
                <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                  没有匹配的规则
                </TableCell>
              </TableRow>
            )}
            {items.map((r) => (
              <TableRow key={r.id || r.name}>
                <TableCell className="max-w-[420px] truncate font-mono text-xs" title={r.name}>
                  {r.name}
                </TableCell>
                <TableCell className="text-sm">{r.category || '—'}</TableCell>
                <TableCell>
                  <Badge variant="outline">{r.source || '—'}</Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{shape(r)}</TableCell>
                <TableCell>
                  <Switch
                    checked={r.enabled}
                    disabled={!isAdmin || toggle.isPending}
                    onCheckedChange={(v) => toggle.mutate({ rule: r, next: v })}
                  />
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(r.updated_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button size="icon" variant="ghost" onClick={() => openEdit(r)} title="编辑">
                      <Pencil className="h-4 w-4" />
                    </Button>
                    {isAdmin && (
                      <Button
                        size="icon"
                        variant="ghost"
                        title="删除"
                        onClick={async () => {
                          if (await confirm(`删除规则「${r.name}」？`)) remove.mutate(r.name)
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
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

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle>{editing ? `编辑规则 · ${editing.name}` : '新建指纹规则'}</DialogTitle>
            <DialogDescription>
              表达式使用 reconkit 语法：<code>body="word"</code>、
              <code>header="server"="nginx"</code>、<code>status==200</code>，支持
              <code>&amp;&amp; || !</code> 与括号。条件树为 JSON，二选一。
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>规则名（唯一）</Label>
                <Input
                  value={form.name}
                  disabled={!!editing}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>分类</Label>
                <Input
                  value={form.category}
                  placeholder="cms / framework / server ..."
                  onChange={(e) => setForm({ ...form, category: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>版本（可选）</Label>
                <Input
                  value={form.version}
                  onChange={(e) => setForm({ ...form, version: e.target.value })}
                />
              </div>
              <label className="flex items-end gap-2 pb-2 text-sm">
                <Switch
                  checked={form.enabled}
                  onCheckedChange={(v) => setForm({ ...form, enabled: v })}
                />
                启用
              </label>
            </div>

            <div className="space-y-1">
              <Label>表达式（reconkit）</Label>
              <Textarea
                className="h-28 w-full rounded-md border bg-background p-3 font-mono text-sm"
                placeholder={'header="server"="nginx" && body="word"'}
                value={form.expression}
                onChange={(e) => setForm({ ...form, expression: e.target.value })}
              />
            </div>

            <div className="space-y-1">
              <Label>条件树 JSON（可选）</Label>
              <Textarea
                className="h-40 w-full rounded-md border bg-background p-3 font-mono text-xs"
                placeholder={'{\n  "and": [\n    {"type": "body", "op": "contains", "value": "word"}\n  ]\n}'}
                value={form.condition}
                onChange={(e) => setForm({ ...form, condition: e.target.value })}
              />
            </div>

            {editing && (editing.rules?.length ?? 0) > 0 && (
              <div className="rounded-md border bg-muted/30 p-3 text-xs text-muted-foreground">
                该规则原有 {editing.rules?.length} 条扁平匹配项；保存时会以当前表达式/条件树为准。
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button
              onClick={() => save.mutate()}
              disabled={save.isPending || !form.name.trim()}
            >
              {save.isPending ? '保存中…' : '保存'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, Trash2, Zap } from 'lucide-react'

import { sourceApi, sourceKinds, type Source, type SourceInput } from '@/api/sources'
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
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const emptyForm: SourceInput = { kind: 'fofa', name: '', endpoint: '', enabled: true, secret: '' }

export default function SourcesPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState<SourceInput>(emptyForm)

  const list = useQuery({ queryKey: ['sources'], queryFn: () => sourceApi.list() })

  const create = useMutation({
    mutationFn: (body: SourceInput) => sourceApi.create(body),
    onSuccess: () => {
      toast({ title: '数据源已创建' })
      setOpen(false)
      setForm(emptyForm)
      queryClient.invalidateQueries({ queryKey: ['sources'] })
    },
    onError: (e: any) => toast({ title: '创建失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: number) => sourceApi.remove(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      queryClient.invalidateQueries({ queryKey: ['sources'] })
    },
    onError: (e: any) => toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const test = useMutation({
    mutationFn: (id: number) => sourceApi.test(id),
    onSuccess: (res) => {
      toast({
        title: res.data.ok ? '连接正常' : '连接失败',
        description: `${res.data.message}${res.data.elapsed_ms ? ` · ${res.data.elapsed_ms}ms` : ''}`,
      })
      queryClient.invalidateQueries({ queryKey: ['sources'] })
    },
    onError: (e: any) => toast({ title: '测试失败', description: e?.message, variant: 'destructive' }),
  })

  const items = list.data?.data.items ?? []

  return (
    <div className="space-y-5 p-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold">数据源</h1>
          <p className="text-sm text-muted-foreground">
            测绘引擎 / 被动源 / 导入源的配置与凭据台账。凭据以 AES-256-GCM 密文落库，
            只显示「已配置」，不回显明文（密钥来自 ZRE_SECRET_KEY）。
            <br />
            GitHub Token 也在这里配置：类型选 <code className="font-mono">github</code>，
            凭据填 Personal Access Token；它同时用于情报 PoC 富化与指纹上游同步。
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button onClick={() => setOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> 新建数据源
          </Button>
        </div>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[110px]">类型</TableHead>
              <TableHead>名称</TableHead>
              <TableHead>Endpoint</TableHead>
              <TableHead className="w-[100px]">凭据</TableHead>
              <TableHead className="w-[90px]">启用</TableHead>
              <TableHead className="w-[170px]">最近测试</TableHead>
              <TableHead className="w-[150px]">操作</TableHead>
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
                  还没有数据源。新建后可用「测试」发一次最小请求验证连通性。
                </TableCell>
              </TableRow>
            )}
            {items.map((s: Source) => (
              <TableRow key={s.id}>
                <TableCell className="font-mono text-xs">{s.kind}</TableCell>
                <TableCell className="text-sm">{s.name}</TableCell>
                <TableCell className="max-w-[320px] truncate font-mono text-xs text-muted-foreground">
                  {s.endpoint || '—'}
                </TableCell>
                <TableCell>
                  <Badge variant={s.has_secret ? 'default' : 'outline'}>
                    {s.has_secret ? '已配置' : '无'}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge variant={s.enabled ? 'secondary' : 'outline'}>{s.enabled ? '启用' : '停用'}</Badge>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {s.last_ok_at ? `成功 ${formatDate(s.last_ok_at)}` : s.last_error ? `失败：${s.last_error}` : '—'}
                </TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    <Button size="sm" variant="outline" onClick={() => test.mutate(s.id)} disabled={test.isPending}>
                      <Zap className="mr-1 h-3.5 w-3.5" /> 测试
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={async () => {
                        if (await confirm(`删除数据源 ${s.name}？凭据会一并删除。`)) remove.mutate(s.id)
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

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建数据源</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>类型</Label>
                <Select value={form.kind} onValueChange={(v) => setForm({ ...form, kind: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {sourceKinds.map((k) => (
                      <SelectItem key={k} value={k}>
                        {k}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>名称 *</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
            </div>
            <div className="space-y-1">
              <Label>Endpoint</Label>
              <Input
                placeholder={
                  form.kind === 'github'
                    ? 'https://api.github.com/rate_limit（留空默认）'
                    : 'https://api.example.com/search'
                }
                value={form.endpoint}
                onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>凭据（API Key / Token）</Label>
              <Input
                type="password"
                placeholder={
                  form.kind === 'github'
                    ? 'ghp_... / github_pat_...'
                    : '保存后不可回显；留空表示不配置'
                }
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
              />
              {form.kind === 'github' && (
                <p className="text-muted-foreground text-xs">
                  环境变量 GITHUB_TOKEN 优先于这里的凭据；两者都没配时，富化接口会明确报错。
                </p>
              )}
            </div>
            <label className="flex items-center gap-2 text-sm">
              <Switch checked={form.enabled} onCheckedChange={(v) => setForm({ ...form, enabled: v })} />
              启用
            </label>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button onClick={() => create.mutate(form)} disabled={!form.name.trim() || create.isPending}>
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

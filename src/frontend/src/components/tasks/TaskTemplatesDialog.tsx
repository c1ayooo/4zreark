import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { templateApi, TaskTemplate, TaskTemplateInput } from '@/api/tasks'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { Pencil, Plus, Trash2 } from 'lucide-react'

const MODULE_OPTIONS = [
  { id: 'subdomain', label: '子域名' },
  { id: 'port_scan', label: '端口扫描' },
  { id: 'fingerprint', label: '指纹识别' },
  { id: 'crawler', label: 'Web爬虫' },
  { id: 'dir_scan', label: '目录扫描' },
  { id: 'vuln_scan', label: '漏洞扫描' },
]

const TEMPLATE_TYPES = [
  { id: 'subdomain', label: '信息收集' },
  { id: 'port_scan', label: '端口扫描' },
  { id: 'vuln_scan', label: '漏洞扫描' },
]

interface FormState {
  name: string
  description: string
  type: string
  scan_types: string[]
  rate_per_sec: number
  target_delay_ms: number
}

const emptyForm: FormState = {
  name: '',
  description: '',
  type: 'subdomain',
  scan_types: ['subdomain', 'port_scan', 'fingerprint'],
  rate_per_sec: 20,
  target_delay_ms: 200,
}

interface TaskTemplatesDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export default function TaskTemplatesDialog({ open, onOpenChange }: TaskTemplatesDialogProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<TaskTemplate | null>(null)
  const [formOpen, setFormOpen] = useState(false)
  const [form, setForm] = useState<FormState>(emptyForm)

  const { data, isLoading } = useQuery({
    queryKey: ['task-templates'],
    queryFn: () => templateApi.list(),
    enabled: open,
  })

  const templates: TaskTemplate[] = data?.data || []

  useEffect(() => {
    if (!open) {
      setFormOpen(false)
      setEditing(null)
      setForm(emptyForm)
    }
  }, [open])

  const saveMutation = useMutation<unknown, Error, TaskTemplateInput>({
    mutationFn: (payload: TaskTemplateInput) =>
      editing ? templateApi.update(editing.id, payload) : templateApi.create(payload),
    onSuccess: () => {
      toast({ title: editing ? '模板已更新' : '模板已创建' })
      queryClient.invalidateQueries({ queryKey: ['task-templates'] })
      setFormOpen(false)
      setEditing(null)
      setForm(emptyForm)
    },
    onError: (err: Error) => toast({ title: '保存失败', description: err.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => templateApi.remove(id),
    onSuccess: () => {
      toast({ title: '模板已删除' })
      queryClient.invalidateQueries({ queryKey: ['task-templates'] })
    },
    onError: (err: Error) => toast({ title: '删除失败', description: err.message, variant: 'destructive' }),
  })

  const startCreate = () => {
    setEditing(null)
    setForm(emptyForm)
    setFormOpen(true)
  }

  const startEdit = (t: TaskTemplate) => {
    const cfg = t.config || {}
    setEditing(t)
    setForm({
      name: t.name,
      description: t.description || '',
      type: t.type || 'subdomain',
      scan_types: cfg.scan_types || [],
      rate_per_sec: cfg.rate_per_sec ?? 20,
      target_delay_ms: cfg.target_delay_ms ?? 200,
    })
    setFormOpen(true)
  }

  const toggleModule = (id: string) => {
    setForm((prev) => ({
      ...prev,
      scan_types: prev.scan_types.includes(id)
        ? prev.scan_types.filter((m) => m !== id)
        : [...prev.scan_types, id],
    }))
  }

  const submit = () => {
    if (!form.name.trim()) {
      toast({ title: '模板名称不能为空', variant: 'destructive' })
      return
    }
    if (form.scan_types.length === 0) {
      toast({ title: '至少选择一个扫描模块', variant: 'destructive' })
      return
    }
    saveMutation.mutate({
      name: form.name.trim(),
      description: form.description.trim(),
      type: form.type,
      is_public: true,
      config: {
        scanTypes: form.scan_types,
        scan_types: form.scan_types,
        rate_per_sec: form.rate_per_sec,
        target_delay_ms: form.target_delay_ms,
      } as TaskTemplateInput['config'],
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle>任务模板</DialogTitle>
          <DialogDescription>
            模板只描述「扫哪些模块 + 扫多快」，创建任务时可直接套用。
          </DialogDescription>
        </DialogHeader>

        {formOpen ? (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">模板名称</Label>
                <Input
                  value={form.name}
                  placeholder="例如：信息收集（不含漏洞）"
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">任务类型</Label>
                <Select value={form.type} onValueChange={(v) => setForm({ ...form, type: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {TEMPLATE_TYPES.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">描述</Label>
              <Textarea
                rows={2}
                value={form.description}
                placeholder="说明这个模板适合什么场景"
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </div>

            <div className="space-y-2">
              <Label className="text-xs text-muted-foreground">扫描模块</Label>
              <div className="grid grid-cols-3 gap-2">
                {MODULE_OPTIONS.map((m) => (
                  <label
                    key={m.id}
                    className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted/50"
                  >
                    <Checkbox
                      checked={form.scan_types.includes(m.id)}
                      onCheckedChange={() => toggleModule(m.id)}
                    />
                    {m.label}
                  </label>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                指纹、爬虫、目录、漏洞会自动补齐端口与指纹上游模块。
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">每秒请求上限</Label>
                <Input
                  type="number"
                  min={1}
                  max={200}
                  value={form.rate_per_sec}
                  onChange={(e) => setForm({ ...form, rate_per_sec: Number(e.target.value) || 1 })}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">单目标间隔（毫秒）</Label>
                <Input
                  type="number"
                  min={0}
                  max={5000}
                  step={50}
                  value={form.target_delay_ms}
                  onChange={(e) => setForm({ ...form, target_delay_ms: Number(e.target.value) })}
                />
              </div>
            </div>

            <div className="flex justify-end gap-2">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setFormOpen(false)
                  setEditing(null)
                }}
              >
                取消
              </Button>
              <Button type="button" onClick={submit} disabled={saveMutation.isPending}>
                {editing ? '保存修改' : '创建模板'}
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex justify-end">
              <Button type="button" size="sm" onClick={startCreate}>
                <Plus className="mr-1.5 h-4 w-4" />
                新建模板
              </Button>
            </div>

            {isLoading ? (
              <p className="py-8 text-center text-sm text-muted-foreground">加载中…</p>
            ) : templates.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                还没有模板，点「新建模板」创建第一个。
              </p>
            ) : (
              <div className="space-y-2">
                {templates.map((t) => {
                  const cfg = t.config || {}
                  return (
                    <div
                      key={t.id}
                      className="flex items-start justify-between gap-3 rounded-lg border p-3"
                    >
                      <div className="min-w-0 space-y-1.5">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{t.name}</span>
                          <Badge variant="secondary">{t.type}</Badge>
                          <Badge variant="outline">
                            {cfg.rate_per_sec ?? 20}/秒 · {cfg.target_delay_ms ?? 200}ms
                          </Badge>
                        </div>
                        {t.description ? (
                          <p className="text-xs text-muted-foreground">{t.description}</p>
                        ) : null}
                        <div className="flex flex-wrap gap-1">
                          {(cfg.scan_types || cfg.scanTypes || []).map((m) => (
                            <Badge key={m} variant="outline" className="text-xs">
                              {m}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-1">
                        <Button type="button" size="sm" variant="ghost" onClick={() => startEdit(t)}>
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          className="text-destructive hover:text-destructive"
                          onClick={() => deleteMutation.mutate(t.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

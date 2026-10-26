import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { templateApi, TaskTemplate, TaskTemplateInput } from '@/api/tasks'
import { Button, Checkbox, Input, Modal, Select, Tag } from 'antd'
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
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      title="任务模板"
      width={768}
      footer={null}
    >
      <p className="mb-4 text-sm text-muted-foreground">
        模板只描述「扫哪些模块 + 扫多快」，创建任务时可直接套用。
      </p>

      {formOpen ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">模板名称</label>
              <Input
                value={form.name}
                placeholder="例如：信息收集（不含漏洞）"
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">任务类型</label>
              <Select
                className="w-full"
                value={form.type}
                onChange={(v) => setForm({ ...form, type: v })}
                options={TEMPLATE_TYPES.map((t) => ({ value: t.id, label: t.label }))}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">描述</label>
            <Input.TextArea
              rows={2}
              value={form.description}
              placeholder="说明这个模板适合什么场景"
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-medium text-muted-foreground">扫描模块</label>
            <div className="grid grid-cols-3 gap-2">
              {MODULE_OPTIONS.map((m) => (
                <label
                  key={m.id}
                  className="flex cursor-pointer items-center gap-2 rounded-md border px-3 py-2 text-sm hover:bg-muted/50"
                >
                  <Checkbox
                    checked={form.scan_types.includes(m.id)}
                    onChange={() => toggleModule(m.id)}
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
              <label className="text-xs font-medium text-muted-foreground">每秒请求上限</label>
              <Input
                type="number"
                min={1}
                max={200}
                value={form.rate_per_sec}
                onChange={(e) => setForm({ ...form, rate_per_sec: Number(e.target.value) || 1 })}
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">单目标间隔（毫秒）</label>
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
              onClick={() => {
                setFormOpen(false)
                setEditing(null)
              }}
            >
              取消
            </Button>
            <Button onClick={submit} loading={saveMutation.isPending} disabled={saveMutation.isPending}>
              {editing ? '保存修改' : '创建模板'}
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex justify-end">
            <Button size="small" icon={<Plus className="h-4 w-4" />} onClick={startCreate}>
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
                        <Tag>{t.type}</Tag>
                        <Tag>
                          {cfg.rate_per_sec ?? 20}/秒 · {cfg.target_delay_ms ?? 200}ms
                        </Tag>
                      </div>
                      {t.description ? (
                        <p className="text-xs text-muted-foreground">{t.description}</p>
                      ) : null}
                      <div className="flex flex-wrap gap-1">
                        {(cfg.scan_types || cfg.scanTypes || []).map((m) => (
                          <Tag key={m} className="text-xs">
                            {m}
                          </Tag>
                        ))}
                      </div>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      <Button
                        type="text"
                        size="small"
                        icon={<Pencil className="h-4 w-4" />}
                        onClick={() => startEdit(t)}
                      />
                      <Button
                        type="text"
                        size="small"
                        className="text-destructive hover:text-destructive"
                        icon={<Trash2 className="h-4 w-4" />}
                        onClick={() => deleteMutation.mutate(t.id)}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </Modal>
  )
}

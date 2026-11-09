import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Drawer, Form, Input, Popconfirm, Select, Switch, Tag, Upload as AntUpload } from 'antd'
import { Pencil, Plus, Sparkles, Star, Trash2, Upload } from 'lucide-react'
import { chatApi, type SkillInput, type SkillItem } from '@/api/chat'
import { sentinelApi } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'

/**
 * 设置 → 审计技能。
 *
 * 技能 = 一段检查清单 + 检索顺序，注入两处：
 *   - 对话：本轮选中的技能（会话级）
 *   - 判定：默认技能（分析任务页选择，或这里设默认）
 * 没有技能时模型照样能答，只是缺少固定的检查顺序。
 */
export function SkillLibraryPanel() {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<SkillItem | null>(null)
  const [form] = Form.useForm<SkillInput>()

  const listQuery = useQuery({
    queryKey: ['chat', 'skills', 'manage'],
    queryFn: chatApi.listSkillsManage,
  })
  const catalogQuery = useQuery({
    queryKey: ['chat', 'skills'],
    queryFn: () => sentinelApi.skills(),
    staleTime: 30_000,
  })

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['chat', 'skills'] })
    qc.invalidateQueries({ queryKey: ['chat', 'skills', 'manage'] })
    qc.invalidateQueries({ queryKey: ['sentinel', 'skills'] })
  }

  const save = useMutation({
    mutationFn: (body: SkillInput) => chatApi.saveSkill(body),
    onSuccess: () => {
      toast({ title: '技能已保存' })
      setOpen(false)
      setEditing(null)
      invalidate()
    },
    onError: (e: Error) => toast({ title: '保存失败', description: e.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: string) => chatApi.deleteSkill(id),
    onSuccess: () => {
      toast({ title: '技能已删除' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '删除失败', description: e.message, variant: 'destructive' }),
  })

  // 导入：.json / .yaml / .md 三种格式都走同一个解析器，导入恒新建（不覆盖内置技能）。
  const importFile = useMutation({
    mutationFn: (file: File) => chatApi.importSkill(file),
    onSuccess: (res) => {
      const failed = res.failed?.length ?? 0
      toast({
        title: `已导入 ${res.items.length} 个技能`,
        description: failed > 0 ? `${failed} 条失败：${res.failed.join('；')}` : undefined,
      })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '导入失败', description: e.message, variant: 'destructive' }),
  })

  const setDefault = useMutation({
    mutationFn: (id: string) => sentinelApi.setDefaultSkill(id),
    onSuccess: () => {
      toast({ title: '已设为判定默认技能' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '设置失败', description: e.message, variant: 'destructive' }),
  })

  useEffect(() => {
    if (!open) return
    if (editing) {
      form.setFieldsValue({
        id: editing.id,
        name: editing.name,
        version: editing.version,
        desc: editing.desc,
        prompt: editing.prompt ?? '',
        checks: editing.checks,
        vuln_classes: editing.vuln_classes,
        enabled: editing.enabled,
        sort: editing.sort,
      })
    } else {
      form.resetFields()
      form.setFieldsValue({ version: 'v1.0', enabled: true, checks: 0, sort: 99 })
    }
  }, [open, editing, form])

  const items = listQuery.data ?? []
  const defaultId = catalogQuery.data?.default_id ?? ''

  const openCreate = () => {
    setEditing(null)
    setOpen(true)
  }
  const openEdit = (s: SkillItem) => {
    setEditing(s)
    setOpen(true)
  }

  return (
    <div className="space-y-3">
      <Card
        title={
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-2">
              <Sparkles size={14} /> 审计技能库
              <Tag className="border-border bg-muted text-[10px]">{items.length} 个</Tag>
            </span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              技能是注入给模型的检查清单与顺序，不改变工具权限。对话里按会话选，判定用「默认技能」。
              内置技能可以改检查项，但不能删除（可停用）。
            </span>
          </div>
        }
        extra={
          <div className="flex items-center gap-1.5">
            <AntUpload
              accept=".json,.yaml,.yml,.md,.txt"
              showUploadList={false}
              beforeUpload={(file) => {
                importFile.mutate(file as File)
                return false
              }}
            >
              <Button size="small" icon={<Upload size={13} />} loading={importFile.isPending}>
                导入
              </Button>
            </AntUpload>
            <Button size="small" type="primary" icon={<Plus size={13} />} onClick={openCreate}>
              新建技能
            </Button>
          </div>
        }
      >
        {listQuery.isLoading ? (
          <p className="text-[12px] text-muted-foreground">加载中…</p>
        ) : items.length === 0 ? (
          <p className="text-[12px] text-muted-foreground">还没有技能，点右上角新建。</p>
        ) : (
          <div className="divide-y divide-border">
            {items.map((s) => {
              const isDefault = s.id === defaultId
              return (
                <div key={s.id} className="flex flex-wrap items-center gap-2 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-[12.5px] font-medium text-foreground">{s.name}</span>
                      <span className="font-mono text-[10px] text-muted-foreground">{s.version}</span>
                      {s.builtin && (
                        <Tag className="m-0 border-border bg-muted text-[9.5px] text-muted-foreground">内置</Tag>
                      )}
                      {isDefault && (
                        <Tag className="m-0 inline-flex items-center gap-0.5 border-transparent bg-emerald-600 text-[9.5px] text-white">
                          <Star size={9} /> 判定默认
                        </Tag>
                      )}
                      {!s.enabled && (
                        <Tag className="m-0 border-transparent bg-zinc-500 text-[9.5px] text-white">已停用</Tag>
                      )}
                    </div>
                    <div className="mt-0.5 line-clamp-2 text-[11px] leading-relaxed text-muted-foreground">
                      {s.desc || '（无描述）'}
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-1">
                      <span className="text-[10px] text-muted-foreground">{s.checks} 项检查</span>
                      {s.vuln_classes?.slice(0, 4).map((v) => (
                        <Tag key={v} className="m-0 border-border bg-background font-mono text-[9px]">
                          {v}
                        </Tag>
                      ))}
                    </div>
                  </div>

                  <div className="flex items-center gap-1">
                    {!isDefault && s.enabled && (
                      <Button size="small" type="text" onClick={() => setDefault.mutate(s.id)}>
                        设为默认
                      </Button>
                    )}
                    <Button size="small" type="text" icon={<Pencil size={12} />} onClick={() => openEdit(s)} />
                    <Popconfirm
                      title="删除这个技能？"
                      disabled={s.builtin}
                      okText="删除"
                      cancelText="取消"
                      onConfirm={() => remove.mutate(s.id)}
                    >
                      <Button
                        size="small"
                        type="text"
                        danger
                        disabled={s.builtin}
                        icon={<Trash2 size={12} />}
                      />
                    </Popconfirm>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </Card>

      <Drawer
        title={editing ? `编辑技能 · ${editing.name}` : '新建技能'}
        width={560}
        open={open}
        onClose={() => {
          setOpen(false)
          setEditing(null)
        }}
        extra={
          <Button type="primary" loading={save.isPending} onClick={() => form.submit()}>
            保存
          </Button>
        }
      >
        <Form form={form} layout="vertical" onFinish={(v) => save.mutate(v)}>
          <Form.Item name="id" hidden>
            <Input />
          </Form.Item>
          <div className="grid grid-cols-2 gap-3">
            <Form.Item
              name="name"
              label="名称"
              rules={[{ required: true, message: '请输入名称' }]}
            >
              <Input placeholder="如：Java 反序列化审计" />
            </Form.Item>
            <Form.Item name="version" label="版本">
              <Input placeholder="v1.0" />
            </Form.Item>
          </div>
          <Form.Item name="desc" label="一句话描述">
            <Input placeholder="readObject / XMLDecoder / gadget 链检索顺序" />
          </Form.Item>
          <Form.Item
            name="prompt"
            label="检查项（会原文注入系统提示）"
            rules={[{ required: true, message: '检查项不能为空' }]}
            extra="建议用 1. 2. 3. 编号，模型会按顺序检索；命中即停的写法能减少无关展开。"
          >
            <Input.TextArea rows={10} placeholder={'按以下顺序检查：\n1. …\n2. …'} />
          </Form.Item>
          <div className="grid grid-cols-2 gap-3">
            <Form.Item name="checks" label="检查项条数（0 = 自动按编号行统计）">
              <Input type="number" />
            </Form.Item>
            <Form.Item name="sort" label="排序（越小越靠前）">
              <Input type="number" />
            </Form.Item>
          </div>
          <Form.Item name="vuln_classes" label="关联漏洞类型（可选，便于筛选）">
            <Select
              mode="tags"
              placeholder="DESERIALIZATION / INJECTION / …"
              options={[
                'DESERIALIZATION', 'TYPE_CONFUSION', 'INJECTION', 'AUTH_BYPASS',
                'PRIV_ESC', 'SSRF', 'PATH_TRAVERSAL', 'OOB_READ', 'OOB_WRITE',
                'BUFFER_OVERFLOW', 'INTEGER_OVERFLOW', 'INFO_LEAK', 'OTHER',
              ].map((v) => ({ value: v, label: v }))}
            />
          </Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Drawer>
    </div>
  )
}

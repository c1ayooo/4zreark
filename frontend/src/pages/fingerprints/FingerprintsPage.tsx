import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fingerprint, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react'
import { Button, Input, Modal, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { fpApi, type FpRule } from '@/api/fingerprints'
import { useConfirm } from '@/components/common/confirm-provider'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
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
  const debouncedQ = useDebouncedValue(q)
  useEffect(() => { setPage(1) }, [debouncedQ])
  const [category, setCategory] = useState('')
  const [source, setSource] = useState('')
  const [enabled, setEnabled] = useState('')
  const [page, setPage] = useState(1)

  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<FpRule | null>(null)
  const [form, setForm] = useState<FormState>(emptyForm)

  const list = useQuery({
    queryKey: ['fingerprints', debouncedQ, category, source, enabled, page],
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
  const counts = sources.data?.data?.counts ?? {}

  const shape = (r: FpRule) => {
    if (r.expression) return '表达式'
    if (r.condition_tree) return '条件树'
    if (r.rules && r.rules.length > 0) return '扁平规则'
    return '—'
  }

  const columns: TableProps<FpRule>['columns'] = [
    {
      title: '规则名',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '分类',
      dataIndex: 'category',
      key: 'category',
      width: 130,
      render: (v: string) => <span className="text-sm">{v || '—'}</span>,
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 100,
      render: (v: string) => <Tag>{v || '—'}</Tag>,
    },
    {
      title: '形态',
      key: 'shape',
      width: 100,
      render: (_, r) => <span className="text-xs text-muted-foreground">{shape(r)}</span>,
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (v: boolean, r) => (
        <Switch
          checked={v}
          disabled={!isAdmin || toggle.isPending}
          onChange={(next) => toggle.mutate({ rule: r, next })}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 150,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{formatDate(v)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      render: (_, r) => (
        <div className="flex items-center gap-1">
          <Button
            type="text"
            size="small"
            title="编辑"
            onClick={() => openEdit(r)}
            icon={<Pencil className="h-4 w-4" />}
          />
          {isAdmin && (
            <Button
              type="text"
              size="small"
              danger
              title="删除"
              icon={<Trash2 className="h-4 w-4" />}
              onClick={async () => {
                if (await confirm(`删除规则「${r.name}」？`)) remove.mutate(r.name)
              }}
            />
          )}
        </div>
      ),
    },
  ]

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
            <Tag key={src}>
              {src} {n}
            </Tag>
          ))}
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          {isAdmin && (
            <Button onClick={() => sync.mutate()} disabled={sync.isPending}>
              {sync.isPending ? '同步中…' : '同步内置规则'}
            </Button>
          )}
          {isAdmin && (
            <Button type="primary" onClick={openCreate}>
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
          className="w-40"
          value={source || 'all'}
          onChange={(v) => {
            setSource(v === 'all' ? '' : v)
            setPage(1)
          }}
          options={[
            { value: 'all', label: '全部来源' },
            { value: 'dddd', label: 'dddd' },
            { value: 'seed', label: 'seed' },
            { value: 'governance', label: 'governance' },
            { value: 'intel', label: 'intel' },
            { value: 'custom', label: 'custom' },
          ]}
        />
        <Select
          className="w-32"
          value={enabled || 'all'}
          onChange={(v) => {
            setEnabled(v === 'all' ? '' : v)
            setPage(1)
          }}
          options={[
            { value: 'all', label: '启用态' },
            { value: '1', label: '已启用' },
            { value: '0', label: '已停用' },
          ]}
        />
        <span className="ml-auto text-sm text-muted-foreground">{total} 条</span>
      </div>

      <div className="overflow-hidden rounded-md border">
        <Table<FpRule>
          columns={columns}
          dataSource={items}
          rowKey={(r) => r.id || r.name}
          loading={list.isLoading}
          locale={{
            emptyText: (
              <div className="py-8 text-center text-muted-foreground">没有匹配的规则</div>
            ),
          }}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showQuickJumper: true,
            // page_size 固定 50、无独立 pageSize 状态，不展示切换器
            showSizeChanger: false,
            hideOnSinglePage: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      <Modal
        open={open}
        onCancel={() => setOpen(false)}
        width={768}
        title={editing ? `编辑规则 · ${editing.name}` : '新建指纹规则'}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => save.mutate()}
              disabled={save.isPending || !form.name.trim()}
            >
              {save.isPending ? '保存中…' : '保存'}
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            表达式使用 reconkit 语法：<code>body="word"</code>、
            <code>header="server"="nginx"</code>、<code>status==200</code>，支持
            <code>&amp;&amp; || !</code> 与括号。条件树为 JSON，二选一。
          </p>

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">规则名（唯一）</label>
              <Input
                value={form.name}
                disabled={!!editing}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">分类</label>
              <Input
                value={form.category}
                placeholder="cms / framework / server ..."
                onChange={(e) => setForm({ ...form, category: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">版本（可选）</label>
              <Input
                value={form.version}
                onChange={(e) => setForm({ ...form, version: e.target.value })}
              />
            </div>
            <label className="flex items-end gap-2 pb-2 text-sm">
              <Switch
                checked={form.enabled}
                onChange={(v) => setForm({ ...form, enabled: v })}
              />
              启用
            </label>
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">表达式（reconkit）</label>
            <Input.TextArea
              className="font-mono text-sm"
              rows={4}
              placeholder={'header="server"="nginx" && body="word"'}
              value={form.expression}
              onChange={(e) => setForm({ ...form, expression: e.target.value })}
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">条件树 JSON（可选）</label>
            <Input.TextArea
              className="font-mono text-xs"
              rows={6}
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
      </Modal>
    </div>
  )
}

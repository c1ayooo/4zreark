import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, RefreshCw, Trash2, Zap } from 'lucide-react'
import { Button, Input, Modal, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { sourceApi, sourceKinds, type Source, type SourceInput } from '@/api/sources'
import { useConfirm } from '@/components/common/confirm-provider'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const emptyForm: SourceInput = { kind: 'fofa', name: '', endpoint: '', enabled: true, secret: '' }

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'default' | 'secondary' | 'destructive' | 'outline') =>
  variant === 'default'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : ''

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

  const columns: TableProps<Source>['columns'] = [
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 110,
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (v: string) => <span className="text-sm">{v}</span>,
    },
    {
      title: 'Endpoint',
      dataIndex: 'endpoint',
      key: 'endpoint',
      ellipsis: true,
      render: (v: string) => (
        <span className="font-mono text-xs text-muted-foreground">{v || '—'}</span>
      ),
    },
    {
      title: '凭据',
      dataIndex: 'has_secret',
      key: 'has_secret',
      width: 100,
      render: (v: boolean) => (
        <Tag className={badgeCls(v ? 'default' : 'outline')}>{v ? '已配置' : '无'}</Tag>
      ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 90,
      render: (v: boolean) => (
        <Tag className={badgeCls(v ? 'secondary' : 'outline')}>{v ? '启用' : '停用'}</Tag>
      ),
    },
    {
      title: '最近测试',
      key: 'last_test',
      width: 170,
      render: (_, s) => (
        <span className="text-xs text-muted-foreground">
          {s.last_ok_at ? `成功 ${formatDate(s.last_ok_at)}` : s.last_error ? `失败：${s.last_error}` : '—'}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      render: (_, s) => (
        <div className="flex gap-1">
          <Button size="small" onClick={() => test.mutate(s.id)} disabled={test.isPending}>
            <Zap className="mr-1 h-3.5 w-3.5" /> 测试
          </Button>
          <Button
            size="small"
            type="text"
            danger
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
              if (await confirm(`删除数据源 ${s.name}？凭据会一并删除。`)) remove.mutate(s.id)
            }}
          />
        </div>
      ),
    },
  ]

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
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button type="primary" onClick={() => setOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> 新建数据源
          </Button>
        </div>
      </div>

      <div className="rounded-md border">
        <Table
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={list.isLoading}
          pagination={false}
          locale={{
            emptyText: (
              <EmptyState
                title="还没有数据源"
                description="新建后可用「测试」发一次最小请求验证连通性。"
                className="border-0"
              />
            ),
          }}
        />
      </div>

      <Modal
        open={open}
        title="新建数据源"
        onCancel={() => setOpen(false)}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => create.mutate(form)}
              disabled={!form.name.trim() || create.isPending}
            >
              创建
            </Button>
          </div>
        }
      >
        <div className="space-y-3 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">类型</label>
              <Select
                value={form.kind}
                onChange={(v) => setForm({ ...form, kind: v })}
                options={sourceKinds.map((k) => ({ value: k, label: k }))}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">名称 *</label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">Endpoint</label>
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
            <label className="text-sm font-medium">凭据（API Key / Token）</label>
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
            <Switch checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
            启用
          </label>
        </div>
      </Modal>
    </div>
  )
}

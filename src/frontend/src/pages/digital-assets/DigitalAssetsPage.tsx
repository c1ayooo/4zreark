import { useEffect, useMemo, useState } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { Plus, RefreshCw, Trash2, Undo2 } from 'lucide-react'
import { Button, Input, Modal, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { projectApi } from '@/api/projects'
import {
  digitalApi,
  digitalKindLabel,
  digitalKinds,
  type DigitalPreview,
} from '@/api/digital'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

const PAGE_SIZE = 50

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'secondary' | 'outline') =>
  variant === 'secondary'
    ? 'border-transparent bg-secondary text-secondary-foreground'
    : ''

export default function DigitalAssetsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [projectId, setProjectId] = useState('0')
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const debouncedQ = useDebouncedValue(q)
  useEffect(() => { setPage(1) }, [debouncedQ])
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
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      digitalApi.list({
        project_id: Number(projectId) || undefined,
        kind: kind || undefined,
        q: debouncedQ || undefined,
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
  const receipts = useMemo(() => batches.data?.data?.items ?? [], [batches.data])
  const canImport = Number(projectId) > 0

  const assetColumns: TableProps<(typeof items)[number]>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (v: string) => <span className="text-sm font-medium">{v}</span>,
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 100,
      render: (v: string) => <Tag>{digitalKindLabel[v] ?? v}</Tag>,
    },
    {
      title: '公司',
      dataIndex: 'company',
      key: 'company',
      width: 160,
      render: (v: string) => <span className="text-sm">{v || '—'}</span>,
    },
    {
      title: '平台',
      dataIndex: 'platform',
      key: 'platform',
      width: 120,
      render: (v: string) => <span className="text-sm">{v || '—'}</span>,
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 90,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{v || '—'}</span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (v: string) => (
        <Tag className={badgeCls(v === 'unverified' ? 'outline' : 'secondary')}>
          {v === 'unverified' ? '待核对' : v}
        </Tag>
      ),
    },
    {
      title: '入库时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{formatDate(v)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 70,
      render: (_, a) => (
        <Button
          type="text"
          size="small"
          danger
          title="删除"
          icon={<Trash2 className="h-4 w-4" />}
          onClick={async () => {
            if (await confirm(`删除「${a.name}」？`)) remove.mutate(a.id)
          }}
        />
      ),
    },
  ]

  const receiptColumns: TableProps<(typeof receipts)[number]>['columns'] = [
    {
      title: '回执',
      dataIndex: 'id',
      key: 'id',
      width: 70,
      render: (v: number) => <span className="font-mono text-sm">#{v}</span>,
    },
    {
      title: '项目',
      dataIndex: 'project_id',
      key: 'project_id',
      width: 130,
      render: (v: number) => <span className="text-sm">{projectName(v)}</span>,
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 90,
      render: (v: string) => (
        <span className="text-xs">{v === 'local_doc' ? '本地文档' : '名单'}</span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => (
        <Tag className={badgeCls(v === 'committed' ? 'secondary' : 'outline')}>
          {v === 'committed' ? '已提交' : v === 'undone' ? '已撤销' : v}
        </Tag>
      ),
    },
    {
      title: '摘要',
      key: 'summary',
      render: (_, b) => (
        <span className="text-xs text-muted-foreground">
          {Object.entries(b.summary ?? {})
            .map(([k, v]) => `${k}: ${String(v)}`)
            .join(' · ')}
        </span>
      ),
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{formatDate(v)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
      render: (_, b) =>
        b.status === 'committed' ? (
          <Button
            size="small"
            onClick={async () => {
              if (await confirm(`撤销回执 #${b.id} 新增的名单？`)) undo.mutate(b.id)
            }}
          >
            <Undo2 className="mr-1 h-3.5 w-3.5" /> 撤销
          </Button>
        ) : null,
    },
  ]

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
            className="w-44"
            value={projectId}
            placeholder="全部项目"
            onChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
            options={[
              { value: '0', label: '全部项目' },
              ...(projects.data?.data ?? []).map((p) => ({
                value: String(p.id),
                label: p.name,
              })),
            ]}
          />
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button
            type="primary"
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

      <div className="overflow-hidden rounded-md border">
        <Table
          columns={assetColumns}
          dataSource={items}
          rowKey="id"
          loading={list.isLoading}
          locale={{
            emptyText: (
              <div className="py-8 text-center text-muted-foreground">
                还没有名单（选择项目后点「导入名单」）
              </div>
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

      <div className="rounded-md border">
        <div className="border-b px-4 py-2 text-sm font-medium">最近导入回执</div>
        <Table
          columns={receiptColumns}
          dataSource={receipts}
          rowKey="id"
          locale={{
            emptyText: (
              <div className="py-6 text-center text-muted-foreground">还没有导入回执</div>
            ),
          }}
          pagination={false}
        />
      </div>

      <Modal
        open={importOpen}
        onCancel={closeImport}
        width={672}
        title="导入数字资产名单"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={closeImport}>取消</Button>
            {!preview ? (
              <Button
                type="primary"
                onClick={() => previewMutation.mutate()}
                disabled={previewMutation.isPending || !importText.trim()}
              >
                {previewMutation.isPending ? '预览中…' : '预览'}
              </Button>
            ) : (
              <Button type="primary" onClick={() => commit.mutate()} disabled={commit.isPending}>
                {commit.isPending ? '导入中…' : `确认导入 ${preview.unique} 条`}
              </Button>
            )}
          </div>
        }
      >
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            每行一个名称，也支持逗号分隔；先预览去重与库内对账，确认后才写库（15 分钟内有效）
          </p>

          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">类型</label>
              <Select
                value={importKind}
                onChange={(v) => setImportKind(v)}
                options={digitalKinds}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">公司（可选）</label>
              <Input value={company} onChange={(e) => setCompany(e.target.value)} />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">平台（可选）</label>
              <Input value={platform} onChange={(e) => setPlatform(e.target.value)} />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">名单</label>
            <Input.TextArea
              className="font-mono text-sm"
              rows={6}
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
                <Tag>总计 {preview.total}</Tag>
                <Tag className={badgeCls('secondary')}>可导入 {preview.unique}</Tag>
                <Tag>批内重复 {preview.duplicates}</Tag>
                <Tag>库内已有 {preview.existing}</Tag>
                <Tag>无效 {preview.invalid}</Tag>
              </div>
              <div className="text-xs text-muted-foreground">
                示例：{preview.sample.map((s) => s.name).join('、') || '—'}
              </div>
            </div>
          )}
        </div>
      </Modal>
    </div>
  )
}

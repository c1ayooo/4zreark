import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Eye, Paperclip, Plus, RefreshCw, Trash2, Upload } from 'lucide-react'
import { Button, Input, Modal, Select, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'

import {
  dictionaryApi,
  dictionaryTypes,
  type Dictionary,
  type DictionaryPreview,
} from '@/api/sources'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import EmptyState from '@/components/common/EmptyState'
import { formatDate } from '@/lib/utils'
import DictLearningPanel from './components/DictLearningPanel'

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

  const columns: TableProps<Dictionary>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (v: string) => <span className="text-sm">{v}</span>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 120,
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '行数',
      dataIndex: 'line_count',
      key: 'line_count',
      width: 110,
      render: (v: number) => <span className="text-sm tabular-nums">{v.toLocaleString()}</span>,
    },
    {
      title: '来源',
      dataIndex: 'is_builtin',
      key: 'is_builtin',
      width: 90,
      render: (v: boolean) =>
        v ? (
          <Tag className="border-transparent bg-secondary text-secondary-foreground">内置</Tag>
        ) : (
          <Tag>导入</Tag>
        ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 170,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{formatDate(v)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      render: (_, d) => (
        <div className="flex gap-1">
          <Button size="small" onClick={() => { setEntriesOf(d); setEntryPage(1) }}>
            <Eye className="mr-1 h-3.5 w-3.5" /> 条目
          </Button>
          <Button
            type="text"
            danger
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
              if (await confirm(`删除字典 ${d.name}？`)) remove.mutate(d.id)
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
          <h1 className="text-2xl font-semibold">字典</h1>
          <p className="text-sm text-muted-foreground">
            词表两段式导入：预览 15 分钟有效，按 5 万行一段物化；被种子引用的字典不可删除。
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button type="primary" onClick={() => setImportOpen(true)}>
            <Upload className="mr-2 h-4 w-4" /> 导入词表
          </Button>
        </div>
      </div>

      <Tabs
        defaultActiveKey="dicts"
        items={[
          {
            key: 'dicts',
            label: '词表',
            children: (
              <div className="space-y-4">
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
                  <Table<Dictionary>
                    columns={columns}
                    dataSource={items}
                    rowKey="id"
                    loading={list.isLoading}
                    locale={{
                      emptyText: (
                        <EmptyState
                          title="还没有字典。点右上角「导入词表」，预览确认后入库。"
                          className="border-0"
                        />
                      ),
                    }}
                    pagination={{
                      current: page,
                      pageSize,
                      total,
                      showQuickJumper: true,
                      // page_size 固定 20、无独立 pageSize 状态，不展示切换器
                      showSizeChanger: false,
                      hideOnSinglePage: true,
                      onChange: (p) => setPage(p),
                    }}
                  />
                </div>
              </div>
            ),
          },
          {
            key: 'learning',
            label: '自动学习',
            children: <DictLearningPanel />,
          },
        ]}
      />

      {/* 导入词表 */}
      <Modal
        open={importOpen}
        title="导入词表"
        width={672}
        onCancel={() => { setImportOpen(false); setPreview(null) }}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setImportOpen(false)}>取消</Button>
            <Button
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
              type="primary"
              onClick={() => preview && importMutation.mutate(preview.token)}
              disabled={!preview || importMutation.isPending}
            >
              确认导入
            </Button>
          </div>
        }
      >
        <div className="space-y-3 py-2">
          <div className="grid grid-cols-3 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">名称 *</label>
              <Input
                value={name}
                onChange={(e) => { setName(e.target.value); setPreview(null) }}
                placeholder="例如：常用子域-2026"
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">类型</label>
              <Select
                value={dictType}
                onChange={(v) => { setDictType(v); setPreview(null) }}
                options={dictionaryTypes.map((t) => ({ value: t, label: t }))}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">格式</label>
              <Select
                value={format}
                onChange={(v) => { setFormat(v); setPreview(null) }}
                options={[
                  { value: 'text', label: '文本（每行一条）' },
                  { value: 'csv', label: 'CSV（取第一列）' },
                  { value: 'tsv', label: 'TSV（取第一列）' },
                  { value: 'xlsx', label: 'Excel（.xlsx，取第一列）' },
                ]}
              />
            </div>
          </div>
          {format === 'xlsx' ? (
            <div className="space-y-1">
              <label className="text-sm font-medium">词表文件（取第一列，首行表头自动跳过）</label>
              {/* 原生 file 控件不可样式化，隐藏后由按钮触发，与其它上传入口保持一致 */}
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
                <Button
                  size="small"
                  onClick={() => document.getElementById('dict-xlsx-file')?.click()}
                >
                  <Paperclip className="mr-2 h-4 w-4" />
                  选择文件
                </Button>
                <p className="text-xs text-muted-foreground">
                  {xlsxFile ? xlsxFile.name : '选择一个 .xlsx 文件'}
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-1">
              <label className="text-sm font-medium">词表（每行一条）</label>
              <Input.TextArea
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
      </Modal>

      {/* 条目 */}
      <Modal
        open={!!entriesOf}
        title={`${entriesOf?.name} · 词表条目`}
        width={576}
        onCancel={() => setEntriesOf(null)}
        footer={
          <div className="flex items-center justify-between">
            <span className="text-xs text-muted-foreground">
              共 {entries.data?.total ?? 0} 条 · 第 {entryPage} 页
            </span>
            <div className="flex gap-2">
              <Button size="small" disabled={entryPage <= 1} onClick={() => setEntryPage(entryPage - 1)}>
                上一页
              </Button>
              <Button
                size="small"
                disabled={(entries.data?.total ?? 0) <= entryPage * 100}
                onClick={() => setEntryPage(entryPage + 1)}
              >
                下一页
              </Button>
            </div>
          </div>
        }
      >
        <div className="max-h-[50vh] overflow-auto rounded border p-3 font-mono text-sm">
          {(entries.data?.data ?? []).map((v) => (
            <div key={v} className="border-b py-0.5 last:border-0">{v}</div>
          ))}
          {entries.isLoading && <div className="text-muted-foreground">加载中…</div>}
          {!entries.isLoading && (entries.data?.data ?? []).length === 0 && (
            <div className="text-muted-foreground">没有条目</div>
          )}
        </div>
      </Modal>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, RotateCcw, Save, Sparkles } from 'lucide-react'
import { Button, InputNumber, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import {
  dictLearningApi,
  type DictLearningConfig,
  type DictLearningEntry,
  type DictLearningKind,
} from '@/api/dictLearning'
import { useToast } from '@/components/ui/use-toast'
import EmptyState from '@/components/common/EmptyState'
import { formatDate } from '@/lib/utils'

const kindLabels: Record<string, string> = {
  subdomain: '子域热词',
  path: '路径热词',
}

// 字典自学习面板：开关 + 晋升阈值 + 学习条目表格。
// 阈值语义：多少个不同任务观察到该词后自动晋升进词表（随任务下发，追加不替代）。
export default function DictLearningPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<'' | DictLearningKind>('')
  const [page, setPage] = useState(1)
  const pageSize = 20

  const cfg = useQuery({ queryKey: ['dict-learning-config'], queryFn: dictLearningApi.config })
  const [draft, setDraft] = useState<DictLearningConfig | null>(null)
  const config = draft ?? cfg.data?.data ?? null

  const entries = useQuery({
    queryKey: ['dict-learning', kind, page],
    queryFn: () => dictLearningApi.list({ kind: kind || undefined, page, page_size: pageSize }),
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['dict-learning'] })
  }

  const saveMutation = useMutation({
    mutationFn: (c: DictLearningConfig) => dictLearningApi.saveConfig(c),
    onSuccess: () => {
      toast({ title: '自学习配置已保存' })
      setDraft(null)
      queryClient.invalidateQueries({ queryKey: ['dict-learning-config'] })
    },
    onError: (e: any) => toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const denyMutation = useMutation({
    mutationFn: ({ id, denied }: { id: number; denied: boolean }) => dictLearningApi.setDenied(id, denied),
    onSuccess: () => invalidate(),
    onError: (e: any) => toast({ title: '操作失败', description: e?.message, variant: 'destructive' }),
  })

  const columns: TableProps<DictLearningEntry>['columns'] = [
    {
      title: '词',
      dataIndex: 'value',
      key: 'value',
      render: (v: string, e) => (
        <span className="break-all font-mono text-sm">
          {v}
          {e.kind === 'path' && <span className="ml-1 text-xs text-muted-foreground">（路径）</span>}
        </span>
      ),
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 100,
      render: (v: string) => <Tag className="font-mono text-xs">{kindLabels[v] ?? v}</Tag>,
    },
    {
      title: '出现任务数',
      dataIndex: 'hits',
      key: 'hits',
      width: 110,
      align: 'right',
      sorter: (a, b) => a.hits - b.hits,
      render: (v: number) => <span className="tabular-nums text-sm">{v}</span>,
    },
    {
      title: '状态',
      key: 'status',
      width: 110,
      render: (_, e) =>
        e.denied ? (
          <Tag className="border-destructive/40 bg-destructive/10 text-destructive">已剔除</Tag>
        ) : e.promoted_at ? (
          <Tag className="border-transparent bg-green-500/15 text-green-600">已入词表</Tag>
        ) : (
          <Tag>观察中</Tag>
        ),
    },
    {
      title: '最近出现',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 120,
      render: (v: string) => <span className="text-xs text-muted-foreground">{formatDate(v)}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      render: (_, e) =>
        e.denied ? (
          <Button
            size="small"
            icon={<RotateCcw className="h-3.5 w-3.5" />}
            onClick={() => denyMutation.mutate({ id: e.id, denied: false })}
          >
            恢复
          </Button>
        ) : (
          <Button
            size="small"
            danger
            type="text"
            icon={<Ban className="h-4 w-4" />}
            title="剔除后不再计频、不再进词表"
            onClick={() => denyMutation.mutate({ id: e.id, denied: true })}
          />
        ),
    },
  ]

  const data = entries.data?.data
  const dirty =
    config != null && cfg.data?.data != null && JSON.stringify(config) !== JSON.stringify(cfg.data.data)

  return (
    <div className="space-y-4">
      <div className="rounded-md border bg-muted/20 p-4">
        <div className="flex items-start gap-2">
          <Sparkles className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
          <div className="text-sm text-muted-foreground">
            扫描任务里反复出现的子域标签与接口路径会被自动记频；达到阈值的词晋升进词表，
            之后每个任务（内置词表、任务级字典之外）都会额外尝试这些热词。<b>只追加，不替代</b>现有字典。
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center gap-6">
          <label className="flex items-center gap-2 text-sm">
            <Switch
              checked={config?.enabled ?? false}
              onChange={(v) => setDraft({ ...(config as DictLearningConfig), enabled: v })}
            />
            启用自动学习
          </label>
          <label className="flex items-center gap-2 text-sm">
            子域晋升阈值
            <InputNumber
              size="small"
              min={1}
              max={500}
              value={config?.subdomain_min_hits ?? 3}
              onChange={(v) => setDraft({ ...(config as DictLearningConfig), subdomain_min_hits: Number(v) || 1 })}
              className="w-[90px]"
            />
            个任务
          </label>
          <label className="flex items-center gap-2 text-sm">
            路径晋升阈值
            <InputNumber
              size="small"
              min={1}
              max={500}
              value={config?.path_min_hits ?? 3}
              onChange={(v) => setDraft({ ...(config as DictLearningConfig), path_min_hits: Number(v) || 1 })}
              className="w-[90px]"
            />
            个任务
          </label>
          <Button
            size="small"
            type="primary"
            icon={<Save className="h-3.5 w-3.5" />}
            disabled={!dirty || saveMutation.isPending}
            loading={saveMutation.isPending}
            onClick={() => config && saveMutation.mutate(config)}
          >
            保存配置
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {([
          ['', '全部'],
          ['subdomain', '子域热词'],
          ['path', '路径热词'],
        ] as const).map(([v, label]) => (
          <button
            key={v}
            className={
              'rounded-full border px-3 py-1 text-sm ' +
              (kind === v ? 'border-primary bg-primary/10 text-primary' : 'text-muted-foreground hover:bg-muted')
            }
            onClick={() => {
              setKind(v as '' | DictLearningKind)
              setPage(1)
            }}
          >
            {label}
          </button>
        ))}
        <span className="ml-auto text-sm text-muted-foreground">共 {data?.total ?? 0} 条</span>
      </div>

      <div className="rounded-md border">
        <Table<DictLearningEntry>
          columns={columns}
          dataSource={data?.items ?? []}
          rowKey="id"
          loading={entries.isLoading}
          size="small"
          locale={{
            emptyText: (
              <EmptyState
                title="还没有学习到热词。跑几个扫描任务后，反复出现的子域标签和路径会出现在这里。"
                className="border-0"
              />
            ),
          }}
          pagination={{
            current: page,
            pageSize,
            total: data?.total ?? 0,
            showSizeChanger: false,
            hideOnSinglePage: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>
    </div>
  )
}

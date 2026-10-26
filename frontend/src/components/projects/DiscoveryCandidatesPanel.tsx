import { useMemo, useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Card, Checkbox, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Radar, Search } from 'lucide-react'
import {
  discoveryApi,
  type CandidateStatus,
  type DiscoveryCandidate,
} from '@/api/discovery'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const candidateKindLabel: Record<string, string> = {
  domain: '域名',
  cidr: '网段',
  company: '公司',
  cert: '证书组织',
  repo: '代码仓库',
  app: '应用',
}

const sourceLabel: Record<string, string> = {
  crtsh: '证书透明日志',
  engine: '测绘引擎',
}

const STATUS_OPTIONS: { value: CandidateStatus; label: string }[] = [
  { value: 'pending', label: '待处理' },
  { value: 'accepted', label: '已接受' },
  { value: 'rejected', label: '已拒绝' },
]

const confidenceVariant = (confidence: number) => {
  if (confidence >= 80) return 'border-transparent bg-emerald-600 text-white'
  if (confidence >= 60) return 'border-transparent bg-blue-500 text-white'
  return 'border-transparent bg-secondary text-secondary-foreground'
}

const { CheckableTag } = Tag

export function DiscoveryCandidatesPanel({ projectId }: { projectId: number }) {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<CandidateStatus>('pending')
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([])
  // 快速过滤：来源 / 置信度分层 / 关键词，均为前端内存过滤（候选最多 500 条）
  const [sourceFilter, setSourceFilter] = useState<string>('all')
  const [tierFilter, setTierFilter] = useState<'all' | 'high' | 'mid' | 'low'>('all')
  const [keyword, setKeyword] = useState('')

  const candidatesQuery = useQuery({
    queryKey: ['project-candidates', projectId, status],
    // 后端 limit 上限 500，拉满才能保证全选覆盖全部待处理候选
    queryFn: () => discoveryApi.candidates(projectId, status, 500),
  })
  const items = candidatesQuery.data?.data?.items ?? []
  // pending 数与 status 过滤无关，接口始终返回，拿来做标题角标
  const pendingCount = candidatesQuery.data?.data?.pending ?? 0

  const sourceCounts = useMemo(() => {
    const m: Record<string, number> = {}
    for (const c of items) m[c.source] = (m[c.source] ?? 0) + 1
    return m
  }, [items])

  const tierCounts = useMemo(() => {
    const m = { high: 0, mid: 0, low: 0 }
    for (const c of items) {
      if (c.confidence >= 80) m.high += 1
      else if (c.confidence >= 60) m.mid += 1
      else m.low += 1
    }
    return m
  }, [items])

  const filteredItems = useMemo(() => {
    const kw = keyword.trim().toLowerCase()
    return items.filter((c) => {
      if (sourceFilter !== 'all' && c.source !== sourceFilter) return false
      if (tierFilter === 'high' && c.confidence < 80) return false
      if (tierFilter === 'mid' && (c.confidence < 60 || c.confidence >= 80)) return false
      if (tierFilter === 'low' && c.confidence >= 60) return false
      if (kw && !c.value.toLowerCase().includes(kw)) return false
      return true
    })
  }, [items, sourceFilter, tierFilter, keyword])

  const resetFilters = () => {
    setSourceFilter('all')
    setTierFilter('all')
    setKeyword('')
  }

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['project-candidates', projectId] })
    queryClient.invalidateQueries({ queryKey: ['project', projectId] })
    queryClient.invalidateQueries({ queryKey: ['project-cruise-status', projectId] })
  }

  const decideMutation = useMutation({
    mutationFn: ({ ids, accept }: { ids: number[]; accept: boolean }) =>
      discoveryApi.decide(projectId, ids, accept),
    onSuccess: (_res, { ids, accept }) => {
      toast({
        title: accept
          ? `已接受 ${ids.length} 个候选（已转为项目种子）`
          : `已拒绝 ${ids.length} 个候选`,
      })
      setSelectedKeys([])
      refresh()
    },
    onError: (e: Error) =>
      toast({ title: '处理失败', description: e.message, variant: 'destructive' }),
  })

  const runMutation = useMutation({
    mutationFn: () => discoveryApi.runDiscovery(projectId),
    onSuccess: (res) => {
      const s = res.data
      toast({
        title: `发现轮完成，新增 ${s?.new_count ?? 0} 个候选`,
        description: `来源 ${s?.sources ?? 0} 个 · 证书透明日志 ${s?.from_ctlog ?? 0} · 测绘引擎 ${s?.from_engines ?? 0}`,
      })
      refresh()
    },
    onError: (e: Error) =>
      toast({ title: '手动发现失败', description: e.message, variant: 'destructive' }),
  })

  const selectedIds = selectedKeys.map(Number).filter((n) => Number.isFinite(n))
  // 行键即候选 id，必须保持数字类型，字符串键在 antd 里匹配不到任何行
  const allIds = filteredItems.map((c) => c.id)
  const selectedIdSet = new Set(selectedIds)
  const allSelected = allIds.length > 0 && allIds.every((id) => selectedIdSet.has(id))
  const someSelected = selectedIds.length > 0 && !allSelected

  const toggleSelectAll = () => {
    setSelectedKeys(allSelected ? [] : allIds)
  }

  const handleAccept = () => {
    if (selectedIds.length === 0) return
    decideMutation.mutate({ ids: selectedIds, accept: true })
  }

  const handleReject = async () => {
    if (selectedIds.length === 0) return
    const ok = await confirm({
      title: `拒绝这 ${selectedIds.length} 个候选？`,
      description: '拒绝后不再进入项目种子；后续同一候选也不会重复冒出来。',
      confirmText: '拒绝',
      destructive: true,
    })
    if (!ok) return
    decideMutation.mutate({ ids: selectedIds, accept: false })
  }

  // 单行快捷处理：接受直达，拒绝过一道确认（与批量拒绝口径一致）
  const handleRejectOne = async (id: number) => {
    const ok = await confirm({
      title: '拒绝这个候选？',
      description: '拒绝后不再进入项目种子；后续同一候选也不会重复冒出来。',
      confirmText: '拒绝',
      destructive: true,
    })
    if (!ok) return
    decideMutation.mutate({ ids: [id], accept: false })
  }

  const isDeciding = (id: number, accept: boolean) =>
    decideMutation.isPending &&
    decideMutation.variables?.ids?.includes(id) === true &&
    decideMutation.variables?.accept === accept

  const columns: TableProps<DiscoveryCandidate>['columns'] = [
    {
      title: '值',
      dataIndex: 'value',
      key: 'value',
      render: (_, c) => (
        <span className="block max-w-[560px] truncate font-mono text-xs">{c.value}</span>
      ),
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 90,
      render: (_, c) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {candidateKindLabel[c.kind] ?? c.kind}
        </span>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 120,
      render: (_, c) => <Tag>{sourceLabel[c.source] ?? c.source}</Tag>,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      key: 'confidence',
      width: 90,
      render: (_, c) => (
        <Tag className={confidenceVariant(c.confidence)}>{c.confidence}%</Tag>
      ),
    },
    {
      title: '发现时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (_, c) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {formatDate(c.created_at)}
        </span>
      ),
    },
    ...(status === 'pending'
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 96,
            align: 'right' as const,
            render: (_: unknown, c: DiscoveryCandidate) => (
              <div className="flex justify-end gap-2">
                <Button
                  type="link"
                  size="small"
                  className="h-auto p-0"
                  loading={isDeciding(c.id, true)}
                  disabled={decideMutation.isPending && !isDeciding(c.id, true)}
                  onClick={() => decideMutation.mutate({ ids: [c.id], accept: true })}
                >
                  接受
                </Button>
                <Button
                  type="link"
                  size="small"
                  className="text-destructive h-auto p-0"
                  loading={isDeciding(c.id, false)}
                  disabled={decideMutation.isPending && !isDeciding(c.id, false)}
                  onClick={() => handleRejectOne(c.id)}
                >
                  拒绝
                </Button>
              </div>
            ),
          },
        ]
      : [
          {
            title: '处理时间',
            dataIndex: 'decided_at',
            key: 'decided_at',
            width: 150,
            render: (_: unknown, c: DiscoveryCandidate) => (
              <span className="text-muted-foreground whitespace-nowrap text-xs">
                {c.decided_at ? formatDate(c.decided_at) : '—'}
              </span>
            ),
          },
        ]),
  ]

  const rowSelection = {
    selectedRowKeys: selectedKeys,
    onChange: (keys: Key[]) => setSelectedKeys(keys),
    columnWidth: 48,
    // antd 默认表头全选只勾当前页，这里换成跨页全选
    columnTitle: (
      <Checkbox
        aria-label="全选候选"
        checked={allSelected}
        indeterminate={someSelected}
        onChange={toggleSelectAll}
      />
    ),
  }

  return (
    <Card
      title={
        <div className="flex flex-col gap-1">
          <span className="flex items-center gap-2">
            发现候选
            {pendingCount > 0 && <Badge count={pendingCount} size="small" />}
          </span>
          <span className="text-xs font-normal leading-relaxed text-muted-foreground">
            从证书透明日志与测绘引擎自动发现的疑似资产；接受后转为项目种子，进入常规采集。
          </span>
        </div>
      }
    >
      <div className="flex flex-wrap items-center gap-2">
        <Select
          size="small"
          value={status}
          onChange={(v) => {
            setStatus(v as CandidateStatus)
            setSelectedKeys([])
            resetFilters()
          }}
          options={STATUS_OPTIONS}
          className="w-28"
        />
        {status === 'pending' && (
          <>
            <Button
              type="primary"
              size="small"
              disabled={selectedIds.length === 0}
              loading={decideMutation.isPending && decideMutation.variables?.accept === true}
              onClick={handleAccept}
            >
              批量接受{selectedIds.length > 0 ? `（${selectedIds.length}）` : ''}
            </Button>
            <Button
              danger
              size="small"
              disabled={selectedIds.length === 0}
              onClick={handleReject}
            >
              批量拒绝
            </Button>
          </>
        )}
        <div className="flex-1" />
        <Input
          size="small"
          allowClear
          prefix={<Search className="h-3.5 w-3.5 opacity-50" />}
          placeholder="搜索候选值"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          className="w-44"
        />
        <Button
          size="small"
          icon={<Radar className="h-3.5 w-3.5" />}
          loading={runMutation.isPending}
          onClick={() => runMutation.mutate()}
        >
          手动发现一轮
        </Button>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-1 gap-y-1">
        <span className="text-muted-foreground mr-1 text-xs">来源</span>
        <CheckableTag checked={sourceFilter === 'all'} onChange={() => setSourceFilter('all')}>
          全部 {items.length}
        </CheckableTag>
        <CheckableTag
          checked={sourceFilter === 'crtsh'}
          onChange={() => setSourceFilter(sourceFilter === 'crtsh' ? 'all' : 'crtsh')}
        >
          证书透明 {sourceCounts.crtsh ?? 0}
        </CheckableTag>
        <CheckableTag
          checked={sourceFilter === 'engine'}
          onChange={() => setSourceFilter(sourceFilter === 'engine' ? 'all' : 'engine')}
        >
          测绘引擎 {sourceCounts.engine ?? 0}
        </CheckableTag>
        <span className="bg-border mx-2 h-4 w-px" />
        <span className="text-muted-foreground mr-1 text-xs">置信度</span>
        <CheckableTag checked={tierFilter === 'all'} onChange={() => setTierFilter('all')}>
          不限
        </CheckableTag>
        <CheckableTag
          checked={tierFilter === 'high'}
          onChange={() => setTierFilter(tierFilter === 'high' ? 'all' : 'high')}
        >
          高 ≥80% {tierCounts.high}
        </CheckableTag>
        <CheckableTag
          checked={tierFilter === 'mid'}
          onChange={() => setTierFilter(tierFilter === 'mid' ? 'all' : 'mid')}
        >
          中 60–79% {tierCounts.mid}
        </CheckableTag>
        <CheckableTag
          checked={tierFilter === 'low'}
          onChange={() => setTierFilter(tierFilter === 'low' ? 'all' : 'low')}
        >
          低 &lt;60% {tierCounts.low}
        </CheckableTag>
      </div>
      <Table<DiscoveryCandidate>
        className="mt-3"
        columns={columns}
        dataSource={filteredItems}
        rowKey="id"
        rowSelection={rowSelection}
        loading={candidatesQuery.isLoading}
        size="small"
        locale={{ emptyText: '没有符合当前条件的候选' }}
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
      />
    </Card>
  )
}

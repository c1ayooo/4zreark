import { useState, type Key } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Card, Select, Skeleton, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Radar } from 'lucide-react'
import {
  discoveryApi,
  type CandidateStatus,
  type DiscoveryCandidate,
} from '@/api/discovery'
import { seedCollectionApi, type CruiseStatus } from '@/api/seedCollection'
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

export function DiscoveryCandidatesPanel({ projectId }: { projectId: number }) {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [status, setStatus] = useState<CandidateStatus>('pending')
  const [selectedKeys, setSelectedKeys] = useState<Key[]>([])

  const candidatesQuery = useQuery({
    queryKey: ['project-candidates', projectId, status],
    queryFn: () => discoveryApi.candidates(projectId, status),
  })
  // 巡航状态：最近发现轮 + 站点巡检汇总（查询失败时整行隐藏）
  const cruiseStatusQuery = useQuery({
    queryKey: ['project-cruise-status', projectId],
    queryFn: () => seedCollectionApi.cruiseStatus(projectId),
  })
  const cruise: CruiseStatus | undefined = cruiseStatusQuery.data?.data
  const items = candidatesQuery.data?.data?.items ?? []
  // pending 数与 status 过滤无关，接口始终返回，拿来做标题角标
  const pendingCount = candidatesQuery.data?.data?.pending ?? 0

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

  const columns: TableProps<DiscoveryCandidate>['columns'] = [
    {
      title: '值',
      dataIndex: 'value',
      key: 'value',
      render: (_, c) => (
        <div className="flex items-baseline gap-2">
          <span className="max-w-[280px] truncate font-mono text-xs">{c.value}</span>
          <span className="text-muted-foreground text-[11px]">
            {candidateKindLabel[c.kind] ?? c.kind}
          </span>
        </div>
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
  ]

  const rowSelection = {
    selectedRowKeys: selectedKeys,
    onChange: (keys: Key[]) => setSelectedKeys(keys.map(String)),
    columnWidth: 48,
  }

  return (
    <Card
      title={
        <div className="flex flex-col gap-1">
          <span className="flex items-center gap-2">
            发现候选
            {pendingCount > 0 && <Badge count={pendingCount} size="small" />}
          </span>
          {!cruiseStatusQuery.isError && (
            <div className="text-xs font-normal leading-relaxed text-muted-foreground">
              {cruiseStatusQuery.isLoading || !cruise ? (
                <Skeleton
                  className="mt-0.5"
                  active
                  title={false}
                  paragraph={{ rows: 1, width: '72%' }}
                />
              ) : (
                `最近发现轮: ${
                  cruise.discovery
                    ? `${formatDate(cruise.discovery.ran_at)} · 证书透明 ${cruise.discovery.from_ctlog} / 引擎 ${cruise.discovery.from_engines} / 新增 ${cruise.discovery.new_count}`
                    : '尚未运行'
                } · 站点巡检: 可达 ${cruise.watch.reachable} · 24h 已查 ${cruise.watch.checked_24h} · 累计变更 ${cruise.watch.changed_total}`
              )}
            </div>
          )}
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
        <Button
          size="small"
          icon={<Radar className="h-3.5 w-3.5" />}
          loading={runMutation.isPending}
          onClick={() => runMutation.mutate()}
        >
          手动发现一轮
        </Button>
      </div>
      <Table<DiscoveryCandidate>
        className="mt-3"
        columns={columns}
        dataSource={items}
        rowKey="id"
        rowSelection={rowSelection}
        loading={candidatesQuery.isLoading}
        size="small"
        pagination={{ pageSize: 10, hideOnSinglePage: true }}
      />
    </Card>
  )
}

import { useEffect, useState } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { Building2, DownloadCloud, FileSearch, GitBranch, Link2, Plus, RefreshCw, Trash2, Upload } from 'lucide-react'
import { Button, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { projectApi } from '@/api/projects'
import {
  enterpriseApi,
  enterpriseStatusLabel,
  type EnterpriseEntity,
  type EnterpriseJob,
  type EnterpriseCandidate,
  type EnterpriseProvider,
} from '@/api/enterprise'
import { icpApi, type ICPQuery } from '@/api/icp'
import { useConfirm } from '@/components/common/confirm-provider'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { statusTagClass } from '@/components/ui/StatusTag'
import {
  AlignedAssetsModal,
  CollectModal,
  CreateEntityModal,
  DeepCollectModal,
  IcpResultModal,
  ImportEntitiesModal,
} from './components/modals'

const PAGE_SIZE = 50


// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass

export default function EnterprisePage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [projectId, setProjectId] = useState('0')
  const [q, setQ] = useState('')
  // 防抖后才是真正发请求的关键词：逐键输入不再每字符打一次后端
  const debouncedQ = useDebouncedValue(q)
  useEffect(() => { setPage(1) }, [debouncedQ])
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)

  const [open, setOpen] = useState(false)
  const [importOpen, setImportOpen] = useState(false)
  const [collectOpen, setCollectOpen] = useState(false)
  const [deepOpen, setDeepOpen] = useState(false)
  const [candStatus, setCandStatus] = useState('')
  const [icpInput, setIcpInput] = useState('')
  const [icpSelected, setIcpSelected] = useState<string | null>(null)
  const [aligned, setAligned] = useState<EnterpriseEntity | null>(null)

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const list = useQuery({
    queryKey: ['enterprise-entities', projectId, debouncedQ, status, page],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      enterpriseApi.list({
        project_id: Number(projectId) || undefined,
        q: debouncedQ || undefined,
        status: status || undefined,
        page,
        page_size: PAGE_SIZE,
      }),
  })
  const providers = useQuery({
    queryKey: ['enterprise-providers'],
    queryFn: () => enterpriseApi.providers(),
    enabled: collectOpen || deepOpen,
  })
  const jobs = useQuery({
    queryKey: ['enterprise-jobs', projectId],
    queryFn: () => enterpriseApi.jobs(Number(projectId) || undefined, 30),
    enabled: Number(projectId) > 0,
    refetchInterval: (query) =>
      (query.state.data?.data?.items ?? []).some((j) => j.status === 'running') ? 3000 : false,
  })
  const candidates = useQuery({
    queryKey: ['enterprise-candidates', projectId, candStatus],
    queryFn: () => enterpriseApi.candidates(Number(projectId) || undefined, candStatus, 200),
    enabled: Number(projectId) > 0,
    refetchInterval: (jobs.data?.data?.items ?? []).some((j) => j.status === 'running')
      ? 3000
      : false,
  })
  const icpQueries = useQuery({
    queryKey: ['icp-queries', projectId],
    queryFn: () => icpApi.list(Number(projectId) || undefined, 30),
    enabled: Number(projectId) > 0,
    refetchInterval: (query) =>
      (query.state.data?.data?.items ?? []).some(
        (q) => q.status === 'queued' || q.status === 'running'
      )
        ? 3000
        : false,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
    queryClient.invalidateQueries({ queryKey: ['enterprise-aligned'] })
  }

  const remove = useMutation({
    mutationFn: (id: number) => enterpriseApi.remove(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const cancelJob = useMutation({
    mutationFn: (id: string) => enterpriseApi.cancelJob(id),
    onSuccess: () => {
      toast({ title: '已请求取消' })
      queryClient.invalidateQueries({ queryKey: ['enterprise-jobs'] })
    },
    onError: (e: any) =>
      toast({ title: '取消失败', description: e?.message, variant: 'destructive' }),
  })

  const enqueueICP = useMutation({
    mutationFn: () => {
      if (Number(projectId) <= 0) throw new Error('先选择归属项目')
      return icpApi.enqueue({
        project_id: Number(projectId),
        query: icpInput.trim(),
        service_type: 1,
        page_size: 40,
      })
    },
    onSuccess: () => {
      toast({ title: '备案查询已入队', description: '官方站限速，单次查询约 15–60 秒' })
      setIcpInput('')
      queryClient.invalidateQueries({ queryKey: ['icp-queries'] })
    },
    onError: (e: any) =>
      toast({ title: '查询失败', description: e?.message, variant: 'destructive' }),
  })

  const cancelICP = useMutation({
    mutationFn: (id: string) => icpApi.cancel(id),
    onSuccess: () => {
      toast({ title: '已请求取消' })
      queryClient.invalidateQueries({ queryKey: ['icp-queries'] })
    },
    onError: (e: any) =>
      toast({ title: '取消失败', description: e?.message, variant: 'destructive' }),
  })

  const items = list.data?.data ?? []
  const total = list.data?.total ?? 0
  const projectName = (id: number) =>
    projects.data?.data?.find((p) => p.id === id)?.name ?? `#${id}`
  const canEdit = Number(projectId) > 0
  const providerList: EnterpriseProvider[] = providers.data?.data?.items ?? []
  const jobItems = jobs.data?.data?.items ?? []
  const candidateItems = candidates.data?.data?.items ?? []
  const icpItems = icpQueries.data?.data?.items ?? []
  const icpStatusLabel: Record<string, string> = {
    queued: '排队中',
    running: '查询中',
    done: '已完成',
    error: '失败',
    canceled: '已取消',
  }
  const jobStatusLabel: Record<string, string> = {
    running: '采集中',
    done: '已完成',
    error: '失败',
    canceled: '已取消',
  }

  const entityColumns: TableProps<EnterpriseEntity>['columns'] = [
    {
      title: '企业名',
      dataIndex: 'name',
      key: 'name',
      render: (_, e) => (
        <div className="text-sm font-medium">
          {e.name}
          {e.project_id > 0 && (
            <span className="ml-2 text-xs text-muted-foreground">{projectName(e.project_id)}</span>
          )}
        </div>
      ),
    },
    {
      title: '统一信用代码',
      dataIndex: 'credit_code',
      key: 'credit_code',
      width: 170,
      render: (_, e) => <span className="font-mono text-xs">{e.credit_code || '—'}</span>,
    },
    {
      title: '法人',
      dataIndex: 'legal_person',
      key: 'legal_person',
      width: 100,
      render: (_, e) => <span className="text-sm">{e.legal_person || '—'}</span>,
    },
    {
      title: '注册资本',
      dataIndex: 'registered_capital',
      key: 'registered_capital',
      width: 130,
      sorter: (a, b) => (a.registered_capital_wan || 0) - (b.registered_capital_wan || 0),
      render: (_, e) =>
        e.registered_capital ? (
          <span className="text-sm" title={`约 ${e.registered_capital_wan || 0} 万元`}>
            {e.registered_capital}
          </span>
        ) : (
          <span className="text-sm text-muted-foreground">—</span>
        ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, e) => (
        <Tag className={badgeCls(e.status === 'verified' ? 'secondary' : 'outline')}>
          {enterpriseStatusLabel[e.status] ?? e.status}
        </Tag>
      ),
    },
    {
      title: '备案域名',
      dataIndex: 'domains',
      key: 'domains',
      width: 90,
      render: (_, e) => <span className="text-sm">{e.domains?.length ?? 0}</span>,
    },
    {
      title: '对齐 APP',
      dataIndex: 'digital_count',
      key: 'digital_count',
      width: 90,
      render: (_, e) => <span className="text-sm">{e.digital_count}</span>,
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 90,
      render: (_, e) => <span className="text-xs text-muted-foreground">{e.source || '—'}</span>,
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      key: 'updated_at',
      width: 150,
      render: (_, e) => (
        <span className="text-xs text-muted-foreground">{formatDate(e.updated_at)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 120,
      render: (_, e) => (
        <div className="flex items-center gap-1">
          <Button
            type="text"
            size="small"
            title="对齐名单"
            icon={<Link2 className="h-4 w-4" />}
            onClick={() => setAligned(e)}
          />
          <Button
            type="text"
            size="small"
            title="删除"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
              if (await confirm(`删除企业线索「${e.name}」？`)) remove.mutate(e.id)
            }}
          />
        </div>
      ),
    },
  ]

  const jobColumns: TableProps<EnterpriseJob>['columns'] = [
    {
      title: '任务',
      dataIndex: 'id',
      key: 'id',
      width: 90,
      render: (_, j) => (
        <span className="font-mono text-xs" title={j.id}>
          {j.id.slice(-6)}
        </span>
      ),
    },
    {
      title: '来源',
      dataIndex: 'provider',
      key: 'provider',
      width: 90,
      render: (_, j) => <span className="text-xs">{j.provider}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, j) => (
        <Tag
          className={badgeCls(
            j.status === 'error' ? 'destructive' : j.status === 'running' ? 'default' : 'outline'
          )}
          title={j.error || undefined}
        >
          {jobStatusLabel[j.status] ?? j.status}
        </Tag>
      ),
    },
    {
      title: '节点',
      dataIndex: 'nodes',
      key: 'nodes',
      width: 70,
      render: (_, j) => <span className="text-sm">{j.nodes}</span>,
    },
    {
      title: '实体',
      dataIndex: 'entities',
      key: 'entities',
      width: 70,
      render: (_, j) => <span className="text-sm">{j.entities}</span>,
    },
    {
      title: '域名',
      dataIndex: 'domains',
      key: 'domains',
      width: 70,
      render: (_, j) => <span className="text-sm">{j.domains}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 70,
      render: (_, j) =>
        j.status === 'running' ? (
          <Button size="small" onClick={() => cancelJob.mutate(j.id)}>
            取消
          </Button>
        ) : null,
    },
  ]

  const candidateColumns: TableProps<EnterpriseCandidate>['columns'] = [
    {
      title: '域名',
      dataIndex: 'value',
      key: 'value',
      render: (_, a) => <span className="font-mono text-xs">{a.value}</span>,
    },
    {
      title: '归属企业',
      dataIndex: 'entity_name',
      key: 'entity_name',
      width: 150,
      render: (_, a) => <span className="text-xs">{a.entity_name || '—'}</span>,
    },
    {
      title: '证据',
      dataIndex: 'evidence',
      key: 'evidence',
      width: 120,
      render: (_, a) => (
        <span className="text-xs text-muted-foreground">{a.evidence || '—'}</span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 80,
      render: (_, a) => (
        <Tag className={badgeCls(a.status === 'imported' ? 'secondary' : 'outline')}>
          {a.status === 'candidate' ? '候选' : a.status === 'imported' ? '已导入' : '已忽略'}
        </Tag>
      ),
    },
  ]

  const icpColumns: TableProps<ICPQuery>['columns'] = [
    {
      title: '关键词',
      dataIndex: 'query',
      key: 'query',
      render: (_, r) => <span className="text-sm">{r.query}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, r) => (
        <Tag
          className={badgeCls(
            r.status === 'error'
              ? 'destructive'
              : r.status === 'running' || r.status === 'queued'
                ? 'default'
                : 'outline'
          )}
          title={r.error || undefined}
        >
          {icpStatusLabel[r.status] ?? r.status}
        </Tag>
      ),
    },
    {
      title: '总数',
      dataIndex: 'total',
      key: 'total',
      width: 80,
      render: (_, r) => <span className="text-sm">{r.total}</span>,
    },
    {
      title: '已抓取',
      dataIndex: 'fetched',
      key: 'fetched',
      width: 90,
      render: (_, r) => <span className="text-sm">{r.fetched}</span>,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 150,
      render: (_, r) => (
        <span className="text-xs text-muted-foreground">{formatDate(r.created_at)}</span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 120,
      render: (_, r) => (
        <div className="flex items-center gap-1">
          <Button size="small" onClick={() => setIcpSelected(r.id)} disabled={r.fetched === 0}>
            结果
          </Button>
          {(r.status === 'queued' || r.status === 'running') && (
            <Button type="text" size="small" onClick={() => cancelICP.mutate(r.id)}>
              取消
            </Button>
          )}
        </div>
      ),
    },
  ]

  return (
    // MainLayout 已带页内边距，这里不再叠 p-6
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <Building2 className="h-6 w-6" /> 企业身份
          </h1>
          <p className="text-sm text-muted-foreground">
            企业名 / 备案 / 关联域名线索；与 APP 名单按「公司名」对齐，只做线索，不触发扫描
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select
            className="w-44"
            value={projectId}
            onChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
            options={[
              { value: '0', label: '全部项目' },
              ...(projects.data?.data ?? []).map((p) => ({ value: String(p.id), label: p.name })),
            ]}
          />
          <Button onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button disabled={!canEdit} onClick={() => setImportOpen(true)}>
            <Upload className="mr-2 h-4 w-4" /> 批量导入
          </Button>
          <Button disabled={!canEdit} onClick={() => setCollectOpen(true)}>
            <DownloadCloud className="mr-2 h-4 w-4" /> 数据源采集
          </Button>
          <Button disabled={!canEdit} onClick={() => setDeepOpen(true)}>
            <GitBranch className="mr-2 h-4 w-4" /> 深度采集
          </Button>
          <Button type="primary" disabled={!canEdit} onClick={() => setOpen(true)}>
            <Plus className="mr-2 h-4 w-4" /> 新建线索
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="w-64"
          placeholder="搜索企业名 / 信用代码 / 法人"
          value={q}
          onChange={(e) => {
            setQ(e.target.value)
            setPage(1)
          }}
        />
        <Select
          className="w-32"
          value={status || 'all'}
          onChange={(v) => {
            setStatus(v === 'all' ? '' : v)
            setPage(1)
          }}
          options={[
            { value: 'all', label: '全部状态' },
            { value: 'unverified', label: '待核对' },
            { value: 'verified', label: '已核对' },
            { value: 'ignored', label: '已忽略' },
          ]}
        />
        <span className="ml-auto text-sm text-muted-foreground">{total} 条</span>
      </div>

      <div className="rounded-md border">
        <Table<EnterpriseEntity>
          columns={entityColumns}
          dataSource={items}
          rowKey="id"
          loading={list.isLoading}
          locale={{ emptyText: '还没有企业线索（手工新建、批量导入或从数据源采集）' }}
          pagination={{
            current: page,
            pageSize: PAGE_SIZE,
            total,
            showQuickJumper: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-md border">
          <div className="flex items-center justify-between border-b px-4 py-2 text-sm font-medium">
            <span>采集任务</span>
            <Button type="text" size="small" onClick={() => jobs.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
          </div>
          <Table<EnterpriseJob>
            columns={jobColumns}
            dataSource={jobItems}
            rowKey="id"
            pagination={false}
            locale={{ emptyText: !canEdit ? '选择项目后查看采集任务' : '还没有深度采集任务' }}
          />
        </div>

        <div className="rounded-md border">
          <div className="flex items-center justify-between border-b px-4 py-2 text-sm font-medium">
            <span>候选域名</span>
            <div className="flex items-center gap-2">
              <Select
                className="w-28"
                value={candStatus || 'all'}
                onChange={(v) => setCandStatus(v === 'all' ? '' : v)}
                options={[
                  { value: 'all', label: '全部状态' },
                  { value: 'candidate', label: '候选' },
                  { value: 'imported', label: '已导入' },
                  { value: 'rejected', label: '已忽略' },
                ]}
              />
              <Button type="text" size="small" onClick={() => candidates.refetch()}>
                <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
              </Button>
            </div>
          </div>
          <Table<EnterpriseCandidate>
            columns={candidateColumns}
            dataSource={candidateItems}
            rowKey="id"
            pagination={false}
            locale={{ emptyText: !canEdit ? '选择项目后查看候选域名' : '暂无候选域名（深度采集完成后写入）' }}
          />
        </div>
      </div>

      <div className="rounded-md border">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2">
          <div>
            <div className="flex items-center gap-2 text-sm font-medium">
              <FileSearch className="h-4 w-4" /> 工信部官方备案查询
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              官方站风控严格：单 worker 串行、任意两次请求间隔 ≥5 秒、翻页间隔 6 秒；
              查询只入队，不阻塞其他任务
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Input
              className="w-64"
              placeholder="企业名或备案号"
              value={icpInput}
              onChange={(e) => setIcpInput(e.target.value)}
              disabled={!canEdit}
            />
            <Button
              type="primary"
              onClick={() => enqueueICP.mutate()}
              disabled={!canEdit || enqueueICP.isPending || !icpInput.trim()}
            >
              {enqueueICP.isPending ? '入队中…' : '查询备案'}
            </Button>
            <Button type="text" size="small" onClick={() => icpQueries.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
          </div>
        </div>
        <Table<ICPQuery>
          columns={icpColumns}
          dataSource={icpItems}
          rowKey="id"
          pagination={false}
          locale={{ emptyText: !canEdit ? '选择项目后可发起官方备案查询' : '还没有备案查询' }}
        />
      </div>

      {/* 各弹窗：表单态与对应 mutation 随组件迁移，开合仍由页面工具栏/列操作控制 */}
      <CreateEntityModal open={open} projectId={projectId} onClose={() => setOpen(false)} />
      <ImportEntitiesModal open={importOpen} projectId={projectId} onClose={() => setImportOpen(false)} />
      <CollectModal
        open={collectOpen}
        projectId={projectId}
        providers={providerList}
        onClose={() => setCollectOpen(false)}
      />
      <DeepCollectModal
        open={deepOpen}
        projectId={projectId}
        providers={providerList}
        onClose={() => setDeepOpen(false)}
      />
      <IcpResultModal icpId={icpSelected} onClose={() => setIcpSelected(null)} />
      <AlignedAssetsModal entity={aligned} onClose={() => setAligned(null)} />
    </div>
  )
}

import { useEffect, useState } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { Building2, DownloadCloud, FileSearch, GitBranch, Link2, Plus, RefreshCw, Search, Trash2, Upload } from 'lucide-react'
import { Button, Input, Modal, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { projectApi } from '@/api/projects'
import {
  enterpriseApi,
  enterpriseStatusLabel,
  type AlignedDigitalAsset,
  type CompanyRef,
  type EnterpriseDomain,
  type EnterpriseEntity,
  type EnterpriseJob,
  type EnterpriseCandidate,
  type EnterpriseProvider,
} from '@/api/enterprise'
import { icpApi, type ICPFiling, type ICPQuery } from '@/api/icp'
import { useConfirm } from '@/components/common/confirm-provider'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const PAGE_SIZE = 50

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: BadgeVariant) =>
  variant === 'default' || variant === 'success'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : variant === 'warning'
          ? 'border-transparent bg-yellow-500 text-black'
          : variant === 'info'
            ? 'border-transparent bg-blue-500 text-white'
            : ''

type FormState = {
  name: string
  credit_code: string
  legal_person: string
  industry: string
  address: string
  icp: string
  domains: string
  status: string
  notes: string
}

const emptyForm: FormState = {
  name: '',
  credit_code: '',
  legal_person: '',
  industry: '',
  address: '',
  icp: '',
  domains: '',
  status: 'unverified',
  notes: '',
}

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
  const [form, setForm] = useState<FormState>(emptyForm)
  const [importOpen, setImportOpen] = useState(false)
  const [importText, setImportText] = useState('')
  const [collectOpen, setCollectOpen] = useState(false)
  const [collectForm, setCollectForm] = useState({
    provider: 'aqc',
    keyword: '',
    cookie: '',
    username: '',
    password: '',
  })
  const [deepOpen, setDeepOpen] = useState(false)
  const [deepForm, setDeepForm] = useState({
    provider: 'aqc',
    keyword: '',
    cookie: '',
    username: '',
    password: '',
    depth: 2,
    max_nodes: 20,
  })
  const [refs, setRefs] = useState<CompanyRef[]>([])
  const [selectedRef, setSelectedRef] = useState<CompanyRef | null>(null)
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
  const alignedQuery = useQuery({
    queryKey: ['enterprise-aligned', aligned?.id],
    queryFn: () => enterpriseApi.alignedAssets(aligned!.id),
    enabled: aligned !== null,
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
  const icpDetail = useQuery({
    queryKey: ['icp-detail', icpSelected],
    queryFn: () => icpApi.get(icpSelected as string, 500),
    enabled: icpSelected !== null,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
    queryClient.invalidateQueries({ queryKey: ['enterprise-aligned'] })
  }

  const save = useMutation({
    mutationFn: () => {
      if (Number(projectId) <= 0) throw new Error('先选择归属项目')
      const icp = form.icp
        .split(/[\s,，]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const domains: EnterpriseDomain[] = form.domains
        .split(/[\s,，|]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((d) => ({ domain: d }))
      return enterpriseApi.upsert({
        project_id: Number(projectId),
        name: form.name.trim(),
        credit_code: form.credit_code.trim(),
        legal_person: form.legal_person.trim(),
        industry: form.industry.trim(),
        address: form.address.trim(),
        icp_numbers: icp,
        domains,
        status: form.status,
        notes: form.notes.trim(),
        source: 'manual',
      })
    },
    onSuccess: () => {
      toast({ title: '企业线索已保存' })
      setOpen(false)
      setForm(emptyForm)
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: number) => enterpriseApi.remove(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const importRows = useMutation({
    mutationFn: () => {
      if (Number(projectId) <= 0) throw new Error('先选择归属项目')
      const items = importText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [name, credit, legal, icp, domains] = line.split(/[,\t]/).map((s) => s.trim())
          if (!name) throw new Error('每行第一个字段必须是企业名')
          return {
            name,
            credit_code: credit || '',
            legal_person: legal || '',
            icp_numbers: icp ? icp.split('|').filter(Boolean) : [],
            domains: domains ? domains.split('|').filter(Boolean).map((d) => ({ domain: d })) : [],
            source: 'import',
            status: 'unverified',
          }
        })
      return enterpriseApi.importRows(Number(projectId), items)
    },
    onSuccess: (res) => {
      toast({
        title: '导入完成',
        description: `新增 ${res.data?.inserted ?? 0} · 更新 ${res.data?.updated ?? 0}`,
      })
      setImportOpen(false)
      setImportText('')
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '导入失败', description: e?.message, variant: 'destructive' }),
  })

  const collect = useMutation({
    mutationFn: () =>
      enterpriseApi.collect({
        project_id: Number(projectId),
        provider: collectForm.provider,
        keyword: collectForm.keyword,
        limit: 5,
        cookie: collectForm.cookie || undefined,
        username: collectForm.username || undefined,
        password: collectForm.password || undefined,
      }),
    onSuccess: (res) => {
      toast({
        title: '采集完成',
        description: `命中 ${res.data?.found ?? 0} 家企业，线索 ${res.data?.entities?.length ?? 0} 条`,
      })
      setCollectOpen(false)
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '采集失败', description: e?.message, variant: 'destructive' }),
  })

  const searchProvider = useMutation({
    mutationFn: () =>
      enterpriseApi.searchProvider({
        project_id: Number(projectId),
        provider: deepForm.provider,
        keyword: deepForm.keyword,
        limit: 10,
        cookie: deepForm.cookie || undefined,
        username: deepForm.username || undefined,
        password: deepForm.password || undefined,
      }),
    onSuccess: (res) => {
      const items = res.data?.items ?? []
      setRefs(items)
      setSelectedRef(items[0] ?? null)
      if (items.length === 0) toast({ title: '没有搜索结果' })
    },
    onError: (e: any) =>
      toast({ title: '搜索失败', description: e?.message, variant: 'destructive' }),
  })

  const discover = useMutation({
    mutationFn: () => {
      if (!selectedRef) throw new Error('先搜索并选择一家企业')
      return enterpriseApi.discover({
        project_id: Number(projectId),
        provider: deepForm.provider,
        ext_id: selectedRef.ext_id,
        name: selectedRef.name,
        depth: deepForm.depth,
        max_nodes: deepForm.max_nodes,
        cookie: deepForm.cookie || undefined,
        username: deepForm.username || undefined,
        password: deepForm.password || undefined,
      })
    },
    onSuccess: (res) => {
      toast({
        title: '深度采集已启动',
        description: `任务 ${res.data?.id}，分支/投资将按深度 ${res.data?.depth} 展开`,
      })
      setDeepOpen(false)
      setRefs([])
      setSelectedRef(null)
      queryClient.invalidateQueries({ queryKey: ['enterprise-jobs'] })
      queryClient.invalidateQueries({ queryKey: ['enterprise-candidates'] })
    },
    onError: (e: any) =>
      toast({ title: '启动失败', description: e?.message, variant: 'destructive' }),
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

  const filingColumns: TableProps<ICPFiling>['columns'] = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (_, f) => <span className="font-mono text-xs">{f.domain || '—'}</span>,
    },
    {
      title: '服务备案号',
      dataIndex: 'service_licence',
      key: 'service_licence',
      width: 170,
      render: (_, f) => <span className="font-mono text-xs">{f.service_licence || '—'}</span>,
    },
    {
      title: '主体备案号',
      dataIndex: 'main_licence',
      key: 'main_licence',
      width: 170,
      render: (_, f) => <span className="font-mono text-xs">{f.main_licence || '—'}</span>,
    },
    {
      title: '主办单位',
      dataIndex: 'unit_name',
      key: 'unit_name',
      width: 220,
      render: (_, f) => <span className="text-xs">{f.unit_name || '—'}</span>,
    },
    {
      title: '性质',
      dataIndex: 'nature_name',
      key: 'nature_name',
      width: 90,
      render: (_, f) => <span className="text-xs">{f.nature_name || '—'}</span>,
    },
    {
      title: '更新时间',
      dataIndex: 'update_record_time',
      key: 'update_record_time',
      width: 120,
      render: (_, f) => (
        <span className="text-xs text-muted-foreground">{f.update_record_time || '—'}</span>
      ),
    },
  ]

  const alignedColumns: TableProps<AlignedDigitalAsset>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (_, a) => <span className="text-sm">{a.name}</span>,
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 100,
      render: (_, a) => <span className="text-xs">{a.kind}</span>,
    },
    {
      title: '平台',
      dataIndex: 'platform',
      key: 'platform',
      width: 120,
      render: (_, a) => <span className="text-xs">{a.platform || '—'}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, a) => <span className="text-xs">{a.status}</span>,
    },
  ]

  return (
    <div className="space-y-5 p-6">
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

      <Modal
        open={open}
        onCancel={() => setOpen(false)}
        title="新建 / 更新企业线索"
        width={672}
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
        <p className="text-muted-foreground mb-4 text-sm">
          按项目 + 企业名唯一；同名的 APP 名单会自动对齐。
        </p>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">企业名</label>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">统一信用代码</label>
            <Input
              value={form.credit_code}
              onChange={(e) => setForm({ ...form, credit_code: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">法人</label>
            <Input
              value={form.legal_person}
              onChange={(e) => setForm({ ...form, legal_person: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">行业</label>
            <Input
              value={form.industry}
              onChange={(e) => setForm({ ...form, industry: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">状态</label>
            <Select
              className="w-full"
              value={form.status}
              onChange={(v) => setForm({ ...form, status: v })}
              options={[
                { value: 'unverified', label: '待核对' },
                { value: 'verified', label: '已核对' },
                { value: 'ignored', label: '已忽略' },
              ]}
            />
          </div>
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">地址</label>
            <Input
              value={form.address}
              onChange={(e) => setForm({ ...form, address: e.target.value })}
            />
          </div>
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">备案号（空格或逗号分隔）</label>
            <Input value={form.icp} onChange={(e) => setForm({ ...form, icp: e.target.value })} />
          </div>
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">关联域名（空格、逗号或 | 分隔）</label>
            <Input
              value={form.domains}
              onChange={(e) => setForm({ ...form, domains: e.target.value })}
            />
          </div>
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">备注</label>
            <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
          </div>
        </div>
      </Modal>

      <Modal
        open={importOpen}
        onCancel={() => setImportOpen(false)}
        title="批量导入企业线索"
        width={672}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setImportOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => importRows.mutate()}
              disabled={importRows.isPending || !importText.trim()}
            >
              {importRows.isPending ? '导入中…' : '确认导入'}
            </Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          每行一家：企业名,信用代码,法人,备案号(|分隔),域名(|分隔)。空字段留空即可。
        </p>
        <Input.TextArea
          className="font-mono text-sm"
          style={{ height: 224 }}
          placeholder={'示例企业有限公司,91110000XXXXXXXX,张三,京ICP备12345678号,example.com|example.cn'}
          value={importText}
          onChange={(e) => setImportText(e.target.value)}
        />
      </Modal>

      <Modal
        open={collectOpen}
        onCancel={() => setCollectOpen(false)}
        title="从企业数据源采集"
        width={576}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setCollectOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => collect.mutate()}
              disabled={collect.isPending || !collectForm.keyword.trim()}
            >
              {collect.isPending ? '采集中…' : '开始采集'}
            </Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          只产生线索与域名列表，不创建站点、不触发扫描；凭据仅在本次请求内使用，不落库。
        </p>
        <div className="space-y-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">数据源</label>
            <Select
              className="w-full"
              value={collectForm.provider}
              onChange={(v) => setCollectForm({ ...collectForm, provider: v })}
              options={providerList.map((p) => ({
                value: p.Name,
                label: `${p.Label}（${p.Auth}）`,
                disabled: !p.Available,
              }))}
            />
            <p className="text-xs text-muted-foreground">
              {providerList.find((p) => p.Name === collectForm.provider)?.Hint ?? ''}
            </p>
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">企业名关键词</label>
            <Input
              value={collectForm.keyword}
              onChange={(e) => setCollectForm({ ...collectForm, keyword: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">Cookie（cookie 类数据源）</label>
            <Input
              value={collectForm.cookie}
              onChange={(e) => setCollectForm({ ...collectForm, cookie: e.target.value })}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">账号（账号类数据源）</label>
              <Input
                value={collectForm.username}
                onChange={(e) => setCollectForm({ ...collectForm, username: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">密码</label>
              <Input
                type="password"
                value={collectForm.password}
                onChange={(e) => setCollectForm({ ...collectForm, password: e.target.value })}
              />
            </div>
          </div>
        </div>
      </Modal>

      <Modal
        open={deepOpen}
        onCancel={() => setDeepOpen(false)}
        title="深度采集（分支 / 投资 / 域名）"
        width={672}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setDeepOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => discover.mutate()}
              disabled={discover.isPending || !selectedRef}
            >
              {discover.isPending ? '启动中…' : '开始深度采集'}
            </Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          先搜索并选中根企业，再按深度逐层展开；节点与翻页有硬上限，结果只进线索与候选域名，不创建站点。
        </p>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">数据源</label>
              <Select
                className="w-full"
                value={deepForm.provider}
                onChange={(v) => setDeepForm({ ...deepForm, provider: v })}
                options={providerList.map((p) => ({
                  value: p.Name,
                  label: `${p.Label}（${p.Auth}）`,
                  disabled: !p.Available,
                }))}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">企业名关键词</label>
              <div className="flex gap-2">
                <Input
                  value={deepForm.keyword}
                  onChange={(e) => setDeepForm({ ...deepForm, keyword: e.target.value })}
                />
                <Button
                  onClick={() => searchProvider.mutate()}
                  disabled={searchProvider.isPending || !deepForm.keyword.trim()}
                >
                  <Search className="mr-1 h-4 w-4" />
                  {searchProvider.isPending ? '搜索中…' : '搜索'}
                </Button>
              </div>
            </div>
            <div className="col-span-2 space-y-1">
              <label className="text-sm font-medium">Cookie（cookie 类数据源）</label>
              <Input
                value={deepForm.cookie}
                onChange={(e) => setDeepForm({ ...deepForm, cookie: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">账号（账号类数据源）</label>
              <Input
                value={deepForm.username}
                onChange={(e) => setDeepForm({ ...deepForm, username: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">密码</label>
              <Input
                type="password"
                value={deepForm.password}
                onChange={(e) => setDeepForm({ ...deepForm, password: e.target.value })}
              />
            </div>
          </div>

          {refs.length > 0 && (
            <div className="max-h-48 space-y-1 overflow-auto rounded-md border p-2">
              {refs.map((r) => (
                <button
                  key={r.ext_id}
                  className={
                    'block w-full rounded px-2 py-1 text-left text-sm ' +
                    (selectedRef?.ext_id === r.ext_id ? 'bg-primary/10 text-primary' : 'hover:bg-muted')
                  }
                  onClick={() => setSelectedRef(r)}
                >
                  <span className="font-medium">{r.name}</span>
                  <span className="ml-2 font-mono text-xs text-muted-foreground">
                    {r.ext_id}
                  </span>
                </button>
              ))}
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-sm font-medium">展开深度（1–3）</label>
              <Input
                type="number"
                min={1}
                max={3}
                value={deepForm.depth}
                onChange={(e) =>
                  setDeepForm({ ...deepForm, depth: Number(e.target.value) || 1 })
                }
              />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">最大节点数（1–200）</label>
              <Input
                type="number"
                min={1}
                max={200}
                value={deepForm.max_nodes}
                onChange={(e) =>
                  setDeepForm({ ...deepForm, max_nodes: Number(e.target.value) || 20 })
                }
              />
            </div>
          </div>
        </div>
      </Modal>

      <Modal
        open={icpSelected !== null}
        onCancel={() => setIcpSelected(null)}
        width={1024}
        title={`官方备案结果 · ${icpDetail.data?.data?.query?.query ?? icpSelected}`}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setIcpSelected(null)}>关闭</Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          共 {icpDetail.data?.data?.query?.total ?? 0} 条，本次抓取{' '}
          {icpDetail.data?.data?.query?.fetched ?? 0} 条（单次最多 20 页）
        </p>
        <div className="max-h-[60vh] overflow-auto rounded-md border">
          <Table<ICPFiling>
            columns={filingColumns}
            dataSource={icpDetail.data?.data?.filings ?? []}
            rowKey="id"
            loading={icpDetail.isLoading}
            pagination={false}
            locale={{ emptyText: '没有备案记录' }}
          />
        </div>
      </Modal>

      <Modal
        open={aligned !== null}
        onCancel={() => setAligned(null)}
        title={`APP 名单归属对齐 · ${aligned?.name}`}
        width={672}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setAligned(null)}>关闭</Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          同项目内 `company` 与企业名完全一致的名单；不同主体同名需人工核对。
        </p>
        <div className="rounded-md border">
          <Table<AlignedDigitalAsset>
            columns={alignedColumns}
            dataSource={alignedQuery.data?.data?.items ?? []}
            rowKey="id"
            loading={alignedQuery.isLoading}
            pagination={false}
            locale={{ emptyText: '没有对齐的 APP 名单' }}
          />
        </div>
      </Modal>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Building2, DownloadCloud, FileSearch, GitBranch, Link2, Plus, RefreshCw, Search, Trash2, Upload } from 'lucide-react'

import { projectApi } from '@/api/projects'
import {
  enterpriseApi,
  enterpriseStatusLabel,
  type CompanyRef,
  type EnterpriseDomain,
  type EnterpriseEntity,
  type EnterpriseProvider,
} from '@/api/enterprise'
import { icpApi } from '@/api/icp'
import { Badge } from '@/components/ui/badge'
import { useConfirm } from '@/components/common/confirm-provider'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const PAGE_SIZE = 50

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
    queryKey: ['enterprise-entities', projectId, q, status, page],
    queryFn: () =>
      enterpriseApi.list({
        project_id: Number(projectId) || undefined,
        q: q || undefined,
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
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))
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
            value={projectId}
            onValueChange={(v) => {
              setProjectId(v)
              setPage(1)
            }}
          >
            <SelectTrigger className="w-44">
              <SelectValue placeholder="全部项目" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">全部项目</SelectItem>
              {(projects.data?.data ?? []).map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" onClick={() => list.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button variant="outline" disabled={!canEdit} onClick={() => setImportOpen(true)}>
            <Upload className="mr-2 h-4 w-4" /> 批量导入
          </Button>
          <Button variant="outline" disabled={!canEdit} onClick={() => setCollectOpen(true)}>
            <DownloadCloud className="mr-2 h-4 w-4" /> 数据源采集
          </Button>
          <Button variant="outline" disabled={!canEdit} onClick={() => setDeepOpen(true)}>
            <GitBranch className="mr-2 h-4 w-4" /> 深度采集
          </Button>
          <Button disabled={!canEdit} onClick={() => setOpen(true)}>
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
          value={status || 'all'}
          onValueChange={(v) => {
            setStatus(v === 'all' ? '' : v)
            setPage(1)
          }}
        >
          <SelectTrigger className="w-32">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="unverified">待核对</SelectItem>
            <SelectItem value="verified">已核对</SelectItem>
            <SelectItem value="ignored">已忽略</SelectItem>
          </SelectContent>
        </Select>
        <span className="ml-auto text-sm text-muted-foreground">{total} 条</span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>企业名</TableHead>
              <TableHead className="w-[170px]">统一信用代码</TableHead>
              <TableHead className="w-[100px]">法人</TableHead>
              <TableHead className="w-[90px]">状态</TableHead>
              <TableHead className="w-[90px]">备案域名</TableHead>
              <TableHead className="w-[90px]">对齐 APP</TableHead>
              <TableHead className="w-[90px]">来源</TableHead>
              <TableHead className="w-[150px]">更新时间</TableHead>
              <TableHead className="w-[120px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.isLoading && (
              <TableRow>
                <TableCell colSpan={9} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!list.isLoading && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={9} className="py-8 text-center text-muted-foreground">
                  还没有企业线索（手工新建、批量导入或从数据源采集）
                </TableCell>
              </TableRow>
            )}
            {items.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="text-sm font-medium">
                  {e.name}
                  {e.project_id > 0 && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      {projectName(e.project_id)}
                    </span>
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs">{e.credit_code || '—'}</TableCell>
                <TableCell className="text-sm">{e.legal_person || '—'}</TableCell>
                <TableCell>
                  <Badge variant={e.status === 'verified' ? 'secondary' : 'outline'}>
                    {enterpriseStatusLabel[e.status] ?? e.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-sm">{e.domains?.length ?? 0}</TableCell>
                <TableCell className="text-sm">{e.digital_count}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{e.source || '—'}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(e.updated_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button
                      size="icon"
                      variant="ghost"
                      title="对齐名单"
                      onClick={() => setAligned(e)}
                    >
                      <Link2 className="h-4 w-4" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      title="删除"
                      onClick={async () => {
                        if (await confirm(`删除企业线索「${e.name}」？`)) remove.mutate(e.id)
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-end gap-2 text-sm">
        <Button
          variant="outline"
          size="sm"
          disabled={page <= 1}
          onClick={() => setPage((p) => Math.max(1, p - 1))}
        >
          上一页
        </Button>
        <span className="text-muted-foreground">
          第 {page} / {totalPages} 页
        </span>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= totalPages}
          onClick={() => setPage((p) => p + 1)}
        >
          下一页
        </Button>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-md border">
          <div className="flex items-center justify-between border-b px-4 py-2 text-sm font-medium">
            <span>采集任务</span>
            <Button size="sm" variant="ghost" onClick={() => jobs.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[90px]">任务</TableHead>
                <TableHead className="w-[90px]">来源</TableHead>
                <TableHead className="w-[90px]">状态</TableHead>
                <TableHead className="w-[70px]">节点</TableHead>
                <TableHead className="w-[70px]">实体</TableHead>
                <TableHead className="w-[70px]">域名</TableHead>
                <TableHead className="w-[70px]">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!canEdit && (
                <TableRow>
                  <TableCell colSpan={7} className="py-6 text-center text-muted-foreground">
                    选择项目后查看采集任务
                  </TableCell>
                </TableRow>
              )}
              {canEdit && jobItems.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-6 text-center text-muted-foreground">
                    还没有深度采集任务
                  </TableCell>
                </TableRow>
              )}
              {jobItems.map((j) => (
                <TableRow key={j.id}>
                  <TableCell className="font-mono text-xs" title={j.id}>
                    {j.id.slice(-6)}
                  </TableCell>
                  <TableCell className="text-xs">{j.provider}</TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        j.status === 'error'
                          ? 'destructive'
                          : j.status === 'running'
                            ? 'default'
                            : 'outline'
                      }
                      title={j.error || undefined}
                    >
                      {jobStatusLabel[j.status] ?? j.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm">{j.nodes}</TableCell>
                  <TableCell className="text-sm">{j.entities}</TableCell>
                  <TableCell className="text-sm">{j.domains}</TableCell>
                  <TableCell>
                    {j.status === 'running' && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => cancelJob.mutate(j.id)}
                      >
                        取消
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        <div className="rounded-md border">
          <div className="flex items-center justify-between border-b px-4 py-2 text-sm font-medium">
            <span>候选域名</span>
            <div className="flex items-center gap-2">
              <Select
                value={candStatus || 'all'}
                onValueChange={(v) => setCandStatus(v === 'all' ? '' : v)}
              >
                <SelectTrigger className="h-8 w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="candidate">候选</SelectItem>
                  <SelectItem value="imported">已导入</SelectItem>
                  <SelectItem value="rejected">已忽略</SelectItem>
                </SelectContent>
              </Select>
              <Button size="sm" variant="ghost" onClick={() => candidates.refetch()}>
                <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
              </Button>
            </div>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>域名</TableHead>
                <TableHead className="w-[150px]">归属企业</TableHead>
                <TableHead className="w-[120px]">证据</TableHead>
                <TableHead className="w-[80px]">状态</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {!canEdit && (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                    选择项目后查看候选域名
                  </TableCell>
                </TableRow>
              )}
              {canEdit && candidateItems.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                    暂无候选域名（深度采集完成后写入）
                  </TableCell>
                </TableRow>
              )}
              {candidateItems.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="font-mono text-xs">{a.value}</TableCell>
                  <TableCell className="text-xs">{a.entity_name || '—'}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {a.evidence || '—'}
                  </TableCell>
                  <TableCell>
                    <Badge variant={a.status === 'imported' ? 'secondary' : 'outline'}>
                      {a.status === 'candidate' ? '候选' : a.status === 'imported' ? '已导入' : '已忽略'}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
              onClick={() => enqueueICP.mutate()}
              disabled={!canEdit || enqueueICP.isPending || !icpInput.trim()}
            >
              {enqueueICP.isPending ? '入队中…' : '查询备案'}
            </Button>
            <Button variant="ghost" size="sm" onClick={() => icpQueries.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
          </div>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>关键词</TableHead>
              <TableHead className="w-[90px]">状态</TableHead>
              <TableHead className="w-[80px]">总数</TableHead>
              <TableHead className="w-[90px]">已抓取</TableHead>
              <TableHead className="w-[150px]">创建时间</TableHead>
              <TableHead className="w-[120px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {!canEdit && (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  选择项目后可发起官方备案查询
                </TableCell>
              </TableRow>
            )}
            {canEdit && icpItems.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  还没有备案查询
                </TableCell>
              </TableRow>
            )}
            {icpItems.map((q) => (
              <TableRow key={q.id}>
                <TableCell className="text-sm">{q.query}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      q.status === 'error'
                        ? 'destructive'
                        : q.status === 'running' || q.status === 'queued'
                          ? 'default'
                          : 'outline'
                    }
                    title={q.error || undefined}
                  >
                    {icpStatusLabel[q.status] ?? q.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-sm">{q.total}</TableCell>
                <TableCell className="text-sm">{q.fetched}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(q.created_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setIcpSelected(q.id)}
                      disabled={q.fetched === 0}
                    >
                      结果
                    </Button>
                    {(q.status === 'queued' || q.status === 'running') && (
                      <Button size="sm" variant="ghost" onClick={() => cancelICP.mutate(q.id)}>
                        取消
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>新建 / 更新企业线索</DialogTitle>
            <DialogDescription>按项目 + 企业名唯一；同名的 APP 名单会自动对齐。</DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-2 gap-3">
            <div className="col-span-2 space-y-1">
              <Label>企业名</Label>
              <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>统一信用代码</Label>
              <Input
                value={form.credit_code}
                onChange={(e) => setForm({ ...form, credit_code: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>法人</Label>
              <Input
                value={form.legal_person}
                onChange={(e) => setForm({ ...form, legal_person: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>行业</Label>
              <Input
                value={form.industry}
                onChange={(e) => setForm({ ...form, industry: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>状态</Label>
              <Select value={form.status} onValueChange={(v) => setForm({ ...form, status: v })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="unverified">待核对</SelectItem>
                  <SelectItem value="verified">已核对</SelectItem>
                  <SelectItem value="ignored">已忽略</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="col-span-2 space-y-1">
              <Label>地址</Label>
              <Input value={form.address} onChange={(e) => setForm({ ...form, address: e.target.value })} />
            </div>
            <div className="col-span-2 space-y-1">
              <Label>备案号（空格或逗号分隔）</Label>
              <Input value={form.icp} onChange={(e) => setForm({ ...form, icp: e.target.value })} />
            </div>
            <div className="col-span-2 space-y-1">
              <Label>关联域名（空格、逗号或 | 分隔）</Label>
              <Input
                value={form.domains}
                onChange={(e) => setForm({ ...form, domains: e.target.value })}
              />
            </div>
            <div className="col-span-2 space-y-1">
              <Label>备注</Label>
              <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              取消
            </Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending || !form.name.trim()}>
              {save.isPending ? '保存中…' : '保存'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>批量导入企业线索</DialogTitle>
            <DialogDescription>
              每行一家：企业名,信用代码,法人,备案号(|分隔),域名(|分隔)。空字段留空即可。
            </DialogDescription>
          </DialogHeader>
          <Textarea
            className="h-56 w-full rounded-md border bg-background p-3 font-mono text-sm"
            placeholder={'示例企业有限公司,91110000XXXXXXXX,张三,京ICP备12345678号,example.com|example.cn'}
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              取消
            </Button>
            <Button
              onClick={() => importRows.mutate()}
              disabled={importRows.isPending || !importText.trim()}
            >
              {importRows.isPending ? '导入中…' : '确认导入'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={collectOpen} onOpenChange={setCollectOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>从企业数据源采集</DialogTitle>
            <DialogDescription>
              只产生线索与域名列表，不创建站点、不触发扫描；凭据仅在本次请求内使用，不落库。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1">
              <Label>数据源</Label>
              <Select
                value={collectForm.provider}
                onValueChange={(v) => setCollectForm({ ...collectForm, provider: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {providerList.map((p) => (
                    <SelectItem key={p.Name} value={p.Name} disabled={!p.Available}>
                      {p.Label}（{p.Auth}）
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {providerList.find((p) => p.Name === collectForm.provider)?.Hint ?? ''}
              </p>
            </div>
            <div className="space-y-1">
              <Label>企业名关键词</Label>
              <Input
                value={collectForm.keyword}
                onChange={(e) => setCollectForm({ ...collectForm, keyword: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>Cookie（cookie 类数据源）</Label>
              <Input
                value={collectForm.cookie}
                onChange={(e) => setCollectForm({ ...collectForm, cookie: e.target.value })}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>账号（账号类数据源）</Label>
                <Input
                  value={collectForm.username}
                  onChange={(e) => setCollectForm({ ...collectForm, username: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>密码</Label>
                <Input
                  type="password"
                  value={collectForm.password}
                  onChange={(e) => setCollectForm({ ...collectForm, password: e.target.value })}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCollectOpen(false)}>
              取消
            </Button>
            <Button
              onClick={() => collect.mutate()}
              disabled={collect.isPending || !collectForm.keyword.trim()}
            >
              {collect.isPending ? '采集中…' : '开始采集'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={deepOpen} onOpenChange={setDeepOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>深度采集（分支 / 投资 / 域名）</DialogTitle>
            <DialogDescription>
              先搜索并选中根企业，再按深度逐层展开；节点与翻页有硬上限，结果只进线索与候选域名，不创建站点。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>数据源</Label>
                <Select
                  value={deepForm.provider}
                  onValueChange={(v) => setDeepForm({ ...deepForm, provider: v })}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {providerList.map((p) => (
                      <SelectItem key={p.Name} value={p.Name} disabled={!p.Available}>
                        {p.Label}（{p.Auth}）
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label>企业名关键词</Label>
                <div className="flex gap-2">
                  <Input
                    value={deepForm.keyword}
                    onChange={(e) => setDeepForm({ ...deepForm, keyword: e.target.value })}
                  />
                  <Button
                    variant="outline"
                    onClick={() => searchProvider.mutate()}
                    disabled={searchProvider.isPending || !deepForm.keyword.trim()}
                  >
                    <Search className="mr-1 h-4 w-4" />
                    {searchProvider.isPending ? '搜索中…' : '搜索'}
                  </Button>
                </div>
              </div>
              <div className="col-span-2 space-y-1">
                <Label>Cookie（cookie 类数据源）</Label>
                <Input
                  value={deepForm.cookie}
                  onChange={(e) => setDeepForm({ ...deepForm, cookie: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>账号（账号类数据源）</Label>
                <Input
                  value={deepForm.username}
                  onChange={(e) => setDeepForm({ ...deepForm, username: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label>密码</Label>
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
                <Label>展开深度（1–3）</Label>
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
                <Label>最大节点数（1–200）</Label>
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
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeepOpen(false)}>
              取消
            </Button>
            <Button
              onClick={() => discover.mutate()}
              disabled={discover.isPending || !selectedRef}
            >
              {discover.isPending ? '启动中…' : '开始深度采集'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={icpSelected !== null} onOpenChange={(o) => !o && setIcpSelected(null)}>
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <DialogTitle>
              官方备案结果 · {icpDetail.data?.data?.query?.query ?? icpSelected}
            </DialogTitle>
            <DialogDescription>
              共 {icpDetail.data?.data?.query?.total ?? 0} 条，本次抓取{' '}
              {icpDetail.data?.data?.query?.fetched ?? 0} 条（单次最多 20 页）
            </DialogDescription>
          </DialogHeader>
          <div className="max-h-[60vh] overflow-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>域名</TableHead>
                  <TableHead className="w-[170px]">服务备案号</TableHead>
                  <TableHead className="w-[170px]">主体备案号</TableHead>
                  <TableHead className="w-[220px]">主办单位</TableHead>
                  <TableHead className="w-[90px]">性质</TableHead>
                  <TableHead className="w-[120px]">更新时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {icpDetail.isLoading && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                      加载中…
                    </TableCell>
                  </TableRow>
                )}
                {!icpDetail.isLoading &&
                  (icpDetail.data?.data?.filings ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                        没有备案记录
                      </TableCell>
                    </TableRow>
                  )}
                {(icpDetail.data?.data?.filings ?? []).map((f) => (
                  <TableRow key={f.id}>
                    <TableCell className="font-mono text-xs">{f.domain || '—'}</TableCell>
                    <TableCell className="font-mono text-xs">{f.service_licence || '—'}</TableCell>
                    <TableCell className="font-mono text-xs">{f.main_licence || '—'}</TableCell>
                    <TableCell className="text-xs">{f.unit_name || '—'}</TableCell>
                    <TableCell className="text-xs">{f.nature_name || '—'}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {f.update_record_time || '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIcpSelected(null)}>
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={aligned !== null} onOpenChange={(o) => !o && setAligned(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>APP 名单归属对齐 · {aligned?.name}</DialogTitle>
            <DialogDescription>
              同项目内 `company` 与企业名完全一致的名单；不同主体同名需人工核对。
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead className="w-[100px]">类型</TableHead>
                  <TableHead className="w-[120px]">平台</TableHead>
                  <TableHead className="w-[90px]">状态</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alignedQuery.isLoading && (
                  <TableRow>
                    <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                      加载中…
                    </TableCell>
                  </TableRow>
                )}
                {!alignedQuery.isLoading &&
                  (alignedQuery.data?.data?.items ?? []).length === 0 && (
                    <TableRow>
                      <TableCell colSpan={4} className="py-6 text-center text-muted-foreground">
                        没有对齐的 APP 名单
                      </TableCell>
                    </TableRow>
                  )}
                {(alignedQuery.data?.data?.items ?? []).map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="text-sm">{a.name}</TableCell>
                    <TableCell className="text-xs">{a.kind}</TableCell>
                    <TableCell className="text-xs">{a.platform || '—'}</TableCell>
                    <TableCell className="text-xs">{a.status}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAligned(null)}>
              关闭
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

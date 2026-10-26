import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { vulnApi } from '@/api/vulnerabilities'
import { reportApi, type ReportProfile } from '@/api/reports'
import { vulnStatusLabel, type VulnStatus } from '@/api/vulnerabilities'
import { ReportGenerateDialog } from '@/components/reports/ReportGenerateDialog'
import { Button, Dropdown, Input, Select, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { useConfirm } from '@/components/common/confirm-provider'
import EmptyState from '@/components/common/EmptyState'
import { cn, formatDate, getSeverityColor, getStatusColor } from '@/lib/utils'
import { getErrorMessage } from '@/lib/errors'
import { Search, Eye, Download, RefreshCw, CheckCircle, MoreHorizontal, BarChart3, List, Shield } from 'lucide-react'
import { Link } from 'react-router-dom'
import VulnDashboard from '@/components/vulnerabilities/VulnDashboard'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

interface VulnRow {
  id: string
  name: string
  severity: string
  status: string
  target: string
  cve?: string
  createdAt: string
}

interface ListProps {
  rows: VulnRow[]
  loading: boolean
  search: string
  onSearch: (v: string) => void
  severityFilter: string
  onSeverity: (v: string) => void
  statusFilter: string
  onStatus: (v: string) => void
  page: number
  onPage: (p: number) => void
  total: number
  selectedIds: string[]
  onSelected: (ids: string[]) => void
  onBatch: (status: string) => void
  verifyingId?: string
  onVerify: (id: string) => void
}

// 漏洞列表。必须保持在模块顶层：定义在渲染体内会因组件类型每次变化
// 导致整棵子树重挂——搜索框每敲一个字符就失焦。
function VulnList(props: ListProps) {
  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    }
    return labels[severity] || severity
  }

  const getStatusLabel = (status: string) =>
    vulnStatusLabel[status as VulnStatus] || status

  const columns: TableProps<VulnRow>['columns'] = [
    {
      title: '漏洞名称',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
      render: (v: string) => <span className="font-medium">{v}</span>,
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (v: string) => (
        <Tag className={cn(getSeverityColor(v))}>
          {getSeverityLabel(v)}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => (
        <Tag className={cn(getStatusColor(v))}>
          {getStatusLabel(v)}
        </Tag>
      ),
    },
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
      ellipsis: true,
      render: (v: string) => <span className="font-mono text-sm">{v}</span>,
    },
    {
      title: 'CVE',
      dataIndex: 'cve',
      key: 'cve',
      width: 120,
      render: (_, vuln) => vuln.cve || '-',
    },
    {
      title: '发现时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 170,
      render: (v: string) => formatDate(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      render: (_, vuln) => (
        <div className="flex gap-1">
          {vuln.status === 'new' && (
            <Button
              type="text"
              title="验证漏洞"
              // 行级 loading：只让正在验证的那一行转圈，其余行可继续操作
              loading={props.verifyingId === vuln.id}
              icon={<CheckCircle className="h-4 w-4 text-green-500" />}
              onClick={() => props.onVerify?.(vuln.id)}
            />
          )}
          <Link to={`/vulnerabilities/${vuln.id}`}>
            <Button type="text" icon={<Eye className="h-4 w-4" />} />
          </Link>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-4 flex-wrap">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground z-10" />
          <Input
            placeholder="搜索漏洞..."
            className="pl-9"
            value={props.search}
            onChange={(e) => props.onSearch(e.target.value)}
          />
        </div>
        <Select
          className="w-32"
          value={props.severityFilter}
          placeholder="严重程度"
          onChange={props.onSeverity}
          options={[
            { value: 'all', label: '全部' },
            { value: 'critical', label: '严重' },
            { value: 'high', label: '高危' },
            { value: 'medium', label: '中危' },
            { value: 'low', label: '低危' },
            { value: 'info', label: '信息' },
          ]}
        />
        <Select
          className="w-32"
          value={props.statusFilter}
          placeholder="状态"
          onChange={props.onStatus}
          options={[
            { value: 'all', label: '全部' },
            { value: 'new', label: '待复核' },
            { value: 'confirmed', label: '已确认' },
            { value: 'fixed', label: '已修复' },
            { value: 'ignored', label: '已忽略' },
            { value: 'false_positive', label: '误报' },
          ]}
        />

        {/* Batch Actions：常驻渲染按需禁用，勾选变化不引起工具栏重排 */}
        <Dropdown
          trigger={['click']}
          menu={{
            items: [
              { key: 'confirmed', label: '标记为已确认', onClick: () => props.onBatch('confirmed') },
              { key: 'fixed', label: '标记为已修复', onClick: () => props.onBatch('fixed') },
              { key: 'ignored', label: '标记为已忽略', onClick: () => props.onBatch('ignored') },
              { key: 'false_positive', label: '标记为误报', onClick: () => props.onBatch('false_positive') },
            ],
          }}
        >
          <Button size="small" disabled={props.selectedIds.length === 0}>
            批量操作{props.selectedIds.length > 0 ? ` (${props.selectedIds.length})` : ''}
            <MoreHorizontal className="ml-2 h-4 w-4" />
          </Button>
        </Dropdown>
      </div>

      {/* Table */}
      <div className="rounded-lg border">
        <Table
          rowSelection={{
            selectedRowKeys: props.selectedIds,
            onChange: (keys) => props.onSelected(keys as string[]),
          }}
          columns={columns}
          dataSource={props.rows}
          rowKey="id"
          loading={props.loading}
          locale={{
            emptyText: <EmptyState title="暂无数据" className="border-0" />,
          }}
          pagination={{
            current: props.page,
            pageSize: 10,
            total: props.total,
            showQuickJumper: true,
            // page_size 固定 10、无独立 pageSize 状态，不展示切换器
            showSizeChanger: false,
            hideOnSinglePage: true,
            onChange: props.onPage,
          }}
        />
      </div>
    </div>
  )
}

export default function VulnerabilitiesPage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState('dashboard')
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search)
  useEffect(() => { setPage(1) }, [debouncedSearch])
  // 仪表盘下钻入口：/vulnerabilities?severity=high 直接落到对应过滤视图
  const [searchParams] = useSearchParams()
  const [severityFilter, setSeverityFilter] = useState<string>(() => searchParams.get('severity') || 'all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [page, setPage] = useState(1)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [reportOpen, setReportOpen] = useState(false)

  const reportTemplatesQuery = useQuery({
    queryKey: ['report-templates'],
    queryFn: () => reportApi.templates(),
    staleTime: 10 * 60 * 1000,
  })
  const reportTemplates: ReportProfile[] = reportTemplatesQuery.data ?? []

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['vulnerabilities', page, debouncedSearch, severityFilter, statusFilter],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      vulnApi.getVulnerabilities({
        page,
        pageSize: 10,
        search: debouncedSearch,
        severity: severityFilter === 'all' ? undefined : severityFilter,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
  })

  const verifyMutation = useMutation({
    mutationFn: vulnApi.verifyVulnerability,
    onSuccess: (result) => {
      toast({
        title: result.data.verified ? '漏洞已验证存在' : '漏洞无法复现',
        variant: result.data.verified ? 'default' : 'destructive',
      })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['vulnStatistics'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '验证失败'), variant: 'destructive' })
    },
  })

  const batchUpdateMutation = useMutation({
    mutationFn: ({ ids, status }: { ids: string[]; status: string }) =>
      vulnApi.batchUpdateStatus(ids, status),
    onSuccess: (res) => {
      toast({ title: res.message || '批量复核完成' })
      setSelectedIds([])
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['vulnStatistics'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '批量更新失败'), variant: 'destructive' })
    },
  })

  const vulnerabilities: VulnRow[] = data?.data?.list || []
  const total = data?.data?.total || 0

  const handleBatchAction = async (status: string) => {
    if (selectedIds.length === 0) {
      toast({ title: '请先选择漏洞', variant: 'destructive' })
      return
    }
    // 批量改状态影响所有勾选行，先确认
    const ok = await confirm({
      title: `批量更新 ${selectedIds.length} 个漏洞？`,
      description: '状态将立即生效并写入复核记录。',
    })
    if (ok) batchUpdateMutation.mutate({ ids: selectedIds, status })
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Shield className="h-6 w-6" />
          漏洞管理
        </h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button
            size="small"
            onClick={() => setReportOpen(true)}
          >
            <Download className="h-4 w-4 mr-2" />
            导出报告
          </Button>
        </div>
      </div>

      {isError && (
        <div className="rounded-lg border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
          漏洞列表加载失败，可能为网络或服务异常。
          <Button type="link" size="small" onClick={() => refetch()}>重试</Button>
        </div>
      )}

      <ReportGenerateDialog
        open={reportOpen}
        onOpenChange={setReportOpen}
        defaultKind="vuln"
        templates={reportTemplates}
      />

      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'dashboard',
            label: (
              <span className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4" />
                统计面板
              </span>
            ),
            children: <VulnDashboard />,
          },
          {
            key: 'list',
            label: (
              <span className="flex items-center gap-2">
                <List className="h-4 w-4" />
                漏洞列表
              </span>
            ),
            children: (
              <VulnList
                rows={vulnerabilities}
                loading={isLoading}
                search={search}
                onSearch={setSearch}
                severityFilter={severityFilter}
                onSeverity={setSeverityFilter}
                statusFilter={statusFilter}
                onStatus={setStatusFilter}
                page={page}
                onPage={setPage}
                total={total}
                selectedIds={selectedIds}
                onSelected={setSelectedIds}
                onBatch={handleBatchAction}
                verifyingId={verifyMutation.variables}
                onVerify={(id) => verifyMutation.mutate(id)}
              />
            ),
          },
        ]}
      />
    </div>
  )
}

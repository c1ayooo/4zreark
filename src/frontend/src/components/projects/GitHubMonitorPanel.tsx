import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Card, Input, Skeleton, Switch, Table, Tag, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { Github, Plus } from 'lucide-react'
import { githubMonitorApi, type GitHubFinding } from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'

// GitHub 泄露监控（4zreco 迁移）：关键词在 GitHub 公开仓库搜索凭据泄露。
// 规则按项目绑定；规则名带项目名前缀，findings 溯源到本项目。

const severityVariant = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'border-transparent bg-red-600 text-white'
    case 'high':
      return 'border-transparent bg-orange-500 text-white'
    case 'medium':
      return 'border-transparent bg-amber-500 text-white'
    default:
      return 'border-transparent bg-secondary text-secondary-foreground'
  }
}

const statusMeta: Record<string, { label: string; cls: string }> = {
  new: { label: '新命中', cls: 'text-primary' },
  confirmed: { label: '已确认', cls: 'text-destructive' },
  ignored: { label: '已忽略', cls: 'text-muted-foreground' },
  resolved: { label: '已处置', cls: 'text-muted-foreground' },
}

const STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'new', label: '新命中' },
  { value: 'confirmed', label: '已确认' },
  { value: 'ignored', label: '已忽略' },
  { value: 'resolved', label: '已处置' },
]

export function GitHubMonitorPanel({ projectId }: { projectId: number }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [tokenInput, setTokenInput] = useState('')
  const [ruleInput, setRuleInput] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)

  const overviewQuery = useQuery({
    queryKey: ['github-monitor', projectId],
    queryFn: () => githubMonitorApi.overview(projectId),
    refetchInterval: 60000,
  })
  const overview = overviewQuery.data?.data
  const settings = overview?.settings
  const rules = overview?.rules ?? []

  const findingsQuery = useQuery({
    queryKey: ['github-monitor-findings', projectId, statusFilter, page],
    queryFn: () => githubMonitorApi.findings(projectId, { status: statusFilter || undefined, page, page_size: 10 }),
    enabled: overviewQuery.isSuccess,
    refetchInterval: 60000,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['github-monitor', projectId] })
    queryClient.invalidateQueries({ queryKey: ['github-monitor-findings', projectId] })
  }

  const settingsMutation = useMutation({
    mutationFn: (body: { enabled: boolean; token?: string }) =>
      githubMonitorApi.saveSettings(projectId, body),
    onSuccess: (res) => {
      toast({ title: res.message || '已保存，监控循环 2 分钟内生效' })
      setTokenInput('')
      invalidate()
    },
    onError: (e: Error) => toast({ title: '保存失败', description: e.message, variant: 'destructive' }),
  })

  const ruleMutation = useMutation({
    mutationFn: async (body: { keywords?: string[]; ruleId?: number }) => {
      if (body.ruleId != null) {
        await githubMonitorApi.deleteRule(projectId, body.ruleId)
        return { saved: true }
      }
      return githubMonitorApi.createRule(projectId, { keywords: body.keywords ?? [] })
    },
    onSuccess: (res: { message?: string } | { saved: boolean }) => {
      const msg = 'message' in res && res.message ? res.message : '已更新，监控循环 2 分钟内生效'
      toast({ title: msg })
      setRuleInput('')
      invalidate()
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const statusMutation = useMutation({
    mutationFn: ({ fid, status }: { fid: string; status: string }) =>
      githubMonitorApi.updateFindingStatus(projectId, fid, status),
    onSuccess: () => {
      toast({ title: '已更新' })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '更新失败', description: e.message, variant: 'destructive' }),
  })

  const addKeyword = () => {
    const kws = ruleInput
      .split(/[,，\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (kws.length === 0) return
    ruleMutation.mutate({ keywords: kws })
  }

  const columns: TableProps<GitHubFinding>['columns'] = [
    {
      title: '仓库',
      dataIndex: 'repository',
      key: 'repository',
      render: (_, f) => (
        <a href={f.html_url} target="_blank" rel="noreferrer" className="font-mono text-xs hover:underline">
          {f.repository}
        </a>
      ),
    },
    {
      title: '路径',
      dataIndex: 'path',
      key: 'path',
      render: (_, f) => (
        <Tooltip title={`${f.path}${f.line ? ':' + f.line : ''}`}>
          <span className="block max-w-[220px] truncate text-xs text-muted-foreground">{f.path}</span>
        </Tooltip>
      ),
    },
    {
      title: '类型',
      dataIndex: 'secret_type',
      key: 'secret_type',
      width: 130,
      render: (_, f) => <span className="text-xs">{f.secret_type}</span>,
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      key: 'severity',
      width: 90,
      render: (_, f) => <Tag className={severityVariant(f.severity)}>{f.severity}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, f) => {
        const meta = statusMeta[f.status] ?? { label: f.status, cls: 'text-muted-foreground' }
        return <span className={cn('text-xs', meta.cls)}>{meta.label}</span>
      },
    },
    {
      title: '发现时间',
      key: 'first_seen',
      width: 150,
      render: (_, f) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">
          {f.first_seen ? formatDate(f.first_seen) : '—'}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      render: (_, f) => (
        <div className="flex gap-2">
          {f.status === 'new' && (
            <>
              <Button
                type="link"
                size="small"
                className="h-auto p-0 text-destructive"
                loading={statusMutation.isPending}
                onClick={() => statusMutation.mutate({ fid: f.id, status: 'confirmed' })}
              >
                确认
              </Button>
              <Button
                type="link"
                size="small"
                className="h-auto p-0"
                onClick={() => statusMutation.mutate({ fid: f.id, status: 'ignored' })}
              >
                忽略
              </Button>
            </>
          )}
          {f.status !== 'new' && (
            <Button
              type="link"
              size="small"
              className="h-auto p-0"
              onClick={() => statusMutation.mutate({ fid: f.id, status: 'resolved' })}
            >
              标记处置
            </Button>
          )}
        </div>
      ),
    },
  ]

  const stats = overview?.stats ?? {}
  const newCount = Number(stats.new ?? 0)

  return (
    <Card
      title={
        <div className="flex flex-col gap-1">
          <span className="flex items-center gap-2">
            <Github className="size-4" />
            GitHub 监控
            {newCount > 0 && <Badge count={newCount} size="small" />}
          </span>
          <span className="text-xs font-normal leading-relaxed text-muted-foreground">
            按keywords周期搜索 GitHub 公开仓库，识别本项目资产的凭据泄露与敏感代码；关键词命中即入库人工研判。
          </span>
        </div>
      }
    >
      {overviewQuery.isLoading ? (
        <Skeleton active title={false} paragraph={{ rows: 4 }} />
      ) : (
        <div className="space-y-4">
          {/* 设置行：开关 + token */}
          <div className="flex flex-wrap items-center gap-3">
            <Switch
              checked={settings?.enabled ?? false}
              loading={settingsMutation.isPending}
              onChange={(enabled) => settingsMutation.mutate({ enabled, token: tokenInput })}
            />
            <span className="text-sm">{settings?.enabled ? '监控中' : '已停用'}</span>
            <Input.Password
              size="small"
              className="w-72"
              placeholder={settings?.token_configured ? '已配置 Token（输入新值可更换）' : 'GitHub Token（必填后才能启用）'}
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
            />
            <Button
              size="small"
              disabled={!tokenInput.trim()}
              loading={settingsMutation.isPending}
              onClick={() => settingsMutation.mutate({ enabled: settings?.enabled ?? false, token: tokenInput })}
            >
              保存 Token
            </Button>
            {!overview?.monitor_ready && (
              <span className="text-destructive text-xs">{overview?.monitor_error}</span>
            )}
          </div>

          {/* 规则：关键词集合 */}
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-muted-foreground text-xs">监控关键词：</span>
              {rules.length === 0 && <span className="text-muted-foreground text-xs">暂无（启用时自动按项目名创建一条）</span>}
              {rules.map((rule) => (
                <Tag
                  key={rule.id}
                  closable
                  onClose={(e) => {
                    e.preventDefault()
                    ruleMutation.mutate({ ruleId: rule.id })
                  }}
                >
                  {rule.name}: {rule.keywords.join(' / ')}
                </Tag>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                size="small"
                className="w-96"
                placeholder="新增关键词，逗号/空格分隔（如：lixiang.com 理想汽车 车励行）"
                value={ruleInput}
                onChange={(e) => setRuleInput(e.target.value)}
                onPressEnter={addKeyword}
              />
              <Button size="small" icon={<Plus className="size-3.5" />} loading={ruleMutation.isPending} onClick={addKeyword}>
                加关键词
              </Button>
            </div>
          </div>

          {/* 命中列表 */}
          <Table<GitHubFinding>
            columns={columns}
            dataSource={findingsQuery.data?.data?.items ?? []}
            rowKey="id"
            loading={findingsQuery.isLoading}
            size="small"
            locale={{ emptyText: '还没有命中——关键词生效后每轮监控自动补充' }}
            pagination={{
              current: page,
              pageSize: 10,
              total: findingsQuery.data?.data?.total ?? 0,
              showSizeChanger: false,
              onChange: setPage,
              hideOnSinglePage: true,
            }}
            title={() => (
              <div className="flex items-center gap-2">
                {STATUS_OPTIONS.map((o) => (
                  <Button
                    key={o.value}
                    size="small"
                    type={statusFilter === o.value ? 'primary' : 'default'}
                    className="h-6 px-2 text-xs"
                    onClick={() => {
                      setStatusFilter(o.value)
                      setPage(1)
                    }}
                  >
                    {o.label}
                  </Button>
                ))}
                <span className="text-muted-foreground ml-1 text-xs">
                  共 {findingsQuery.data?.data?.total ?? 0} 条
                </span>
              </div>
            )}
          />
        </div>
      )}
    </Card>
  )
}

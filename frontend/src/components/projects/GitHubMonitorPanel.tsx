import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Card, Input, Modal, Popconfirm, Progress, Select, Skeleton, Switch, Table, Tag, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { Github, Plus, RefreshCw, Shield, Zap } from 'lucide-react'
import {
  githubMonitorApi,
  type GitHubCleanupReport,
  type GitHubFinding,
  type GitHubPoolToken,
  type GitHubSuppression,
} from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'

import { safeExternalURL } from '@/lib/safeUrl'
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

const SUPPRESSION_TYPE_OPTIONS = [
  { value: 'repo', label: '仓库（owner/name）' },
  { value: 'org', label: '组织/用户' },
  { value: 'path_glob', label: '路径通配' },
  { value: 'rule', label: '规则名' },
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

  // ---- 全局运维：立即巡查 / 补全明文 / 历史清理（两段式）/ 抑制 / Token 池 ----
  const opsInvalidate = () => {
    invalidate()
    queryClient.invalidateQueries({ queryKey: ['github-leak-ops'] })
  }

  const opsMutation = useMutation({
    mutationFn: async (action: 'run' | 'backfill' | 'refresh-tokens') => {
      if (action === 'run') return githubMonitorApi.runNow()
      if (action === 'backfill') return githubMonitorApi.backfill()
      return githubMonitorApi.refreshAllTokens()
    },
    onSuccess: (res, action) => {
      const msg =
        action === 'run'
          ? '已加入巡查队列'
          : action === 'backfill'
            ? `已补全 ${(res.data as { filled?: number } | undefined)?.filled ?? 0} 条明文`
            : '全池配额已刷新'
      toast({ title: msg })
      opsInvalidate()
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const tokensQuery = useQuery({
    queryKey: ['github-leak-ops', 'tokens'],
    queryFn: () => githubMonitorApi.tokens(),
    refetchInterval: 120000,
  })
  const tokens = tokensQuery.data?.data ?? []

  const suppressionsQuery = useQuery({
    queryKey: ['github-leak-ops', 'suppressions'],
    queryFn: () => githubMonitorApi.listSuppressions(),
  })
  const suppressions = suppressionsQuery.data?.data?.suppressions ?? []

  const suppressionMutation = useMutation({
    mutationFn: async (action: { type: 'add'; body: { pattern_type: string; pattern: string; note?: string } } | { type: 'delete'; id: string }) => {
      if (action.type === 'delete') return githubMonitorApi.deleteSuppression(action.id)
      return githubMonitorApi.addSuppression(action.body)
    },
    onSuccess: (res: { message?: string }) => {
      toast({ title: res.message || '已保存' })
      setSuppPattern('')
      setSuppNote('')
      queryClient.invalidateQueries({ queryKey: ['github-leak-ops'] })
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const tokenMutation = useMutation({
    mutationFn: async (action: { type: 'add'; token: string; label?: string } | { type: 'delete'; id: string } | { type: 'enable'; id: string; enabled: boolean }) => {
      if (action.type === 'delete') return githubMonitorApi.deleteToken(action.id)
      if (action.type === 'enable') return githubMonitorApi.setTokenEnabled(action.id, action.enabled)
      return githubMonitorApi.addToken({ token: action.token, label: action.label })
    },
    onSuccess: (res: { message?: string }) => {
      toast({ title: res.message || '已更新' })
      setPoolTokenInput('')
      setPoolLabelInput('')
      queryClient.invalidateQueries({ queryKey: ['github-leak-ops'] })
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const [suppPattern, setSuppPattern] = useState('')
  const [suppType, setSuppType] = useState('repo')
  const [suppNote, setSuppNote] = useState('')
  const [poolTokenInput, setPoolTokenInput] = useState('')
  const [poolLabelInput, setPoolLabelInput] = useState('')

  /** 历史清理两段式：先预览拿报告，用户确认后才真正删除 */
  const cleanupPreview = useMutation({
    mutationFn: () => githubMonitorApi.cleanupPreview(),
    onSuccess: (res) => {
      const report = res.data as GitHubCleanupReport
      Modal.confirm({
        title: '确认清理历史噪音命中？',
        width: 560,
        content: (
          <div className="text-sm">
            <p>
              扫描 <b>{report.total}</b> 条历史命中，匹配噪音特征 <b className="text-destructive">{report.matched}</b> 条，
              执行后不可恢复。
            </p>
            {Object.keys(report.by_status ?? {}).length > 0 && (
              <p className="mt-2 text-xs text-muted-foreground">
                按状态：{Object.entries(report.by_status).map(([k, v]) => `${k}=${v}`).join('，')}
              </p>
            )}
            {Object.keys(report.by_type ?? {}).length > 0 && (
              <p className="text-xs text-muted-foreground">
                按类型：{Object.entries(report.by_type).map(([k, v]) => `${k}=${v}`).join('，')}
              </p>
            )}
          </div>
        ),
        okText: `删除 ${report.matched} 条`,
        okType: 'danger',
        cancelText: '取消',
        onOk: async () => {
          try {
            const r2 = await githubMonitorApi.cleanupApply()
            toast({ title: `已删除 ${r2.data?.deleted ?? 0} 条` })
            opsInvalidate()
          } catch (e) {
            toast({ title: '清理失败', description: (e as Error).message, variant: 'destructive' })
          }
        },
      })
    },
    onError: (e: Error) => toast({ title: '预览失败', description: e.message, variant: 'destructive' }),
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
        <a href={safeExternalURL(f.html_url) ?? undefined} target="_blank" rel="noreferrer" className="font-mono text-xs hover:underline">
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
                placeholder="新增关键词，逗号/空格分隔（如：example.com 某公司名 内部系统代号）"
                value={ruleInput}
                onChange={(e) => setRuleInput(e.target.value)}
                onPressEnter={addKeyword}
              />
              <Button size="small" icon={<Plus className="size-3.5" />} loading={ruleMutation.isPending} onClick={addKeyword}>
                加关键词
              </Button>
            </div>
          </div>

          {/* 全局运维：巡查/补全/清理/配额 */}
          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Zap className="size-3.5" /> 全局运维：
            </span>
            <Button
              size="small"
              icon={<RefreshCw className="size-3.5" />}
              loading={opsMutation.isPending && opsMutation.variables === 'run'}
              onClick={() => opsMutation.mutate('run')}
            >
              立即巡查
            </Button>
            <Button
              size="small"
              loading={opsMutation.isPending && opsMutation.variables === 'backfill'}
              onClick={() => opsMutation.mutate('backfill')}
            >
              补全明文（≤50）
            </Button>
            <Button size="small" loading={cleanupPreview.isPending} onClick={() => cleanupPreview.mutate()}>
              历史噪音清理
            </Button>
            <Button
              size="small"
              loading={opsMutation.isPending && opsMutation.variables === 'refresh-tokens'}
              onClick={() => opsMutation.mutate('refresh-tokens')}
            >
              刷新全部配额
            </Button>
          </div>

          {/* Token 池：多账号轮换，配额展示 */}
          <div className="rounded-lg border border-border p-3">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="flex items-center gap-1 text-xs font-medium">
                <Shield className="size-3.5" /> Token 池（多账号轮换，按剩余配额选号）
              </span>
              <span className="text-xs text-muted-foreground">
                池为空时使用上方项目 Token；同号重复入池会被拒绝
              </span>
            </div>
            <div className="mb-2 flex flex-wrap gap-2">
              <Input
                size="small"
                className="w-56"
                placeholder="备注名（可选，缺省用掩码）"
                value={poolLabelInput}
                onChange={(e) => setPoolLabelInput(e.target.value)}
              />
              <Input.Password
                size="small"
                className="w-80"
                placeholder="ghp_… 开头的 Personal Access Token"
                value={poolTokenInput}
                onChange={(e) => setPoolTokenInput(e.target.value)}
              />
              <Button
                size="small"
                icon={<Plus className="size-3.5" />}
                disabled={!poolTokenInput.trim()}
                loading={tokenMutation.isPending}
                onClick={() => tokenMutation.mutate({ type: 'add', token: poolTokenInput.trim(), label: poolLabelInput.trim() || undefined })}
              >
                入池
              </Button>
            </div>
            {tokens.length > 0 && (
              <Table<GitHubPoolToken>
                rowKey="id"
                size="small"
                dataSource={tokens}
                pagination={false}
                locale={{ emptyText: '池为空' }}
                columns={[
                  {
                    title: '账号',
                    key: 'label',
                    render: (_, t) => (
                      <div className="text-xs">
                        <div className="font-medium">{t.label}</div>
                        <div className="font-mono text-[10px] text-muted-foreground">{t.masked}</div>
                      </div>
                    ),
                  },
                  {
                    title: '剩余配额',
                    key: 'rate',
                    width: 180,
                    render: (_, t) =>
                      t.rate_remaining < 0 ? (
                        <span className="text-xs text-muted-foreground">未采集</span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <Progress
                            percent={t.rate_limit ? Math.round((t.rate_remaining / t.rate_limit) * 100) : 0}
                            size="small"
                            className="w-24 [&_.ant-progress-text]:text-[10px]"
                            strokeColor={t.rate_remaining <= 0 ? '#ef4444' : undefined}
                          />
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {t.rate_remaining}/{t.rate_limit}
                          </span>
                        </div>
                      ),
                  },
                  {
                    title: '重置时间',
                    key: 'reset',
                    width: 140,
                    render: (_, t) => (
                      <span className="text-[10px] text-muted-foreground">
                        {t.rate_reset_at ? formatDate(t.rate_reset_at) : '—'}
                      </span>
                    ),
                  },
                  {
                    title: '启用',
                    key: 'enabled',
                    width: 70,
                    render: (_, t) => (
                      <Switch
                        size="small"
                        checked={t.enabled}
                        onChange={(enabled) => tokenMutation.mutate({ type: 'enable', id: t.id, enabled })}
                      />
                    ),
                  },
                  {
                    title: '操作',
                    key: 'ops',
                    width: 120,
                    render: (_, t) => (
                      <div className="flex gap-2">
                        <Button
                          type="link"
                          size="small"
                          className="h-auto p-0 text-xs"
                          onClick={() => githubMonitorApi.refreshToken(t.id).then(() => {
                            toast({ title: `${t.label} 已刷新` })
                            queryClient.invalidateQueries({ queryKey: ['github-leak-ops'] })
                          })}
                        >
                          刷新
                        </Button>
                        <Popconfirm title="删除该 Token？" onConfirm={() => tokenMutation.mutate({ type: 'delete', id: t.id })}>
                          <Button type="link" size="small" className="h-auto p-0 text-xs text-destructive">
                            删除
                          </Button>
                        </Popconfirm>
                      </div>
                    ),
                  },
                ]}
              />
            )}
          </div>

          {/* 误报抑制管理 */}
          <div className="rounded-lg border border-border p-3">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium">误报抑制（命中不再入库）</span>
              <span className="text-xs text-muted-foreground">标记误报时也会自动按指纹静默</span>
            </div>
            <div className="mb-2 flex flex-wrap gap-2">
              <Select
                size="small"
                className="w-40"
                value={suppType}
                onChange={setSuppType}
                options={SUPPRESSION_TYPE_OPTIONS}
              />
              <Input
                size="small"
                className="w-72"
                placeholder="匹配值（如 owner/repo、*.example.com/*）"
                value={suppPattern}
                onChange={(e) => setSuppPattern(e.target.value)}
              />
              <Input
                size="small"
                className="w-48"
                placeholder="备注（可选）"
                value={suppNote}
                onChange={(e) => setSuppNote(e.target.value)}
              />
              <Button
                size="small"
                icon={<Plus className="size-3.5" />}
                disabled={!suppPattern.trim()}
                loading={suppressionMutation.isPending}
                onClick={() => suppressionMutation.mutate({ type: 'add', body: { pattern_type: suppType, pattern: suppPattern.trim(), note: suppNote.trim() || undefined } })}
              >
                加抑制
              </Button>
            </div>
            {suppressions.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {suppressions.map((s: GitHubSuppression) => (
                  <Tag
                    key={s.id}
                    closable
                    onClose={(e) => {
                      e.preventDefault()
                      suppressionMutation.mutate({ type: 'delete', id: s.id })
                    }}
                    className="max-w-[420px]"
                  >
                    <span className="font-mono text-[10px] text-muted-foreground">[{s.pattern_type}]</span> {s.pattern}
                    {s.note && <span className="ml-1 text-[10px] text-muted-foreground">· {s.note}</span>}
                  </Tag>
                ))}
              </div>
            )}
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

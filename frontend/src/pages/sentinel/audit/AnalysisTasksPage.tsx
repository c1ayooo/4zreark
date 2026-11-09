/**
 * 代码审计 · 分析任务
 *
 * 「任务」在这里是采集任务：每条监控仓库按 interval_minutes 进调度，
 * worker 执行 git fetch + rev-list + git show，落库待判定的提交。
 *
 * 真实接口（api/sentinel.ts）：
 *   GET    /api/sentinel/overview
 *   GET    /api/sentinel/repos?keyword=
 *   POST   /api/sentinel/repos            {full_name?, clone_url, branch?, interval_minutes?, enabled?}
 *   PUT    /api/sentinel/repos/{id}       {enabled?, interval_minutes?, branch?, clone_url?}
 *   DELETE /api/sentinel/repos/{id}
 *   POST   /api/sentinel/repos/{id}/collect
 */
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Drawer, Form, Input, Popconfirm, Select, Switch, Table } from 'antd'
import type { TableProps } from 'antd'
import { ExternalLink, Plus, RefreshCw, Search, Sparkles, Trash2 } from 'lucide-react'
import { sentinelApi, type SentinelRepo } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import {
  EmptyBlock,
  ErrorPanel,
  Metric,
  PageHeader,
  RepoHealthTag,
  fmtNumber,
  fmtRelative,
} from './shared'

const INTERVAL_OPTIONS = [
  { value: 30, label: '30 分钟' },
  { value: 60, label: '1 小时' },
  { value: 180, label: '3 小时' },
  { value: 360, label: '6 小时' },
  { value: 720, label: '12 小时' },
  { value: 1440, label: '24 小时' },
]

interface CreateForm {
  clone_url: string
  full_name?: string
  branch?: string
  interval_minutes: number
  enabled: boolean
}

export default function AnalysisTasksPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [keyword, setKeyword] = useState('')
  const [onlyEnabled, setOnlyEnabled] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<CreateForm>()

  const overviewQuery = useQuery({
    queryKey: ['sentinel', 'overview'],
    queryFn: () => sentinelApi.overview(),
    refetchInterval: 30000,
  })
  const reposQuery = useQuery({
    queryKey: ['sentinel', 'repos', keyword],
    queryFn: () => sentinelApi.repos(keyword.trim() || undefined),
    refetchInterval: 30000,
  })
  // 审计技能：判定时注入的检查顺序（对话页可单独选）
  const skillsQuery = useQuery({
    queryKey: ['sentinel', 'skills'],
    queryFn: () => sentinelApi.skills(),
    staleTime: 5 * 60_000,
  })
  const setDefaultSkill = useMutation({
    mutationFn: (skillId: string) => sentinelApi.setDefaultSkill(skillId),
    onSuccess: (_d, skillId) => {
      toast({ title: skillId ? '已切换判定技能' : '已关闭技能注入' })
      queryClient.invalidateQueries({ queryKey: ['sentinel', 'skills'] })
    },
    onError: (e: Error) => toast({ title: '切换失败', description: e.message, variant: 'destructive' }),
  })

  const overview = overviewQuery.data
  const repos = reposQuery.data?.items ?? []
  const cloneHosts = reposQuery.data?.clone_hosts ?? []

  const rows = useMemo(
    () => (onlyEnabled ? repos.filter((r) => r.enabled) : repos),
    [repos, onlyEnabled],
  )

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['sentinel'] })
  }

  const createMutation = useMutation({
    mutationFn: (v: CreateForm) => sentinelApi.createRepo(v),
    onSuccess: (res) => {
      toast({ title: res.message || '已创建并开始采集' })
      setCreateOpen(false)
      form.resetFields()
      invalidate()
    },
    onError: (e: Error) =>
      toast({ title: '创建失败', description: e?.message, variant: 'destructive' }),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      sentinelApi.updateRepo(id, { enabled }),
    onSuccess: () => invalidate(),
    onError: (e: Error) =>
      toast({ title: '更新失败', description: e?.message, variant: 'destructive' }),
  })

  const collectMutation = useMutation({
    mutationFn: (id: string) => sentinelApi.collectRepo(id),
    onSuccess: (res) => {
      toast({ title: res.message || '已加入采集队列' })
      invalidate()
    },
    onError: (e: Error) =>
      toast({ title: '入队失败', description: e?.message, variant: 'destructive' }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => sentinelApi.deleteRepo(id),
    onSuccess: () => {
      toast({ title: '已删除' })
      invalidate()
    },
    onError: (e: Error) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const columns: TableProps<SentinelRepo>['columns'] = [
    {
      title: '仓库',
      key: 'repo',
      render: (_, r) => (
        <div className="min-w-[260px]">
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-[12.5px] font-medium text-foreground">{r.full_name}</span>
            <a
              href={r.clone_url}
              target="_blank"
              rel="noreferrer"
              className="text-muted-foreground hover:text-primary"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink size={11} />
            </a>
          </div>
          <div className="truncate font-mono text-[10.5px] text-muted-foreground">{r.clone_url}</div>
        </div>
      ),
    },
    {
      title: '分支',
      key: 'branch',
      width: 110,
      render: (_, r) => (
        <span className="font-mono text-[11px] text-secondary-foreground">
          {r.branch || r.default_branch || 'main'}
          {!r.branch && <span className="ml-1 text-[9.5px] text-muted-foreground">默认</span>}
        </span>
      ),
    },
    {
      title: '间隔',
      key: 'interval',
      width: 84,
      render: (_, r) => (
        <span className="font-mono text-[11px] text-secondary-foreground">{r.interval_minutes} 分</span>
      ),
    },
    {
      title: '状态',
      key: 'health',
      width: 108,
      render: (_, r) => <RepoHealthTag repo={r} />,
    },
    {
      title: '上次采集',
      key: 'checked',
      width: 150,
      render: (_, r) => (
        <div className="leading-tight">
          <div className="text-[11px] text-secondary-foreground">{fmtRelative(r.last_checked_at)}</div>
          <div className="font-mono text-[10px] text-muted-foreground">
            {r.last_commit_sha ? r.last_commit_sha.slice(0, 8) : '—'}
          </div>
        </div>
      ),
    },
    {
      title: '启用',
      key: 'enabled',
      width: 68,
      render: (_, r) => (
        <Switch
          size="small"
          checked={r.enabled}
          loading={toggleMutation.isPending && toggleMutation.variables?.id === r.id}
          onChange={(checked) => toggleMutation.mutate({ id: r.id, enabled: checked })}
        />
      ),
    },
    {
      title: '操作',
      key: 'action',
      width: 156,
      render: (_, r) => (
        <div className="flex items-center gap-1">
          <Button
            size="small"
            type="text"
            icon={<RefreshCw size={12} />}
            className="!px-1.5 text-[11px]"
            loading={collectMutation.isPending && collectMutation.variables === r.id}
            onClick={() => collectMutation.mutate(r.id)}
          >
            采集
          </Button>
          <Popconfirm
            title="删除仓库"
            description="提交、判定与发现会级联删除，不可恢复"
            okText="删除"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => deleteMutation.mutate(r.id)}
          >
            <Button size="small" type="text" danger icon={<Trash2 size={12} />} className="!px-1.5 text-[11px]">
              删除
            </Button>
          </Popconfirm>
        </div>
      ),
    },
  ]

  const loading = overviewQuery.isLoading || reposQuery.isLoading
  const error = overviewQuery.error ?? reposQuery.error

  return (
    <div className="space-y-4">
      <PageHeader
        title="分析任务"
        desc="监控仓库 → 定时采集提交 → 投喂判定队列；只接受白名单 host 的公开仓库"
        actions={
          <Button size="small" icon={<Plus size={13} />} onClick={() => setCreateOpen(true)}>
            监控仓库
          </Button>
        }
      />

      {error ? (
        <ErrorPanel
          error={error}
          onRetry={() => {
            overviewQuery.refetch()
            reposQuery.refetch()
          }}
        />
      ) : null}

      {/* 审计技能：判定链路注入哪套检查项 */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-card px-3 py-2">
        <Sparkles size={13} className="text-accent-foreground" />
        <span className="text-[12px] font-medium text-foreground">审计技能</span>
        <Select
          size="small"
          className="w-[240px]"
          value={skillsQuery.data?.default_id ?? ''}
          loading={skillsQuery.isLoading}
          onChange={(v) => setDefaultSkill.mutate(v)}
          options={[
            { value: '', label: '不注入技能' },
            ...(skillsQuery.data?.items ?? []).map((s) => ({
              value: s.id,
              label: `${s.name} ${s.version}`,
            })),
          ]}
        />
        <span className="text-[10.5px] text-muted-foreground">
          判定时把该技能的检查顺序注入系统提示；对话页可单独选，两者共用同一份技能库
        </span>
      </div>

      <div className="grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-5">
        <Metric
          label="监控仓库"
          value={loading ? '…' : fmtNumber(overview?.repo_count)}
          hint={`${repos.filter((r) => r.enabled).length} 个启用`}
        />
        <Metric
          label="今日提交"
          value={loading ? '…' : fmtNumber(overview?.today_commits)}
          hint="committed_at 落在今天"
        />
        <Metric
          label="累计安全修复"
          value={loading ? '…' : fmtNumber(overview?.security_fixes)}
          hint="judgment.is_security_fix"
          tone="text-sky-700 dark:text-sky-400"
        />
        <Metric
          label="待判定"
          value={loading ? '…' : fmtNumber(overview?.pending_commits)}
          hint="commit.status = pending"
          tone={overview?.pending_commits ? 'text-amber-700 dark:text-amber-400' : undefined}
        />
        <Metric
          label="队列积压"
          value={loading ? '…' : fmtNumber(overview?.queue_backlog)}
          hint="river_job 采集 + 判定"
          tone={overview?.queue_backlog ? 'text-amber-700 dark:text-amber-400' : undefined}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          placeholder="按仓库名搜索…"
          allowClear
          prefix={<Search className="h-3.5 w-3.5 text-muted-foreground" />}
          className="w-full sm:w-[240px]"
        />
        <label className="flex items-center gap-1.5 text-[11px] text-secondary-foreground">
          <Switch size="small" checked={onlyEnabled} onChange={setOnlyEnabled} />
          只看启用
        </label>
        <span className="text-[10.5px] text-muted-foreground">
          {rows.length} 个仓库
        </span>
        {cloneHosts.length > 0 && (
          <span className="ml-auto text-[10.5px] text-muted-foreground">
            允许 clone 的 host：<span className="font-mono">{cloneHosts.join(', ')}</span>
          </span>
        )}
      </div>

      <div className="overflow-hidden rounded-xl border border-border bg-card">
        {!loading && rows.length === 0 && !error ? (
          <div className="p-3">
            <EmptyBlock>
              还没有监控仓库。点右上角「监控仓库」添加一个 <span className="font-mono">https://github.com/owner/repo</span>{' '}
              —— 创建后会立刻排一次采集。
            </EmptyBlock>
          </div>
        ) : (
          <Table
            rowKey={(r) => r.id}
            size="middle"
            loading={loading}
            columns={columns}
            dataSource={rows}
            pagination={false}
          />
        )}
      </div>

      <div className="text-[10.5px] leading-relaxed text-muted-foreground">
        采集只走 <span className="font-mono">git clone --bare</span> + <span className="font-mono">rev-list</span>{' '}
        增量区间，不经过 shell；因为凭证不能写进 mirror 的 config，私有仓库目前不在支持范围。
        调度周期由仓库的间隔决定，master 每分钟扫一次到期仓库。
      </div>

      <Drawer
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={520}
        title="新增监控仓库"
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ interval_minutes: 60, enabled: true }}
          onFinish={(v) => createMutation.mutate(v)}
        >
          <Form.Item
            name="clone_url"
            label="Clone URL"
            rules={[
              { required: true, message: '填写仓库地址' },
              {
                pattern: /^https:\/\/[^\s]+$/i,
                message: '只接受 https:// 开头的地址',
              },
            ]}
            extra={cloneHosts.length ? `host 必须在白名单内：${cloneHosts.join(', ')}` : undefined}
          >
            <Input placeholder="https://github.com/owner/repo.git" allowClear />
          </Form.Item>
          <Form.Item
            name="full_name"
            label="仓库名"
            extra="留空则从 URL 推导 owner/repo"
          >
            <Input placeholder="owner/repo" allowClear />
          </Form.Item>
          <Form.Item name="branch" label="分支" extra="留空跟随默认分支">
            <Input placeholder="main" allowClear />
          </Form.Item>
          <Form.Item name="interval_minutes" label="采集间隔" rules={[{ required: true }]}>
            <Select options={INTERVAL_OPTIONS} />
          </Form.Item>
          <Form.Item name="enabled" label="创建后启用" valuePropName="checked">
            <Switch />
          </Form.Item>
          <div className="flex items-center gap-2">
            <Button type="primary" htmlType="submit" loading={createMutation.isPending}>
              创建并采集
            </Button>
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <span className="ml-auto text-[10.5px] text-muted-foreground">
              间隔最小 10 分钟；默认 60
            </span>
          </div>
        </Form>
      </Drawer>
    </div>
  )
}

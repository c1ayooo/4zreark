import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Popconfirm, Progress, Switch, Table } from 'antd'
import { KeyRound, Plus } from 'lucide-react'
import { githubMonitorApi, type GitHubPoolToken } from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { LEAK_OPS_KEY } from './shared'

/** Token 池：多账号按剩余配额轮换；明文只在提交时输入，列表仅回显掩码。 */
export function TokenPoolCard() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [label, setLabel] = useState('')
  const [token, setToken] = useState('')

  const tokensQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'tokens'],
    queryFn: () => githubMonitorApi.tokens(),
    refetchInterval: 120000,
  })
  const tokens = tokensQuery.data?.data ?? []

  const invalidate = () => queryClient.invalidateQueries({ queryKey: LEAK_OPS_KEY })

  const mutation = useMutation({
    mutationFn: async (
      action:
        | { type: 'add'; token: string; label?: string }
        | { type: 'delete'; id: string }
        | { type: 'enable'; id: string; enabled: boolean }
        | { type: 'refresh'; id: string },
    ) => {
      if (action.type === 'delete') return githubMonitorApi.deleteToken(action.id)
      if (action.type === 'enable') return githubMonitorApi.setTokenEnabled(action.id, action.enabled)
      if (action.type === 'refresh') return githubMonitorApi.refreshToken(action.id)
      return githubMonitorApi.addToken({ token: action.token, label: action.label })
    },
    onSuccess: (res) => {
      toast({ title: res.message || '已更新' })
      setLabel('')
      setToken('')
      invalidate()
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const columns = [
    {
      title: '账号',
      key: 'label',
      width: 200,
      render: (_: unknown, t: GitHubPoolToken) => (
        <div className="text-xs">
          <div className="font-medium">{t.label}</div>
          <div className="font-mono text-[10px] text-muted-foreground">{t.masked}</div>
        </div>
      ),
    },
    {
      title: '剩余配额',
      key: 'rate',
      width: 190,
      render: (_: unknown, t: GitHubPoolToken) =>
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
      width: 150,
      render: (_: unknown, t: GitHubPoolToken) => (
        <span className="text-[10px] text-muted-foreground">
          {t.rate_reset_at ? formatDate(t.rate_reset_at) : '—'}
        </span>
      ),
    },
    {
      title: '启用',
      key: 'enabled',
      width: 70,
      render: (_: unknown, t: GitHubPoolToken) => (
        <Switch
          size="small"
          checked={t.enabled}
          loading={mutation.isPending && mutation.variables?.type === 'enable'}
          onChange={(enabled) => mutation.mutate({ type: 'enable', id: t.id, enabled })}
        />
      ),
    },
    {
      title: '操作',
      key: 'ops',
      width: 120,
      render: (_: unknown, t: GitHubPoolToken) => (
        <div className="flex gap-2">
          <Button
            type="link"
            size="small"
            className="h-auto p-0 text-xs"
            loading={mutation.isPending && mutation.variables?.type === 'refresh'}
            onClick={() => mutation.mutate({ type: 'refresh', id: t.id })}
          >
            刷新
          </Button>
          <Popconfirm title="删除该 Token？" onConfirm={() => mutation.mutate({ type: 'delete', id: t.id })}>
            <Button type="link" size="small" className="h-auto p-0 text-xs text-destructive">
              删除
            </Button>
          </Popconfirm>
        </div>
      ),
    },
  ]

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4">
      <div className="mb-1 flex items-center gap-2 text-sm font-semibold">
        <KeyRound className="size-4 text-primary" /> Token 池
      </div>
      <p className="mb-3 text-xs text-muted-foreground">
        多账号按剩余配额轮换（5000 次/日/号）；池为空时回退项目级单 Token。同号重复入池会被拒绝，token 不回显。
      </p>
      <div className="mb-3 flex flex-wrap gap-2">
        <Input
          size="small"
          className="w-52"
          placeholder="备注名（可选）"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
        />
        <Input.Password
          size="small"
          className="w-80"
          placeholder="ghp_… 开头的 Personal Access Token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          onPressEnter={() => token.trim() && mutation.mutate({ type: 'add', token: token.trim(), label: label.trim() || undefined })}
        />
        <Button
          size="small"
          type="primary"
          icon={<Plus className="size-3.5" />}
          disabled={!token.trim()}
          loading={mutation.isPending && mutation.variables?.type === 'add'}
          onClick={() => mutation.mutate({ type: 'add', token: token.trim(), label: label.trim() || undefined })}
        >
          入池
        </Button>
      </div>
      <Table<GitHubPoolToken>
        rowKey="id"
        size="small"
        tableLayout="fixed"
        columns={columns}
        dataSource={tokens}
        loading={tokensQuery.isLoading}
        pagination={false}
        scroll={{ x: 730 }}
        locale={{ emptyText: '池为空——监控将使用项目级单 Token' }}
      />
    </div>
  )
}

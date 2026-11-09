import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Input, Popconfirm, Tag } from 'antd'
import { KeyRound, Plus, Trash2 } from 'lucide-react'
import { getErrorMessage } from '@/lib/errors'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { githubTokensApi, GitHubToken } from '@/api/githubTokens'

// 卡片标题：主标题 + 说明小字，与设置页其他 tab 一致。
function cardTitle(title: string, desc: string) {
  return (
    <div className="flex flex-col gap-1">
      <span>{title}</span>
      <span className="text-xs font-normal leading-relaxed text-muted-foreground">{desc}</span>
    </div>
  )
}

function quotaText(t: GitHubToken) {
  if (!t.enabled) return '—'
  if (t.rate_remaining < 0) return '未采集'
  return `${t.rate_remaining}/${t.rate_limit}`
}

export function GitHubTokenPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [token, setToken] = useState('')

  const tokensQuery = useQuery({
    queryKey: ['github-tokens'],
    queryFn: () => githubTokensApi.list(),
  })
  const items: GitHubToken[] = tokensQuery.data?.data?.items ?? []

  const add = useMutation({
    mutationFn: () => githubTokensApi.add({ label: name.trim() || undefined, token: token.trim() }),
    onSuccess: () => {
      toast({ title: 'Token 已添加' })
      setName('')
      setToken('')
      queryClient.invalidateQueries({ queryKey: ['github-tokens'] })
    },
    onError: (e: unknown) =>
      toast({ title: '添加失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (id: string) => githubTokensApi.remove(id),
    onSuccess: () => {
      toast({ title: 'Token 已删除' })
      queryClient.invalidateQueries({ queryKey: ['github-tokens'] })
    },
    onError: (e: unknown) =>
      toast({ title: '删除失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  const submit = () => {
    if (!token.trim()) return
    add.mutate()
  }

  return (
    <div className="space-y-4">
      <Card
        title={cardTitle(
          'GitHub Token 池',
          '平台统一池：sentinel 采集认证、GitHub 泄露监控、情报 PoC 检索共用；多条轮询使用，入池后自动采集剩余配额。'
        )}
      >
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="w-56"
              placeholder="名称（可空，默认脱敏串）"
              value={name}
              onChange={(e) => setName(e.target.value)}
              onPressEnter={submit}
            />
            <Input.Password
              className="min-w-72 flex-1"
              placeholder="ghp_ / github_pat_ …"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              onPressEnter={submit}
            />
            <Button
              type="primary"
              icon={<Plus className="h-4 w-4" />}
              disabled={!token.trim()}
              loading={add.isPending}
              onClick={submit}
            >
              添加
            </Button>
          </div>

          <div className="rounded-md border">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b text-left text-xs text-muted-foreground">
                  <th className="p-2">名称</th>
                  <th className="p-2">Token</th>
                  <th className="p-2">状态</th>
                  <th className="p-2">剩余配额</th>
                  <th className="p-2">添加时间</th>
                  <th className="p-2 text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((t) => (
                  <tr key={t.id} className="border-b last:border-0">
                    <td className="p-2 font-medium">{t.label || '—'}</td>
                    <td className="p-2 font-mono text-xs">{t.masked}</td>
                    <td className="p-2">
                      {t.enabled ? (
                        <Tag className="border-transparent bg-emerald-600 text-white">启用</Tag>
                      ) : (
                        <Tag>停用</Tag>
                      )}
                    </td>
                    <td className="p-2 text-muted-foreground">{quotaText(t)}</td>
                    <td className="p-2 text-muted-foreground">
                      {t.created_at ? formatDate(t.created_at) : '—'}
                    </td>
                    <td className="p-2 text-right">
                      <Popconfirm
                        title={`删除 Token「${t.label || t.masked}」？`}
                        onConfirm={() => remove.mutate(t.id)}
                      >
                        <Button type="text" size="small" danger disabled={remove.isPending}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </Popconfirm>
                    </td>
                  </tr>
                ))}
                {items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="p-6 text-center text-sm text-muted-foreground">
                      <span className="inline-flex items-center gap-1">
                        <KeyRound className="h-4 w-4" />
                        还没有 Token
                      </span>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {tokensQuery.isError && (
            <div className="text-sm text-destructive">
              读取失败：{getErrorMessage(tokensQuery.error)}
            </div>
          )}
        </div>
      </Card>
    </div>
  )
}

import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, InputNumber, Skeleton, Switch, Tag } from 'antd'

import { mcpGovernanceApi, type MCPGovernanceOverview } from '@/api/mcpGovernance'
import type { ApiResponse } from '@/lib/api'
import { getErrorMessage } from '@/lib/errors'
import { useToast } from '@/components/ui/use-toast'

const QUERY_KEY = ['mcp-governance']

export function MCPGovernancePanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const overview = useQuery({
    queryKey: QUERY_KEY,
    queryFn: mcpGovernanceApi.overview,
  })
  const tools = overview.data?.data?.tools ?? []
  const serverRateLimit = overview.data?.data?.rate_limit_per_min

  // 配额草稿；null = 未编辑，回显服务端当前值
  const [rateDraft, setRateDraft] = useState<number | null>(null)
  const dirty = rateDraft !== null && rateDraft !== serverRateLimit

  // 乐观启停：失败回滚 + toast；settled 后以服务端为准
  const toggleTool = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      mcpGovernanceApi.setToolEnabled(name, enabled),
    onMutate: async ({ name, enabled }) => {
      await queryClient.cancelQueries({ queryKey: QUERY_KEY })
      const prev = queryClient.getQueryData<ApiResponse<MCPGovernanceOverview>>(QUERY_KEY)
      queryClient.setQueryData<ApiResponse<MCPGovernanceOverview>>(QUERY_KEY, (old) =>
        old
          ? {
              ...old,
              data: {
                ...old.data,
                tools: old.data.tools.map((t) => (t.name === name ? { ...t, enabled } : t)),
              },
            }
          : old,
      )
      return { prev }
    },
    onError: (e: unknown, _vars, ctx) => {
      if (ctx?.prev) queryClient.setQueryData(QUERY_KEY, ctx.prev)
      toast({ title: getErrorMessage(e, '工具开关更新失败'), variant: 'destructive' })
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: QUERY_KEY })
    },
  })

  const saveRateLimit = useMutation({
    mutationFn: (perMinute: number) => mcpGovernanceApi.updateRateLimit(perMinute),
    onSuccess: () => {
      toast({ title: '速率配额已保存，立即生效' })
      setRateDraft(null)
      queryClient.invalidateQueries({ queryKey: QUERY_KEY })
    },
    onError: (e: unknown) =>
      toast({ title: getErrorMessage(e, '配额保存失败'), variant: 'destructive' }),
  })

  return (
    <Card title="MCP 治理">
      <div className="space-y-6">
        <div className="flex flex-wrap items-center gap-3">
          <label htmlFor="mcp-rate-limit" className="text-sm font-medium">
            速率配额（次/分钟）
          </label>
          <InputNumber
            id="mcp-rate-limit"
            className="w-28"
            min={1}
            max={600}
            precision={0}
            value={rateDraft ?? serverRateLimit}
            onChange={(v) => setRateDraft(typeof v === 'number' ? v : null)}
          />
          <Button
            type="primary"
            disabled={!dirty || saveRateLimit.isPending}
            loading={saveRateLimit.isPending}
            onClick={() => dirty && saveRateLimit.mutate(rateDraft)}
          >
            保存配额
          </Button>
        </div>

        {overview.isLoading ? (
          <Skeleton active title={false} paragraph={{ rows: 6 }} />
        ) : overview.isError ? (
          <Alert
            type="error"
            showIcon
            message="MCP 治理配置读取失败"
            description={getErrorMessage(overview.error, '')}
            action={
              <Button size="small" onClick={() => overview.refetch()}>
                重试
              </Button>
            }
          />
        ) : (
          <div className="max-h-[480px] overflow-y-auto rounded-md border">
            {tools.map((t) => (
              <div
                key={t.name}
                className="flex items-center justify-between gap-3 border-b px-3 py-2 last:border-b-0"
              >
                <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span className="text-sm font-medium">{t.title || t.name}</span>
                  {t.title && (
                    <code className="truncate font-mono text-xs text-muted-foreground">{t.name}</code>
                  )}
                  {t.write && <Tag color="warning">写</Tag>}
                </div>
                <Switch
                  checked={t.enabled}
                  aria-label={`启用 ${t.title || t.name}`}
                  onChange={(checked) => toggleTool.mutate({ name: t.name, enabled: checked })}
                />
              </div>
            ))}
            {tools.length === 0 && (
              <div className="p-6 text-center text-sm text-muted-foreground">没有已注册的工具</div>
            )}
          </div>
        )}
      </div>
    </Card>
  )
}

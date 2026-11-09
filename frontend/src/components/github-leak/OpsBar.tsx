import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Modal } from 'antd'
import { DatabaseZap, Eraser, RefreshCw, RotateCcw, Zap } from 'lucide-react'
import { githubMonitorApi, type GitHubCleanupReport } from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { LEAK_GLOBAL_FINDINGS_KEY, LEAK_OPS_KEY } from './shared'

/** 全局运维条：立即巡查 / 补全明文 / 历史清理（预览→确认）/ 水线重置 / 配额刷新。 */
export function OpsBar({ onChanged }: { onChanged?: () => void }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: LEAK_OPS_KEY })
    queryClient.invalidateQueries({ queryKey: LEAK_GLOBAL_FINDINGS_KEY })
    onChanged?.()
  }

  const ops = useMutation({
    mutationFn: async (action: 'run' | 'backfill') => {
      const res = action === 'run' ? await githubMonitorApi.runNow() : await githubMonitorApi.backfill()
      return res.data as { accepted?: boolean; filled?: number }
    },
    onSuccess: (data, action) => {
      toast({
        title: action === 'run' ? '已加入巡查队列' : `已补全 ${data?.filled ?? 0} 条明文`,
      })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const cleanup = useMutation({
    mutationFn: () => githubMonitorApi.cleanupPreview(),
    onSuccess: (res) => {
      const report = res.data as GitHubCleanupReport
      Modal.confirm({
        title: '确认清理历史噪音命中？',
        width: 560,
        content: (
          <div className="text-sm">
            <p>
              扫描 <b>{report.total}</b> 条历史命中，匹配噪音特征{' '}
              <b className="text-destructive">{report.matched}</b> 条，执行后不可恢复。
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
            invalidate()
          } catch (e) {
            toast({ title: '清理失败', description: (e as Error).message, variant: 'destructive' })
          }
        },
      })
    },
    onError: (e: Error) => toast({ title: '预览失败', description: e.message, variant: 'destructive' }),
  })

  const waterline = useMutation({
    mutationFn: () => githubMonitorApi.resetWaterline(),
    onSuccess: (res) => {
      toast({ title: `已重置 ${res.data?.reset ?? 0} 条规则水线，下轮从头回扫` })
      invalidate()
    },
    onError: (e: Error) => toast({ title: '重置失败', description: e.message, variant: 'destructive' }),
  })

  const busy = (action: string) => ops.isPending && ops.variables === action

  return (
    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-card/50 px-3 py-2.5">
      <span className="mr-1 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
        <Zap className="size-3.5 text-primary" /> 全局运维
      </span>
      <Button
        size="small"
        type="primary"
        icon={<RefreshCw className="size-3.5" />}
        loading={busy('run')}
        onClick={() => ops.mutate('run')}
      >
        立即巡查
      </Button>
      <Button
        size="small"
        icon={<DatabaseZap className="size-3.5" />}
        loading={busy('backfill')}
        onClick={() => ops.mutate('backfill')}
      >
        补全明文（≤50）
      </Button>
      <Button
        size="small"
        danger
        icon={<Eraser className="size-3.5" />}
        loading={cleanup.isPending}
        onClick={() => cleanup.mutate()}
      >
        历史噪音清理
      </Button>
      <Button
        size="small"
        icon={<RotateCcw className="size-3.5" />}
        loading={waterline.isPending}
        onClick={() => waterline.mutate()}
      >
        重置水线
      </Button>
    </div>
  )
}

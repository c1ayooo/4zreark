import { useState } from 'react'
import { Button, Card } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type VerifyStats } from '@/api/tools'

export default function RuntimePanel() {
  const { toast } = useToast()
  const [stats, setStats] = useState<VerifyStats | null>(null)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    setBusy(true)
    try {
      setStats(await toolsApi.verifyStats(30))
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取运行时状态失败', variant: 'destructive' })
    } finally { setBusy(false) }
  }

  return (
    <Card
      title={
        <span className="flex flex-wrap items-center gap-3">
          自动验证统计（近 30 天）
          <span className="text-xs font-normal text-muted-foreground">nuclei 运行时与更新策略见「更新策略」标签页</span>
        </span>
      }
      extra={<Button onClick={load} loading={busy}>刷新</Button>}
    >
      <div className="space-y-2 text-sm">
        {stats ? (
          <>
            <div>完结任务：{stats.finished} · 命中 {stats.hits} · 未命中 {stats.misses} · 失败 {stats.failures} · 跳过 {stats.skipped}</div>
            <div className="text-xs text-muted-foreground">状态分布：{Object.entries(stats.by_status || {}).map(([k, v]) => `${k}=${v}`).join(' · ') || '无'}</div>
          </>
        ) : <p className="text-xs text-muted-foreground">点击刷新读取统计。</p>}
      </div>
    </Card>
  )
}

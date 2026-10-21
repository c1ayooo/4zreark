import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Play, RefreshCw } from 'lucide-react'

import { projectApi } from '@/api/projects'
import {
  runApi,
  runStatusLabel,
  runStatusVariant,
  targetStateLabel,
  type RunTarget,
} from '@/api/runs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
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
import { useAuthStore } from '@/store/auth'

// stats.targets 可能是数字，也可能是按状态聚合的对象（{done:3, skipped:1}）。
// 直接渲染对象会触发 React #31，这里统一折算成总数。
function targetTotal(stats?: Record<string, unknown>): number | undefined {
  if (!stats) return undefined
  const raw = stats.targets
  if (typeof raw === 'number') return raw
  if (typeof stats.total_targets === 'number') return stats.total_targets
  if (raw && typeof raw === 'object') {
    return Object.values(raw as Record<string, unknown>).reduce<number>(
      (sum, v) => sum + (typeof v === 'number' ? v : Number(v) || 0),
      0
    )
  }
  return undefined
}

const TARGET_STATES = [
  { value: '', label: '全部' },
  { value: 'pending', label: '待执行' },
  { value: 'running', label: '执行中' },
  { value: 'done', label: '完成' },
  { value: 'failed', label: '失败' },
  { value: 'skipped', label: '跳过' },
]

export default function RunsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role === 'admin')

  const [projectId, setProjectId] = useState('0')
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [targetState, setTargetState] = useState('')

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const runs = useQuery({
    queryKey: ['runs', projectId],
    queryFn: () => runApi.list(Number(projectId) || undefined, 100),
  })
  const detail = useQuery({
    queryKey: ['run', selectedId],
    queryFn: () => runApi.detail(selectedId as number),
    enabled: selectedId !== null,
  })
  const targets = useQuery({
    queryKey: ['run-targets', selectedId, targetState],
    queryFn: () => runApi.targets(selectedId as number, targetState || undefined, 200),
    enabled: selectedId !== null,
  })

  const execute = useMutation({
    mutationFn: () => runApi.execute(selectedId as number, 50),
    onSuccess: (res) => {
      const stats = res.data ?? {}
      toast({
        title: '已执行一批目标',
        description:
          Object.entries(stats)
            .map(([k, v]) => `${k}: ${String(v)}`)
            .join(' · ') || '没有待执行目标',
      })
      queryClient.invalidateQueries({ queryKey: ['run', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['run-targets', selectedId] })
      queryClient.invalidateQueries({ queryKey: ['runs'] })
    },
    onError: (e: any) =>
      toast({ title: '执行失败', description: e?.message, variant: 'destructive' }),
  })

  const projectName = (id: number) =>
    projects.data?.data?.find((p) => p.id === id)?.name ?? `#${id}`

  const list = runs.data?.data ?? []
  const run = detail.data?.data?.run
  const targetStats = detail.data?.data?.target_stats ?? {}
  const targetList: RunTarget[] = targets.data?.data ?? []

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">执行记录</h1>
          <p className="text-sm text-muted-foreground">
            治理计划到点后生成的批次；可查看执行单元状态，并对剩余目标手动推进
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={projectId} onValueChange={(v) => setProjectId(v)}>
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
          <Button variant="outline" onClick={() => runs.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <div className="rounded-md border xl:col-span-3">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[70px]">批次</TableHead>
                <TableHead>项目</TableHead>
                <TableHead className="w-[100px]">状态</TableHead>
                <TableHead className="w-[140px]">周期开始</TableHead>
                <TableHead className="w-[90px]">目标</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.isLoading && (
                <TableRow>
                  <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                    加载中…
                  </TableCell>
                </TableRow>
              )}
              {!runs.isLoading && list.length === 0 && (
                <TableRow>
                  <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                    还没有批次（计划到点或手动触发后会生成）
                  </TableCell>
                </TableRow>
              )}
              {list.map((r) => {
                const targetCount = targetTotal(r.stats)
                return (
                  <TableRow
                    key={r.id}
                    className={
                      'cursor-pointer ' + (selectedId === r.id ? 'bg-muted/60' : '')
                    }
                    onClick={() => setSelectedId(r.id)}
                  >
                    <TableCell className="font-mono text-sm">#{r.id}</TableCell>
                    <TableCell className="text-sm">{projectName(r.project_id)}</TableCell>
                    <TableCell>
                      <Badge variant={runStatusVariant(r.status)}>
                        {runStatusLabel[r.status] ?? r.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatDate(r.cycle_start)}
                    </TableCell>
                    <TableCell className="text-sm">{targetCount ?? '—'}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>

        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Activity className="h-4 w-4" />
              {run ? `批次 #${run.id}` : '批次详情'}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {!run && (
              <p className="text-sm text-muted-foreground">
                从左侧选择一个批次，查看执行单元与统计
              </p>
            )}
            {run && (
              <>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <dt className="text-muted-foreground">项目</dt>
                  <dd>{projectName(run.project_id)}</dd>
                  <dt className="text-muted-foreground">计划</dt>
                  <dd className="font-mono">#{run.plan_id}</dd>
                  <dt className="text-muted-foreground">状态</dt>
                  <dd>
                    <Badge variant={runStatusVariant(run.status)}>
                      {runStatusLabel[run.status] ?? run.status}
                    </Badge>
                  </dd>
                  <dt className="text-muted-foreground">周期开始</dt>
                  <dd className="text-xs">{formatDate(run.cycle_start)}</dd>
                  <dt className="text-muted-foreground">开始</dt>
                  <dd className="text-xs">{run.started_at ? formatDate(run.started_at) : '—'}</dd>
                  <dt className="text-muted-foreground">结束</dt>
                  <dd className="text-xs">{run.ended_at ? formatDate(run.ended_at) : '—'}</dd>
                </dl>

                <div className="flex flex-wrap gap-2">
                  {Object.entries(targetStats).map(([state, n]) => (
                    <Badge key={state} variant="outline">
                      {targetStateLabel[state] ?? state} {n}
                    </Badge>
                  ))}
                  {Object.keys(targetStats).length === 0 && (
                    <span className="text-sm text-muted-foreground">暂无执行单元统计</span>
                  )}
                </div>

                {isAdmin && (
                  <Button
                    className="w-full"
                    onClick={() => execute.mutate()}
                    disabled={execute.isPending || run.status === 'done' || run.status === 'failed'}
                  >
                    <Play className="mr-2 h-4 w-4" />
                    {execute.isPending ? '执行中…' : '执行剩余目标（50 条）'}
                  </Button>
                )}

                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    {TARGET_STATES.map((s) => (
                      <button
                        key={s.value}
                        className={
                          'rounded-full border px-3 py-1 text-xs ' +
                          (targetState === s.value
                            ? 'border-primary bg-primary/10 text-primary'
                            : 'text-muted-foreground hover:bg-muted')
                        }
                        onClick={() => setTargetState(s.value)}
                      >
                        {s.label}
                      </button>
                    ))}
                    <span className="ml-auto text-xs text-muted-foreground">
                      {targetList.length} 条
                    </span>
                  </div>
                  <div className="max-h-[360px] overflow-auto rounded-md border">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>目标</TableHead>
                          <TableHead className="w-[80px]">状态</TableHead>
                          <TableHead className="w-[60px]">尝试</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {targets.isLoading && (
                          <TableRow>
                            <TableCell colSpan={3} className="py-6 text-center text-muted-foreground">
                              加载中…
                            </TableCell>
                          </TableRow>
                        )}
                        {!targets.isLoading && targetList.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={3} className="py-6 text-center text-muted-foreground">
                              没有执行单元
                            </TableCell>
                          </TableRow>
                        )}
                        {targetList.map((t) => (
                          <TableRow key={t.id}>
                            <TableCell className="font-mono text-xs">
                              {t.host}:{t.port}
                            </TableCell>
                            <TableCell>
                              <Badge variant={t.state === 'failed' ? 'destructive' : 'outline'}>
                                {targetStateLabel[t.state] ?? t.state}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-xs">{t.attempts}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

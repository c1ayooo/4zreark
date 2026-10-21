import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Network, RefreshCw, Share2 } from 'lucide-react'

import { projectApi } from '@/api/projects'
import {
  relationApi,
  relationTypeLabel,
  type RelationIndexStatus,
} from '@/api/relations'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'

const TYPES = [
  { value: '', label: '全部' },
  { value: 'same_ip', label: '同 IP' },
  { value: 'domain_parent', label: '父子域' },
  { value: 'same_icon', label: '同图标' },
  { value: 'same_fp', label: '同技术栈' },
  { value: 'same_cert', label: '同证书' },
  { value: 'same_c_segment', label: '同 C 段' },
  { value: 'redirect', label: '跳转关系' },
]

export default function RelationsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [projectId, setProjectId] = useState('0')
  const [type, setType] = useState('')

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const status = useQuery({
    queryKey: ['relation-status', projectId],
    queryFn: () => relationApi.indexStatus(Number(projectId) || undefined),
  })
  const graph = useQuery({
    queryKey: ['relations', projectId, type],
    queryFn: () =>
      relationApi.list({
        project_id: Number(projectId) || undefined,
        type: type || undefined,
        limit: 500,
      }),
  })

  const rebuild = useMutation({
    mutationFn: () => relationApi.rebuild(Number(projectId) || undefined),
    onSuccess: (res) => {
      toast({
        title: '关系图谱已重建',
        description: Object.entries(res.data?.by_type ?? {})
          .map(([k, v]) => `${relationTypeLabel[k] ?? k} ${v}`)
          .join(' · ') || '当前没有可建边的数据',
      })
      queryClient.invalidateQueries({ queryKey: ['relations'] })
      queryClient.invalidateQueries({ queryKey: ['relation-status'] })
    },
    onError: (e: any) => toast({ title: '重建失败', description: e?.message, variant: 'destructive' }),
  })

  const stats: RelationIndexStatus | undefined = status.data?.data
  const data = graph.data?.data
  const edges = data?.edges ?? []

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">关系图谱</h1>
          <p className="text-sm text-muted-foreground">
            按同 IP / 父子域 / 同图标 / 同技术栈聚类；每条边都挂两侧站点的原始记录作为证据
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={projectId} onValueChange={setProjectId}>
            <SelectTrigger className="w-[190px]">
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
          <Button variant="outline" onClick={() => graph.refetch()}>
            <RefreshCw className="mr-2 h-4 w-4" /> 刷新
          </Button>
          <Button onClick={() => rebuild.mutate()} disabled={rebuild.isPending}>
            <Share2 className="mr-2 h-4 w-4" />
            {rebuild.isPending ? '重建中…' : '重建图谱'}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="关系边" value={stats?.edges ?? 0} />
        <StatCard label="证据行" value={stats?.evidence ?? 0} />
        <StatCard label="参与站点" value={stats?.sites ?? 0} />
        <StatCard
          label="类型"
          value={
            Object.keys(stats?.by_type ?? {}).length
              ? Object.entries(stats?.by_type ?? {})
                  .map(([k, v]) => `${relationTypeLabel[k] ?? k}:${v}`)
                  .join('  ')
              : '—'
          }
          small
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {TYPES.map((t) => (
          <button
            key={t.value}
            className={
              'rounded-full border px-3 py-1 text-sm ' +
              (type === t.value
                ? 'border-primary bg-primary/10 text-primary'
                : 'text-muted-foreground hover:bg-muted')
            }
            onClick={() => setType(t.value)}
          >
            {t.label}
          </button>
        ))}
        <span className="ml-auto text-sm text-muted-foreground">
          {data?.total_edges ?? 0} 条{data?.truncated ? '（已截断）' : ''}
        </span>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[110px]">类型</TableHead>
              <TableHead>聚类键</TableHead>
              <TableHead>站点 A</TableHead>
              <TableHead>站点 B</TableHead>
              <TableHead className="w-[90px]">置信度</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {graph.isLoading && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!graph.isLoading && edges.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-10 text-center text-muted-foreground">
                  <Network className="mx-auto mb-2 h-6 w-6 opacity-40" />
                  还没有关系边。导入资产后点右上角「重建图谱」；同 IP/父子域/同图标/同技术栈会生成聚类。
                </TableCell>
              </TableRow>
            )}
            {edges.map((e) => (
              <TableRow key={e.id}>
                <TableCell>
                  <Badge variant="outline">{relationTypeLabel[e.type] ?? e.type}</Badge>
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{e.key}</TableCell>
                <TableCell>
                  <div className="text-sm font-mono">{e.left.host}</div>
                  <div className="text-xs text-muted-foreground">
                    {e.left.title || '—'} · {e.left.ip || '—'}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="text-sm font-mono">{e.right.host}</div>
                  <div className="text-xs text-muted-foreground">
                    {e.right.title || '—'} · {e.right.ip || '—'}
                  </div>
                </TableCell>
                <TableCell className="text-sm tabular-nums">{e.confidence.toFixed(2)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

function StatCard({ label, value, small }: { label: string; value: string | number; small?: boolean }) {
  return (
    <Card>
      <CardHeader className="pb-1">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
      </CardHeader>
      <CardContent>
        <div className={small ? 'text-sm font-medium' : 'text-2xl font-bold tabular-nums'}>{value}</div>
      </CardContent>
    </Card>
  )
}

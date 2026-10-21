import { useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowRight,
  Briefcase,
  Database,
  FolderPlus,
  Layers,
  Plus,
  RefreshCw,
} from 'lucide-react'

import { projectApi, type Project, type ProjectInput } from '@/api/projects'
import { ProjectFormDialog } from '@/components/projects/ProjectFormDialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'

const regionLabel = (region: string) => {
  if (!region) return '—'
  if (region === 'domestic') return '国内'
  if (region === 'intl' || region === 'overseas') return '国际'
  return region
}

function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-2">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="text-foreground truncate text-sm font-medium tabular-nums">{value}</span>
    </div>
  )
}

function ProjectCard({ project, onOpen }: { project: Project; onOpen: () => void }) {
  return (
    <Card
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          onOpen()
        }
      }}
      className="hover:border-primary/40 hover:shadow-md group cursor-pointer transition-all"
    >
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span
              className="flex size-9 shrink-0 items-center justify-center rounded-lg text-white shadow-sm"
              style={{ backgroundColor: project.color || '#64748b' }}
            >
              <Briefcase className="size-4" />
            </span>
            <div className="min-w-0">
              <div className="truncate text-base font-semibold leading-tight">{project.name}</div>
              <div className="text-muted-foreground truncate font-mono text-xs">{project.code}</div>
            </div>
          </div>
          <Badge variant={project.collection_paused ? 'warning' : 'success'} className="shrink-0">
            {project.collection_paused ? '已暂停' : '采集中'}
          </Badge>
        </div>
        <p className="text-muted-foreground line-clamp-2 min-h-[2.5rem] pt-2 text-sm">
          {project.description || '暂无项目说明'}
        </p>
      </CardHeader>

      <CardContent className="space-y-2 pb-3">
        <Field label="地区" value={regionLabel(project.region)} />
        <Field label="采集周期" value={`${project.cycle_interval_days} 天`} />
        <div className="border-border/60 grid grid-cols-2 gap-x-4 gap-y-2 border-t pt-2">
          <Field
            label="资产"
            value={
              <span className="inline-flex items-center gap-1">
                <Database className="text-muted-foreground size-3" />
                {project.asset_count}
              </span>
            }
          />
          <Field label="原始记录" value={project.record_count} />
          <Field
            label="失联"
            value={
              <span
                className={cn(
                  'inline-flex items-center gap-1',
                  project.lost_count > 0 && 'text-destructive',
                )}
              >
                <AlertTriangle className="size-3" />
                {project.lost_count}
              </span>
            }
          />
          <Field
            label="种子"
            value={
              <span className="inline-flex items-center gap-1">
                <Layers className="text-muted-foreground size-3" />
                {project.seed_count}
              </span>
            }
          />
        </div>
      </CardContent>

      <CardFooter className="text-muted-foreground flex items-center justify-between pt-0 text-xs">
        <span>更新于 {formatDate(project.updated_at)}</span>
        <span className="text-primary inline-flex items-center gap-1 font-medium">
          查看详情
          <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" />
        </span>
      </CardFooter>
    </Card>
  )
}

export default function ProjectsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createOpen, setCreateOpen] = useState(false)

  const projects = useQuery({ queryKey: ['projects'], queryFn: () => projectApi.list() })

  const createMutation = useMutation({
    mutationFn: (input: ProjectInput) => projectApi.create(input),
    onSuccess: (res) => {
      toast({ title: res.message || '项目已创建' })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      queryClient.invalidateQueries({ queryKey: ['asset-projects'] })
    },
    onError: (e: any) => {
      toast({
        title: '创建项目失败',
        description: e?.message || '请检查表单后重试',
        variant: 'destructive',
      })
    },
  })

  const list = projects.data?.data ?? []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">项目管理</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            项目是公司 / SRC 的资产边界，资产、种子与持续监控计划都挂在项目下。
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => projects.refetch()}
            disabled={projects.isFetching}
          >
            <RefreshCw className={cn('mr-2 h-4 w-4', projects.isFetching && 'animate-spin')} />
            刷新
          </Button>
          <Button size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            新建项目
          </Button>
        </div>
      </div>

      {projects.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-[260px] w-full rounded-lg" />
          ))}
        </div>
      ) : projects.isError ? (
        <Card>
          <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16 text-sm">
            <AlertTriangle className="text-destructive h-8 w-8" />
            项目列表加载失败
            <Button variant="outline" size="sm" onClick={() => projects.refetch()}>
              重试
            </Button>
          </CardContent>
        </Card>
      ) : list.length === 0 ? (
        <Card>
          <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16 text-center">
            <Briefcase className="h-10 w-10 opacity-40" />
            <div>
              <p className="text-foreground font-medium">还没有项目</p>
              <p className="mt-1 text-sm">先创建一个公司 / SRC 项目，再往项目里加种子和监控计划。</p>
            </div>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <FolderPlus className="mr-2 h-4 w-4" />
              新建项目
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {list.map((p) => (
            <ProjectCard key={p.id} project={p} onOpen={() => navigate(`/projects/${p.id}`)} />
          ))}
        </div>
      )}

      <ProjectFormDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSubmit={(input) => createMutation.mutateAsync(input)}
      />
    </div>
  )
}

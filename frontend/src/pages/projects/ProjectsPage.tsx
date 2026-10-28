import { useState } from 'react'
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
  Rocket,
  Sprout,
  Trash2,
} from 'lucide-react'
import { Button, Card, Skeleton, Tag } from 'antd'

import { projectApi, type Project, type ProjectInput } from '@/api/projects'
import { ProjectFormDialog } from '@/components/projects/ProjectFormDialog'
import OnboardDialog from '@/components/projects/OnboardDialog'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'

const regionLabel = (region: string) => {
  if (!region) return '—'
  if (region === 'domestic') return '国内'
  if (region === 'intl' || region === 'overseas') return '国际'
  return region
}

function ProjectCard({
  project,
  onOpen,
  onDelete,
}: {
  project: Project
  onOpen: () => void
  onDelete: () => void
}) {
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
      styles={{ body: { padding: '12px 14px' } }}
      className="hover:border-primary/40 hover:shadow-md group cursor-pointer transition-all"
    >
      {/* 标识行：图标缩小、名称代码同行挤、状态角标 */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span
            className="flex size-7 shrink-0 items-center justify-center rounded-md text-white shadow-sm"
            style={{ backgroundColor: project.color || '#64748b' }}
          >
            <Briefcase className="size-3.5" />
          </span>
          <div className="flex min-w-0 items-baseline gap-2">
            <span className="truncate text-sm font-semibold leading-tight">{project.name}</span>
            <span className="text-muted-foreground truncate font-mono text-xs">{project.code}</span>
          </div>
        </div>
        <Tag
          className={cn(
            'shrink-0 border-transparent text-xs',
            project.collection_paused
              ? 'bg-yellow-500 text-black'
              : 'bg-primary text-primary-foreground',
          )}
        >
          {project.collection_paused ? '已暂停' : '采集中'}
        </Tag>
      </div>

      {/* 描述压成一行 */}
      <p className="text-muted-foreground truncate pt-1.5 text-xs">
        {project.description || '暂无项目说明'}
      </p>

      {/* 元信息一行 + 统计一行 */}
      <div className="text-muted-foreground flex items-center gap-3 pt-1.5 text-xs">
        <span>{regionLabel(project.region)}</span>
        <span>周期 {project.cycle_interval_days} 天</span>
        <span>更新 {formatDate(project.updated_at)}</span>
      </div>
      <div className="text-muted-foreground grid grid-cols-4 gap-2 border-t pt-2 text-xs">
        <span className="inline-flex items-center gap-1" title="资产">
          <Database className="size-3" />
          <span className="text-foreground font-medium tabular-nums">{project.asset_count}</span>
        </span>
        <span className="inline-flex items-center gap-1" title="原始记录">
          <Layers className="size-3" />
          <span className="text-foreground font-medium tabular-nums">{project.record_count}</span>
        </span>
        <span
          className={cn('inline-flex items-center gap-1', project.lost_count > 0 && 'text-destructive')}
          title="失联"
        >
          <AlertTriangle className="size-3" />
          <span className="text-foreground font-medium tabular-nums">{project.lost_count}</span>
        </span>
        <span className="inline-flex items-center gap-1" title="种子">
          <Sprout className="size-3" />
          <span className="text-foreground font-medium tabular-nums">{project.seed_count}</span>
        </span>
      </div>

      {/* 底栏：详情 + 删除（种子数已在统计行，不再重复） */}
      <div className="flex items-center justify-between border-t pt-2">
        <span className="text-primary inline-flex items-center gap-1 text-xs font-medium">
          查看详情
          <ArrowRight className="size-3 transition-transform group-hover:translate-x-0.5" />
        </span>
        <Button
          type="text"
          size="small"
          danger
          className="h-6 px-1.5 text-xs"
          onClick={(e) => {
            e.stopPropagation()
            onDelete()
          }}
        >
          <Trash2 className="h-3 w-3" />
        </Button>
      </div>
    </Card>
  )
}

export default function ProjectsPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [createOpen, setCreateOpen] = useState(false)
  const [onboardOpen, setOnboardOpen] = useState(false)

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
            size="small"
            onClick={() => projects.refetch()}
            disabled={projects.isFetching}
          >
            <RefreshCw className={cn('mr-2 h-4 w-4', projects.isFetching && 'animate-spin')} />
            刷新
          </Button>
          <Button size="small" onClick={() => setOnboardOpen(true)}>
            <Rocket className="mr-2 h-4 w-4" />
            一键侦察
          </Button>
          <Button type="primary" size="small" onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            新建项目
          </Button>
        </div>
      </div>

      {projects.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} loading active paragraph={{ rows: 7 }} className="rounded-lg" />
          ))}
        </div>
      ) : projects.isError ? (
        <Card>
          <div className="text-muted-foreground flex flex-col items-center gap-3 py-10 text-sm">
            <AlertTriangle className="text-destructive h-8 w-8" />
            项目列表加载失败
            <Button size="small" onClick={() => projects.refetch()}>
              重试
            </Button>
          </div>
        </Card>
      ) : list.length === 0 ? (
        <Card>
          <div className="text-muted-foreground flex flex-col items-center gap-3 py-10 text-center">
            <Briefcase className="h-10 w-10 opacity-40" />
            <div>
              <p className="text-foreground font-medium">还没有项目</p>
              <p className="mt-1 text-sm">先创建一个公司 / SRC 项目，再往项目里加种子和监控计划。</p>
            </div>
            <Button type="primary" size="small" onClick={() => setCreateOpen(true)}>
              <FolderPlus className="mr-2 h-4 w-4" />
              新建项目
            </Button>
          </div>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
          {list.map((p) => (
            <ProjectCard
              key={p.id}
              project={p}
              onOpen={() => navigate(`/projects/${p.id}`)}
              onDelete={() => navigate(`/projects/${p.id}?delete=1`)}
            />
          ))}
        </div>
      )}

      <ProjectFormDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onSubmit={(input) => createMutation.mutateAsync(input)}
      />
      <OnboardDialog open={onboardOpen} onClose={() => setOnboardOpen(false)} />
    </div>
  )
}

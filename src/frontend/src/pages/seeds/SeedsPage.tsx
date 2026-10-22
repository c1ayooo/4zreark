import { useMemo, useState } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ExternalLink, RefreshCw, Search, Sprout } from 'lucide-react'

import { assetApi } from '@/api/assets'
import { seedsApi, type Seed, type SeedKind } from '@/api/seeds'
import EmptyState from '@/components/common/EmptyState'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

const KIND_LABEL: Record<SeedKind, string> = {
  domain: '域名',
  cidr: '网段',
  company: '企业',
  cert: '证书组织',
  repo: '仓库',
  app: '应用',
  dict: '字典',
}

/**
 * 跨项目种子索引。
 *
 * 种子的写入（新增 / 删除 / 预览 / 绑定监控计划）只在项目详情页一处，
 * 这里做只读汇总。同一件事若保留两个写入口，校验、提示和权限判断必然逐渐分叉。
 */
export default function SeedsPage() {
  const [projectId, setProjectId] = useState('0')
  const [keyword, setKeyword] = useState('')

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })
  const seeds = useQuery({ queryKey: ['seeds', projectId], queryFn: () => seedsApi.list(projectId) })
  // /seeds/domain-counts 必须带 project_id，所以按项目逐个取再合并；
  // 项目数不多（当前个位数），比给后端加一个全局聚合接口更省事。
  const countQueries = useQueries({
    queries: (projects.data?.data || []).map((p) => ({
      queryKey: ['seed-domain-counts', p.id],
      queryFn: () => seedsApi.domainCounts(p.id),
    })),
  })

  const items = useMemo(() => {
    const list = seeds.data?.data || []
    const kw = keyword.trim().toLowerCase()
    return kw ? list.filter((s) => s.value.toLowerCase().includes(kw)) : list
  }, [seeds.data, keyword])

  const projectName = (id: number) => (projects.data?.data || []).find((p) => p.id === id)?.name || `#${id}`
  // /seeds/domain-counts 返回 items:[{seed_id, site_count}]，不是 map，别按对象直接取值。
  const countMap = useMemo(() => {
    const m = new Map<number, number>()
    countQueries.forEach((q) => {
      (q.data?.data?.items || []).forEach((d) => m.set(d.seed_id, d.site_count))
    })
    return m
  }, [countQueries])
  const coverage = (seed: Seed) => countMap.get(seed.id) ?? 0

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">种子</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            所有项目正在盯的目标总览。种子决定持续监控的范围，新增与删除在对应项目详情页完成。
          </p>
        </div>
        <Button variant="outline" asChild>
          <Link to="/projects">
            去项目管理添加
            <ExternalLink className="ml-1 h-3.5 w-3.5" />
          </Link>
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select value={projectId} onValueChange={setProjectId}>
          <SelectTrigger className="h-9 w-[220px]">
            <SelectValue placeholder="全部项目" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="0">全部项目</SelectItem>
            {(projects.data?.data || []).map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="relative">
          <Search className="text-muted-foreground absolute top-1/2 left-2 h-4 w-4 -translate-y-1/2" />
          <Input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            placeholder="搜索种子值"
            className="h-9 w-64 pl-8"
          />
        </div>

        <Button variant="outline" size="sm" onClick={() => seeds.refetch()} disabled={seeds.isFetching}>
          <RefreshCw className={seeds.isFetching ? 'mr-1 h-4 w-4 animate-spin' : 'mr-1 h-4 w-4'} />
          刷新
        </Button>

        <span className="text-muted-foreground ml-auto text-sm">共 {items.length} 个种子</span>
      </div>

      <div className="bg-background overflow-hidden rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>种子值</TableHead>
              <TableHead className="w-24">类型</TableHead>
              <TableHead className="w-40">项目</TableHead>
              <TableHead className="w-28">覆盖站点</TableHead>
              <TableHead className="w-24">状态</TableHead>
              <TableHead className="w-40">创建时间</TableHead>
              <TableHead className="w-24">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {seeds.isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-muted-foreground py-10 text-center">
                  加载中…
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="p-0">
                  <EmptyState
                    icon={Sprout}
                    title={keyword ? '没有匹配的种子' : '这里还没有种子'}
                    description={
                      keyword
                        ? '换个关键词试试，或清空搜索查看全部。'
                        : '种子在项目详情页里维护：进项目，添加域名或网段，监控计划会自动按时展开。'
                    }
                    hints={['域名种子展开子域与站点', '网段种子用于 IP 资产', '种子本身不发请求，由计划与批次执行']}
                    actions={
                      <Button size="sm" asChild>
                        <Link to="/projects">打开项目管理</Link>
                      </Button>
                    }
                  />
                </TableCell>
              </TableRow>
            ) : (
              items.map((s: Seed) => (
                <TableRow key={s.id}>
                  <TableCell className="max-w-[320px] truncate font-mono text-sm">{s.value}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{KIND_LABEL[s.kind] ?? s.kind}</Badge>
                  </TableCell>
                  <TableCell className="text-sm">{projectName(s.project_id)}</TableCell>
                  <TableCell className="text-sm">{coverage(s)}</TableCell>
                  <TableCell>
                    <Badge variant={s.enabled ? 'default' : 'secondary'}>{s.enabled ? '启用' : '停用'}</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground text-xs">
                    {s.created_at ? new Date(s.created_at).toLocaleString() : '—'}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" asChild>
                      <Link to={`/projects/${s.project_id}`}>项目详情</Link>
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}

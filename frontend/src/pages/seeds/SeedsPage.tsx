import { useMemo, useState } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { ExternalLink, RefreshCw, Search, Sprout } from 'lucide-react'
import { Button, Input, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import { assetApi } from '@/api/assets'
import { seedsApi, type Seed, type SeedKind } from '@/api/seeds'
import EmptyState from '@/components/common/EmptyState'

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
  const navigate = useNavigate()
  // 仪表盘项目分布表下钻入口：/seeds?project_id=N 只看该项目种子
  const [searchParams] = useSearchParams()
  const [projectId, setProjectId] = useState(() => searchParams.get('project_id') || '0')
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

  // /seeds 无排序参数，覆盖站点数与创建时间走客户端排序
  const columns: TableProps<Seed>['columns'] = [
    {
      title: '种子值',
      dataIndex: 'value',
      key: 'value',
      render: (v: string) => <span className="block max-w-[320px] truncate font-mono text-sm">{v}</span>,
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 96,
      render: (v: string) => <Tag>{KIND_LABEL[v as SeedKind] ?? v}</Tag>,
    },
    {
      title: '项目',
      key: 'project',
      width: 160,
      render: (_, s) => <span className="text-sm">{projectName(s.project_id)}</span>,
    },
    {
      title: '覆盖站点',
      key: 'coverage',
      width: 112,
      render: (_, s) => <span className="text-sm">{coverage(s)}</span>,
      sorter: (a, b) => coverage(a) - coverage(b),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 96,
      render: (v: boolean) => (
        <Tag className={v ? 'border-primary/30 bg-primary/10 text-primary' : undefined}>
          {v ? '启用' : '停用'}
        </Tag>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (v: string) => (
        <span className="text-xs text-muted-foreground">{v ? new Date(v).toLocaleString() : '—'}</span>
      ),
      sorter: (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: '操作',
      key: 'actions',
      width: 96,
      render: (_, s) => (
        <Button type="link" size="small" className="px-0" onClick={() => navigate(`/projects/${s.project_id}`)}>
          项目详情
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold">种子</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            所有项目正在盯的目标总览。种子决定持续监控的范围，新增与删除在对应项目详情页完成。
          </p>
        </div>
        <Button onClick={() => navigate('/projects')}>
          去项目管理添加
          <ExternalLink className="ml-1 h-3.5 w-3.5" />
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          className="w-[220px]"
          value={projectId}
          onChange={(v) => setProjectId(v)}
          options={[
            { value: '0', label: '全部项目' },
            ...(projects.data?.data || []).map((p) => ({ value: String(p.id), label: p.name })),
          ]}
        />

        <Input
          className="w-64"
          value={keyword}
          onChange={(e) => setKeyword(e.target.value)}
          placeholder="搜索种子值"
          prefix={<Search className="h-4 w-4 text-muted-foreground" />}
        />

        <Button size="small" onClick={() => seeds.refetch()} disabled={seeds.isFetching}>
          <RefreshCw className={seeds.isFetching ? 'mr-1 h-4 w-4 animate-spin' : 'mr-1 h-4 w-4'} />
          刷新
        </Button>

        <span className="text-muted-foreground ml-auto text-sm">共 {items.length} 个种子</span>
      </div>

      <div className="bg-background overflow-hidden rounded-md border">
        <Table<Seed>
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={seeds.isLoading}
          pagination={false}
          locale={{
            emptyText: (
              <EmptyState
                className="my-8"
                icon={Sprout}
                title={keyword ? '没有匹配的种子' : '这里还没有种子'}
                description={
                  keyword
                    ? '换个关键词试试，或清空搜索查看全部。'
                    : '种子在项目详情页里维护：进项目，添加域名或网段，监控计划会自动按时展开。'
                }
                hints={['域名种子展开子域与站点', '网段种子用于 IP 资产', '种子本身不发请求，由计划与批次执行']}
                actions={
                  <Button size="small" onClick={() => navigate('/projects')}>
                    打开项目管理
                  </Button>
                }
              />
            ),
          }}
        />
      </div>
    </div>
  )
}

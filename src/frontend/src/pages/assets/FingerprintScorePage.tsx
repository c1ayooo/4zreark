import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {keepPreviousData, useQuery} from '@tanstack/react-query'
import { assetApi } from '@/api/assets'
import {
  fingerprintScoreApi,
  FpScoreBand,
  FpScoreItem,
  FpScoreLevel,
  FpScoreSort,
} from '@/api/fingerprint-scores'
import { Button, Input, Pagination, Progress, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import EmptyState from '@/components/common/EmptyState'
import { cn } from '@/lib/utils'
import {
  ChevronRight,
  Fingerprint,
  RefreshCw,
  Search,
  SlidersHorizontal,
  X,
} from 'lucide-react'
import { statusTagClass } from '@/components/ui/StatusTag'

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass
const FALLBACK_LEVEL_LABEL: Record<FpScoreLevel, string> = {
  high: '高危',
  medium: '中危',
  low: '低危',
  none: '无信号',
}

const levelMeta: Record<FpScoreLevel, { badge: BadgeVariant; dot: string; stroke: string }> = {
  high: { badge: 'destructive', dot: 'bg-destructive', stroke: 'hsl(var(--destructive))' },
  medium: { badge: 'warning', dot: 'bg-yellow-500', stroke: '#eab308' },
  low: { badge: 'info', dot: 'bg-blue-500', stroke: '#3b82f6' },
  none: { badge: 'outline', dot: 'bg-muted-foreground/40', stroke: 'hsl(var(--muted-foreground) / 0.4)' },
}

const stateLabel: Record<string, string> = {
  reachable: '可访问',
  lost: '失联',
  archived: '已归档',
  pending: '待验证',
}

const stateVariant = (state: string): BadgeVariant => {
  if (state === 'reachable') return 'default'
  if (state === 'lost') return 'destructive'
  if (state === 'archived') return 'outline'
  return 'secondary'
}

const SORTS: { value: FpScoreSort; label: string }[] = [
  { value: 'score', label: '评分优先' },
  { value: 'assets', label: '指纹数量' },
  { value: 'host', label: '主机名' },
]

const PAGE_SIZES = [20, 50, 100, 200]

/** 评分依据：分数 + 每条命中的来源和分值。 */
const scoreTitle = (item: FpScoreItem) => {
  if (item.matches.length === 0) return '该资产还没有可用指纹'
  return [
    `指纹评分 ${item.score} / 100 · ${item.level_label || item.level}`,
    ...item.matches.map((m) => `+${m.points} ${m.name}${m.category ? `（${m.category_label || m.category}）` : ''}`),
  ].join('\n')
}

function clampScore(v: string): string {
  if (v.trim() === '') return ''
  const n = Number(v)
  if (!Number.isFinite(n)) return ''
  return String(Math.min(100, Math.max(0, Math.round(n))))
}

export default function FingerprintScorePage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const [projectId, setProjectId] = useState(() => searchParams.get('project_id') || '0')
  const [q, setQ] = useState(() => searchParams.get('q') || '')
  const [appliedQ, setAppliedQ] = useState(() => searchParams.get('q') || '')
  const [level, setLevel] = useState<FpScoreLevel | ''>(() => {
    const v = searchParams.get('level')
    return v === 'high' || v === 'medium' || v === 'low' || v === 'none' ? v : ''
  })
  const [minScore, setMinScore] = useState(() => clampScore(searchParams.get('min_score') || ''))
  const [maxScore, setMaxScore] = useState(() => clampScore(searchParams.get('max_score') || ''))
  const [minDraft, setMinDraft] = useState(minScore)
  const [maxDraft, setMaxDraft] = useState(maxScore)
  const [category, setCategory] = useState(() => searchParams.get('category') || '')
  const [fingerprint, setFingerprint] = useState(() => searchParams.get('fingerprint') || '')
  const [fpDraft, setFpDraft] = useState(fingerprint)
  const [sort, setSort] = useState<FpScoreSort>(() => {
    const v = searchParams.get('sort')
    return v === 'host' || v === 'assets' ? v : 'score'
  })
  const [page, setPage] = useState(() => Math.max(1, Number(searchParams.get('page')) || 1))
  const [pageSize, setPageSize] = useState(() => {
    const n = Number(searchParams.get('page_size'))
    return PAGE_SIZES.includes(n) ? n : 20
  })

  // 所有筛选/分页同步进 URL：刷新和分享链接能还原完整视图。
  useEffect(() => {
    const next = new URLSearchParams()
    if (projectId !== '0') next.set('project_id', projectId)
    if (appliedQ) next.set('q', appliedQ)
    if (level) next.set('level', level)
    if (minScore) next.set('min_score', minScore)
    if (maxScore) next.set('max_score', maxScore)
    if (category) next.set('category', category)
    if (fingerprint) next.set('fingerprint', fingerprint)
    if (sort !== 'score') next.set('sort', sort)
    if (pageSize !== 20) next.set('page_size', String(pageSize))
    if (page > 1) next.set('page', String(page))
    setSearchParams(next, { replace: true })
  }, [
    projectId, appliedQ, level, minScore, maxScore, category, fingerprint, sort,
    page, pageSize, setSearchParams,
  ])

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => assetApi.projects() })

  const list = useQuery({
    queryKey: [
      'fingerprint-scores', page, pageSize, projectId, appliedQ, level,
      minScore, maxScore, category, fingerprint, sort,
    ],
    staleTime: 30_000,
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      fingerprintScoreApi.list({
        project_id: Number(projectId) || undefined,
        q: appliedQ || undefined,
        level: level || undefined,
        min_score: Number(minScore) || undefined,
        max_score: Number(maxScore) || undefined,
        category: category || undefined,
        fingerprint: fingerprint || undefined,
        sort,
        page,
        page_size: pageSize,
      }),
  })

  const data = list.data?.data
  const items = data?.items ?? []
  const facets = data?.facets
  const total = data?.total ?? 0
  const hasFilters = !!appliedQ || !!level || !!minScore || !!maxScore || !!category || !!fingerprint

  // 档位中文名来自分档计数；没拿到（比如还没加载完）时退回固定文案。
  const bandLabel = (lv: FpScoreLevel) =>
    facets?.bands.find((b) => b.level === lv)?.label || FALLBACK_LEVEL_LABEL[lv]

  // 分类原始键 → 中文名；表格里的分类标签也用这份映射。
  // 资产上的分类保留原始写法（Web-Server），facet 的 name 已归一化（web-server）。
  const categoryKey = (name: string) =>
    name.trim().toLowerCase().replace(/[_\s]+/g, '-')
  const categoryLabel = (name: string) =>
    facets?.categories.find((c) => c.name === categoryKey(name))?.label || name

  const applyBand = (band: FpScoreBand) => {
    setLevel((cur) => (cur === band.level ? '' : band.level))
    setMinScore('')
    setMaxScore('')
    setMinDraft('')
    setMaxDraft('')
    setPage(1)
  }

  const commitRange = () => {
    const min = clampScore(minDraft)
    const max = clampScore(maxDraft)
    setMinDraft(min)
    setMaxDraft(max)
    setMinScore(min)
    setMaxScore(max)
    if (min || max) setLevel('')
    setPage(1)
  }

  const applyFingerprint = (name: string) => {
    setFingerprint(name)
    setFpDraft(name)
    setPage(1)
  }

  const clearAll = () => {
    setQ('')
    setAppliedQ('')
    setLevel('')
    setMinScore('')
    setMaxScore('')
    setMinDraft('')
    setMaxDraft('')
    setCategory('')
    setFingerprint('')
    setFpDraft('')
    setPage(1)
  }

  const columns: TableProps<FpScoreItem>['columns'] = [
    {
      title: '资产',
      key: 'host',
      render: (_, item) => (
        <>
          <div className="break-all text-sm font-medium">{item.host}</div>
          <div className="mt-0.5 max-w-[420px] truncate text-[13px] text-muted-foreground">
            {item.title || item.value}
            {item.ip && item.ip !== item.host ? ` · ${item.ip}` : ''}
          </div>
          <div className="mt-1 flex items-center gap-2 md:hidden">
            <Tag className={cn('tabular-nums', badgeCls(levelMeta[item.level]?.badge ?? levelMeta.none.badge))}>
              {item.score}
            </Tag>
            <span className="text-[13px] text-muted-foreground">{item.level_label}</span>
          </div>
        </>
      ),
    },
    {
      title: '项目',
      dataIndex: 'project_name',
      key: 'project_name',
      width: 110,
      className: 'hidden lg:table-cell',
      render: (v: string) => <span className="text-sm">{v}</span>,
    },
    {
      title: '指纹评分',
      key: 'score',
      width: 170,
      className: 'hidden text-right md:table-cell',
      render: (_, item) => {
        const meta = levelMeta[item.level] ?? levelMeta.none
        return (
          <div title={scoreTitle(item)}>
            <div className="flex items-center justify-end gap-2">
              <div className="w-20">
                <Progress
                  percent={Math.min(100, Math.max(0, item.score))}
                  showInfo={false}
                  strokeWidth={6}
                  strokeColor={meta.stroke}
                />
              </div>
              <Tag className={cn('tabular-nums', badgeCls(meta.badge))}>{item.score}</Tag>
            </div>
            <div className="mt-0.5 text-[13px] tabular-nums text-muted-foreground">{item.level_label}</div>
          </div>
        )
      },
    },
    {
      title: '命中指纹',
      key: 'matches',
      className: 'hidden xl:table-cell',
      render: (_, item) => (
        <div className="flex max-w-[360px] flex-wrap items-center gap-1">
          {item.matches.slice(0, 3).map((m) => (
            <button
              key={`${m.source}-${m.name}`}
              type="button"
              title={`${m.reason} +${m.points}`}
              onClick={(e) => {
                e.stopPropagation()
                applyFingerprint(m.name)
              }}
              className="rounded-full border px-2 py-0.5 text-[13px] tabular-nums hover:bg-muted"
            >
              {m.name}
              <span className="ml-1 font-mono tabular-nums text-muted-foreground">{m.points}</span>
            </button>
          ))}
          {item.matches.length > 3 && (
            <span className="text-[13px] tabular-nums text-muted-foreground">
              +{item.matches.length - 3}
            </span>
          )}
          {item.matches.length === 0 && (
            <span className="text-[13px] text-muted-foreground">—</span>
          )}
        </div>
      ),
    },
    {
      title: '分类',
      key: 'categories',
      width: 150,
      className: 'hidden xl:table-cell',
      render: (_, item) => (
        <div className="flex flex-wrap gap-1">
          {item.categories.map((c) => (
            <button
              key={c}
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                setCategory(c)
                setPage(1)
              }}
              className="rounded border px-1.5 py-0.5 text-[13px] text-muted-foreground hover:bg-muted"
            >
              {categoryLabel(c)}
            </button>
          ))}
          {item.categories.length === 0 && <span className="text-[13px] text-muted-foreground">—</span>}
        </div>
      ),
    },
    {
      title: '状态',
      key: 'state',
      width: 110,
      render: (_, item) => (
        <Tag className={badgeCls(stateVariant(item.state))}>
          {stateLabel[item.state] ?? item.state}
        </Tag>
      ),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen',
      key: 'last_seen',
      width: 110,
      className: 'hidden text-right xl:table-cell',
      render: (v: string | null) => (
        <span className="text-[13px] tabular-nums text-muted-foreground">{v?.slice(0, 10)}</span>
      ),
    },
    {
      title: '',
      key: 'go',
      width: 32,
      render: () => (
        <span className="text-muted-foreground">
          <ChevronRight className="h-4 w-4" />
        </span>
      ),
    },
  ]

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-semibold">
            <Fingerprint className="h-5 w-5" />
            指纹评分
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            按项目汇总资产，用指纹命中的产品与分类折算 0-100 分；分数越高越值得优先测试。
          </p>
          {facets && (
            <p className="mt-1 text-[13px] text-muted-foreground">
              候选资产 {facets.total.toLocaleString()} 个 · 有指纹{' '}
              {facets.scored.toLocaleString()} 个 · 平均分 {facets.avg_score}
              {data?.truncated &&
                ` · 候选过多，仅对其中 ${data.scored_count.toLocaleString()} 个计算（优先有指纹的资产）`}
            </p>
          )}
        </div>
        <Button onClick={() => list.refetch()}>
          <RefreshCw className="mr-2 h-4 w-4" /> 刷新
        </Button>
      </div>

      {/* 分档导航：计数来自当前项目/关键词条件，不受档位自身筛选影响 */}
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        <button
          type="button"
          onClick={() => {
            setLevel('')
            setMinScore('')
            setMaxScore('')
            setMinDraft('')
            setMaxDraft('')
            setPage(1)
          }}
          className={cn(
            'rounded-md border px-3 py-2 text-left transition-colors',
            !level && !minScore && !maxScore
              ? 'border-foreground/30 bg-muted'
              : 'hover:bg-muted/50'
          )}
        >
          <div className="text-[13px] text-muted-foreground">全部资产</div>
          <div className="text-lg font-semibold tabular-nums">{facets?.total ?? 0}</div>
        </button>
        {(facets?.bands ?? []).map((band) => {
          const meta = levelMeta[band.level]
          const active = level === band.level
          return (
            <button
              key={band.level}
              type="button"
              onClick={() => applyBand(band)}
              className={cn(
                'rounded-md border px-3 py-2 text-left transition-colors',
                active ? 'border-foreground/30 bg-muted' : 'hover:bg-muted/50'
              )}
            >
              <div className="flex items-center justify-between text-[13px]">
                <span className="text-muted-foreground">{band.label}</span>
                <span className="font-mono text-[13px] tabular-nums text-muted-foreground">
                  {band.min}-{band.max}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={cn('h-2 w-2 rounded-full', meta.dot)} />
                <span className="text-lg font-semibold tabular-nums">{band.count}</span>
              </div>
            </button>
          )
        })}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Select
          className="w-[200px]"
          value={projectId}
          onChange={(v) => {
            setProjectId(v)
            setPage(1)
          }}
          placeholder="全部项目"
          options={[
            { value: '0', label: '全部项目' },
            ...(projects.data?.data ?? []).map((p) => ({
              value: String(p.id),
              label: `${p.name}（${p.asset_count}）`,
            })),
          ]}
        />

        <div className="relative min-w-[240px] flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground z-10" />
          <Input
            className="pl-9"
            placeholder="搜索主机名或 URL，回车查询"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                setAppliedQ(q.trim())
                setPage(1)
              }
            }}
          />
        </div>
        <Button
          type="primary"
          onClick={() => {
            setAppliedQ(q.trim())
            setPage(1)
          }}
        >
          查询
        </Button>

        <div className="flex items-center gap-1 rounded-md border px-2 py-1">
          <SlidersHorizontal className="mr-1 h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-[13px] text-muted-foreground">分数</span>
          <Input
            className="h-7 w-14 border-0 px-1 text-center font-mono text-sm"
            inputMode="numeric"
            placeholder="0"
            value={minDraft}
            onChange={(e) => setMinDraft(e.target.value)}
            onBlur={commitRange}
            onKeyDown={(e) => e.key === 'Enter' && commitRange()}
          />
          <span className="text-muted-foreground">-</span>
          <Input
            className="h-7 w-14 border-0 px-1 text-center font-mono text-sm"
            inputMode="numeric"
            placeholder="100"
            value={maxDraft}
            onChange={(e) => setMaxDraft(e.target.value)}
            onBlur={commitRange}
            onKeyDown={(e) => e.key === 'Enter' && commitRange()}
          />
        </div>

        <Select
          className="w-[180px]"
          value={category || 'all'}
          onChange={(v) => {
            setCategory(v === 'all' ? '' : v)
            setPage(1)
          }}
          placeholder="全部分类"
          options={[
            { value: 'all', label: '全部分类' },
            ...(facets?.categories ?? []).map((c) => ({
              value: c.name,
              label: `${c.label || c.name}（${c.asset_count}）`,
            })),
          ]}
        />

        <Select
          className="w-[120px]"
          value={sort}
          onChange={(v) => {
            setSort(v as FpScoreSort)
            setPage(1)
          }}
          options={SORTS.map((s) => ({ value: s.value, label: s.label }))}
        />

        <div className="flex items-center gap-1 rounded-md border px-2 py-1">
          <Fingerprint className="mr-1 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            className="h-7 w-36 border-0 px-1 text-sm"
            placeholder="指纹名，回车筛选"
            value={fpDraft}
            onChange={(e) => setFpDraft(e.target.value)}
            onBlur={() => applyFingerprint(fpDraft.trim())}
            onKeyDown={(e) => {
              if (e.key === 'Enter') applyFingerprint(fpDraft.trim())
              if (e.key === 'Escape') {
                setFpDraft('')
                applyFingerprint('')
              }
            }}
          />
        </div>

        {hasFilters && (
          <Button type="text" onClick={clearAll}>
            <X className="mr-1 h-4 w-4" /> 清空筛选
          </Button>
        )}
      </div>

      <div className="rounded-md border">
        <Table
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={list.isLoading}
          onRow={(record) => ({
            className: 'cursor-pointer',
            onClick: () => navigate(`/assets/${record.id}`),
          })}
          locale={{
            emptyText: hasFilters ? (
              <EmptyState
                icon={Search}
                title="没有匹配的资产"
                description="当前分数区间或筛选条件下没有资产。"
                hints={[
                  level ? `档位：${bandLabel(level)}` : '档位：全部',
                  minScore || maxScore ? `分数：${minScore || 0} - ${maxScore || 100}` : '分数：不限',
                  category ? `分类：${categoryLabel(category)}` : '分类：全部',
                  fingerprint ? `指纹：${fingerprint}` : '指纹：不限',
                ]}
                actions={
                  <Button size="small" onClick={clearAll}>
                    清空筛选
                  </Button>
                }
              />
            ) : (
              <EmptyState
                icon={Fingerprint}
                title={projectId === '0' ? '还没有可评分的资产' : '这个项目还没有可评分的资产'}
                description="指纹评分依赖站点已识别的技术栈或指纹规则命中。跑一次带指纹识别的任务后再回来。"
                hints={[
                  '指纹来源：探测时命中的 fingerprint_rules，以及站点技术栈',
                  '分析完成后，这里会按分数从高到低列出资产',
                ]}
                actions={
                  <Button type="primary" size="small" onClick={() => navigate('/tasks/new')}>
                    建一个侦察任务
                  </Button>
                }
              />
            ),
          }}
          pagination={false}
        />
      </div>

      <div className="flex flex-wrap items-center justify-end gap-3">
        <Pagination
          current={page}
          pageSize={pageSize}
          total={total}
          pageSizeOptions={PAGE_SIZES.map(String)}
          showQuickJumper
          showSizeChanger
          showTotal={(t) => `共 ${t.toLocaleString()} 条`}
          onChange={(p, s) => {
            setPage(p)
            setPageSize(s)
          }}
        />
      </div>
    </div>
  )
}

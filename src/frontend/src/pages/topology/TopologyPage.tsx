import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Search } from 'lucide-react'
import { Button, Card, Input, Select } from 'antd'

import { assetApi, type AssetGraphData } from '@/api/assets'
import { AssetGraphCanvas } from '@/components/assets/AssetGraphCanvas'
import { cn } from '@/lib/utils'

export default function TopologyPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [projectID, setProjectID] = useState<number>(() => Number(searchParams.get('project_id')) || 0)
  const [keyword, setKeyword] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [data, setData] = useState<AssetGraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [showAll, setShowAll] = useState(false)

  // 轮询签名：结构没变就不 setData，避免节点位置被重置。
  const sigRef = useRef('')
  const requestSeq = useRef(0)

  // 后端 q 是资产 DSL（host = "x"）。这里把裸关键字自动包成 host 条件，
  // 含操作符的输入按 DSL 原样透传，避免用户必须记住语法。
  const buildQuery = (raw: string): string | undefined => {
    const v = raw.trim()
    if (!v) return undefined
    if (/[=!<>]/.test(v)) return v
    return `host = "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  }

  // 概览/全量共用同一份全量数据：概览在前端懒展开渲染（每层限量），
  // 全量一次铺开。这样点击展开不需要额外的按需请求。
  const fetchGraph = useCallback(async () => {
    const seq = ++requestSeq.current
    setLoading(true)
    try {
      const res = await assetApi.graph({
        project_id: projectID || undefined,
        q: buildQuery(keyword),
      })
      if (seq !== requestSeq.current) return
      const g = res.data
      const n = g.nodes ?? []
      const e = g.edges ?? []
      const sig = JSON.stringify([
        g.summary,
        g.counts,
        g.totals,
        n.map((x) => [x.key, x.kind, x.state, x.title, x.status_code]),
        e.map((x) => [x.src, x.dst, x.rel]),
      ])
      if (sig === sigRef.current) return
      sigRef.current = sig
      setData({ ...g, nodes: n, edges: e })
    } catch {
      /* 保留上一次数据 */
    } finally {
      if (seq === requestSeq.current) {
        setLoading(false)
      }
    }
  }, [projectID, keyword])

  useEffect(() => {
    sigRef.current = ''
    setShowAll(false)
    fetchGraph()
    const timer = setInterval(() => {
      // 隐藏标签页不轮询
      if (document.visibilityState === 'visible') {
        fetchGraph()
      }
    }, 60000)
    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        fetchGraph()
      }
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [fetchGraph])

  const { data: projectsRes } = useQuery({
    queryKey: ['projects'],
    queryFn: () => assetApi.projects(),
  })
  const projects = projectsRes?.data ?? []

  // 项目详情跳过来时带 project_id，切换项目后同步回 URL。
  const changeProject = (v: string) => {
    const id = Number(v) || 0
    setProjectID(id)
    const next = new URLSearchParams(searchParams)
    if (id > 0) next.set('project_id', String(id))
    else next.delete('project_id')
    setSearchParams(next, { replace: true })
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold">资产星图</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            项目 → 根域名 → 子域名 → 子子域名 → 服务 → 接口/入口，点击节点逐层展开。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select
            className="w-[180px]"
            value={String(projectID)}
            onChange={(v) => changeProject(v)}
            options={[
              { value: '0', label: '全部项目' },
              ...projects.map((p) => ({ value: String(p.id), label: p.name })),
            ]}
          />
          <Input
            className="w-[220px]"
            placeholder="搜索主机 / DSL，回车确认"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') setKeyword(searchInput.trim())
            }}
            prefix={<Search className="h-4 w-4 text-muted-foreground" />}
          />
          <Button size="small" onClick={() => fetchGraph()} disabled={loading}>
            <RefreshCw className={cn('mr-2 h-4 w-4', loading && 'animate-spin')} />
            刷新
          </Button>
        </div>
      </div>

      <Card styles={{ body: { padding: 0 } }}>
        {/* key 绑定筛选条件：切换项目/搜索后画布重建，丢弃上一个视图的
            节点坐标与展开状态，避免新旧布局混杂错位 */}
        <AssetGraphCanvas
          key={`topo-${projectID}-${keyword}`}
          data={data}
          loading={loading}
          showAll={showAll}
          onShowAllChange={setShowAll}
        />
      </Card>
    </div>
  )
}

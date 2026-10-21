import { useCallback, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Search } from 'lucide-react'

import { assetApi, type AssetGraphData } from '@/api/assets'
import { AssetGraphCanvas } from '@/components/assets/AssetGraphCanvas'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { cn } from '@/lib/utils'

export default function TopologyPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [projectID, setProjectID] = useState<number>(() => Number(searchParams.get('project_id')) || 0)
  const [keyword, setKeyword] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [data, setData] = useState<AssetGraphData | null>(null)
  const [loading, setLoading] = useState(true)
  const [showAll, setShowAll] = useState(false)
  const [fullLoading, setFullLoading] = useState(false)

  // 轮询签名：结构没变就不 setData，避免节点位置被重置。
  const sigRef = useRef('')
  const requestSeq = useRef(0)
  const showAllRef = useRef(false)

  // 后端 q 是资产 DSL（host = "x"）。这里把裸关键字自动包成 host 条件，
  // 含操作符的输入按 DSL 原样透传，避免用户必须记住语法。
  const buildQuery = (raw: string): string | undefined => {
    const v = raw.trim()
    if (!v) return undefined
    if (/[=!<>]/.test(v)) return v
    return `host = "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  }

  const fetchGraph = useCallback(async (mode: 'summary' | 'full' = 'summary') => {
    const seq = ++requestSeq.current
    if (mode === 'full') setFullLoading(true)
    else setLoading(true)
    try {
      const res = await assetApi.graph({
        project_id: projectID || undefined,
        q: buildQuery(keyword),
        mode,
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
        setFullLoading(false)
      }
    }
  }, [projectID, keyword])

  useEffect(() => {
    showAllRef.current = showAll
  }, [showAll])

  useEffect(() => {
    sigRef.current = ''
    setShowAll(false)
    fetchGraph('summary')
    const timer = setInterval(() => {
      // 隐藏标签页不轮询；全量模式也不自动拉，避免反复下载大图。
      if (document.visibilityState === 'visible' && !showAllRef.current) {
        fetchGraph('summary')
      }
    }, 30000)
    const onVisible = () => {
      if (document.visibilityState === 'visible' && !showAllRef.current) {
        fetchGraph('summary')
      }
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [fetchGraph])

  const changeShowAll = (value: boolean) => {
    setShowAll(value)
    fetchGraph(value ? 'full' : 'summary')
  }

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
            项目 → 根域名 → 子域名 → IP → 服务 → 入口，左到右分层。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={String(projectID)} onValueChange={changeProject}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="全部项目" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">全部项目</SelectItem>
              {projects.map((p) => (
                <SelectItem key={p.id} value={String(p.id)}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div className="relative">
            <Search className="text-muted-foreground absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2" />
            <Input
              placeholder="搜索主机 / DSL，回车确认"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') setKeyword(searchInput.trim())
              }}
              className="w-[220px] pl-9"
            />
          </div>
          <Button variant="outline" size="sm" onClick={() => fetchGraph(showAll ? 'full' : 'summary')} disabled={loading || fullLoading}>
            <RefreshCw className={cn('mr-2 h-4 w-4', loading && 'animate-spin')} />
            刷新
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <AssetGraphCanvas
            data={data}
            loading={loading}
            showAll={showAll}
            onShowAllChange={changeShowAll}
            loadingFull={fullLoading}
          />
        </CardContent>
      </Card>
    </div>
  )
}

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

  // 轮询签名：结构没变就不 setData，避免节点位置被重置。
  const sigRef = useRef('')

  // 后端 q 是资产 DSL（host = "x"）。这里把裸关键字自动包成 host 条件，
  // 含操作符的输入按 DSL 原样透传，避免用户必须记住语法。
  const buildQuery = (raw: string): string | undefined => {
    const v = raw.trim()
    if (!v) return undefined
    if (/[=!<>]/.test(v)) return v
    return `host = "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  }

  const fetchGraph = useCallback(() => {
    setLoading(true)
    assetApi
      .graph({ project_id: projectID || undefined, q: buildQuery(keyword) })
      .then((res) => {
        const g = res.data
        const n = g.nodes ?? []
        const e = g.edges ?? []
        const sig = JSON.stringify([
          n.map((x) => [x.key, x.kind, x.state, x.title, x.status_code]),
          e.map((x) => [x.src, x.dst, x.rel]),
        ])
        if (sig === sigRef.current) return
        sigRef.current = sig
        setData({ ...g, nodes: n, edges: e })
      })
      .catch(() => {
        /* 保留上一次数据 */
      })
      .finally(() => setLoading(false))
  }, [projectID, keyword])

  useEffect(() => {
    sigRef.current = ''
    fetchGraph()
    const timer = setInterval(fetchGraph, 30000)
    return () => clearInterval(timer)
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
          <Button variant="outline" size="sm" onClick={fetchGraph} disabled={loading}>
            <RefreshCw className={cn('mr-2 h-4 w-4', loading && 'animate-spin')} />
            刷新
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <AssetGraphCanvas data={data} loading={loading} />
        </CardContent>
      </Card>
    </div>
  )
}

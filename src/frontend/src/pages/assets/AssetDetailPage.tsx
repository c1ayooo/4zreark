import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowLeft,
  ExternalLink,
  Fingerprint,
  GitBranch,
  Globe,
  Link2,
  Radar,
  RefreshCw,
  Server,
  ShieldAlert,
} from 'lucide-react'

import {
  assetApi,
  type AssetEvent,
  type AssetFingerprintHit,
  type AssetRawRecord,
  type AssetRelation,
  type AssetVerification,
  type Site,
} from '@/api/assets'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'

const stateLabel: Record<string, string> = {
  reachable: '可访问',
  lost: '失联',
  archived: '已归档',
  pending: '待验证',
}

const stateVariant = (state: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (state === 'reachable') return 'default'
  if (state === 'lost') return 'destructive'
  if (state === 'archived') return 'outline'
  return 'secondary'
}

const priorityVariant = (p: string): 'default' | 'secondary' | 'destructive' | 'outline' => {
  if (p === 'p0' || p === 'p1') return 'destructive'
  if (p === 'p2') return 'default'
  if (p === 'p3') return 'secondary'
  return 'outline'
}

const verificationLabel: Record<string, string> = {
  verified: '已验证',
  reachable: '可达',
  unreachable: '不可达',
  inconclusive: '判不出',
  pending: '待验证',
  failed: '验证失败',
}

const verificationVariant = (
  status: string,
): 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' => {
  if (status === 'verified' || status === 'reachable') return 'success'
  if (status === 'unreachable' || status === 'failed') return 'destructive'
  if (status === 'inconclusive') return 'warning'
  return 'outline'
}

const eventLabel: Record<string, string> = {
  first_seen: '首次发现',
  attribute_change: '属性变化',
  reappear: '重新出现',
  lost: '失联',
  archived: '归档',
  restored: '恢复',
}

const relationLabel: Record<string, string> = {
  same_ip: '同 IP',
  same_icon: '同图标',
  same_fp: '同技术栈',
  domain_parent: '父子域',
  same_cert: '同证书',
  cname: 'CNAME',
}

const fmtDate = (v?: string | null) => (v ? formatDate(v) : '—')

const hasKeys = (v?: Record<string, unknown> | null) => !!v && Object.keys(v).length > 0

function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return '—'
  if (typeof v === 'string') return v || '—'
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

function diffKeys(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(before ?? {}), ...Object.keys(after ?? {})])].filter(
    (k) => JSON.stringify(before?.[k]) !== JSON.stringify(after?.[k]),
  )
}

function Stat({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Globe
  label: string
  value: ReactNode
  tone?: 'danger' | 'success'
}) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 p-4">
        <span
          className={cn(
            'flex size-9 shrink-0 items-center justify-center rounded-lg',
            tone === 'danger'
              ? 'bg-destructive/10 text-destructive'
              : tone === 'success'
                ? 'bg-emerald-500/10 text-emerald-600'
                : 'bg-primary/10 text-primary',
          )}
        >
          <Icon className="size-4" />
        </span>
        <div className="min-w-0">
          <div className="text-muted-foreground text-xs">{label}</div>
          <div className="truncate text-lg font-semibold tabular-nums">{value}</div>
        </div>
      </CardContent>
    </Card>
  )
}

function SectionCard({
  title,
  description,
  action,
  children,
}: {
  title: string
  description?: string
  action?: ReactNode
  children: ReactNode
}) {
  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <CardTitle className="text-base">{title}</CardTitle>
            {description && <p className="text-muted-foreground mt-1 text-xs">{description}</p>}
          </div>
          {action}
        </div>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function Verifications({ items }: { items: AssetVerification[] }) {
  if (items.length === 0) {
    return <p className="text-muted-foreground py-4 text-sm">还没有验证记录</p>
  }
  return (
    <div className="space-y-2">
      {items.map((v) => (
        <div key={v.id} className="rounded-md border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Badge variant={verificationVariant(v.status)}>
                {verificationLabel[v.status] ?? v.status}
              </Badge>
              {v.http_status > 0 && <span className="font-mono text-xs">HTTP {v.http_status}</span>}
              <span className="text-muted-foreground text-xs">第 {v.attempts} 次</span>
            </div>
            <span className="text-muted-foreground text-xs">{fmtDate(v.observed_at)}</span>
          </div>
          {v.reason_code && <p className="mt-1 font-mono text-xs">{v.reason_code}</p>}
          {hasKeys(v.detail) && (
            <details className="mt-2">
              <summary className="text-muted-foreground cursor-pointer text-xs">验证详情</summary>
              <pre className="bg-muted mt-1 max-h-48 overflow-auto rounded p-2 text-[11px]">
                {JSON.stringify(v.detail, null, 2)}
              </pre>
            </details>
          )}
        </div>
      ))}
    </div>
  )
}

function Fingerprints({ items }: { items: AssetFingerprintHit[] }) {
  if (items.length === 0) {
    return <p className="text-muted-foreground py-4 text-sm">还没有指纹命中</p>
  }
  return (
    <div className="space-y-2">
      {items.map((f) => (
        <div key={f.rule_id} className="rounded-md border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <Fingerprint className="text-muted-foreground size-3.5 shrink-0" />
              <span className="truncate text-sm font-medium">{f.rule_name}</span>
              {f.category && <Badge variant="outline">{f.category}</Badge>}
            </div>
            <span className="text-muted-foreground text-xs">{fmtDate(f.observed_at)}</span>
          </div>
          {f.record_id && (
            <p className="text-muted-foreground mt-1 font-mono text-[11px]">
              证据记录 #{f.record_id}
            </p>
          )}
          {hasKeys(f.evidence) && (
            <details className="mt-2">
              <summary className="text-muted-foreground cursor-pointer text-xs">命中证据</summary>
              <pre className="bg-muted mt-1 max-h-48 overflow-auto rounded p-2 text-[11px]">
                {JSON.stringify(f.evidence, null, 2)}
              </pre>
            </details>
          )}
        </div>
      ))}
    </div>
  )
}

function Events({ items }: { items: AssetEvent[] }) {
  if (items.length === 0) {
    return <p className="text-muted-foreground py-4 text-sm">还没有变更事件</p>
  }
  return (
    <div className="space-y-2">
      {items.map((e) => {
        const keys = diffKeys(e.before, e.after)
        return (
          <div key={e.id} className="rounded-md border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Badge variant="outline">{eventLabel[e.event_type] ?? e.event_type}</Badge>
                <span className="text-sm font-medium">{e.title}</span>
              </div>
              <span className="text-muted-foreground text-xs">{fmtDate(e.created_at)}</span>
            </div>
            {keys.length > 0 ? (
              <div className="mt-2 space-y-1 text-xs">
                {keys.map((k) => (
                  <div key={k} className="flex flex-wrap items-baseline gap-1">
                    <span className="text-muted-foreground font-mono">{k}</span>
                    <span className="text-muted-foreground line-through">{fmtValue(e.before?.[k])}</span>
                    <span className="text-muted-foreground">→</span>
                    <span className="font-medium">{fmtValue(e.after?.[k])}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground mt-1 text-xs">无字段变化</p>
            )}
          </div>
        )
      })}
    </div>
  )
}

function Records({ items }: { items: AssetRawRecord[] }) {
  if (items.length === 0) {
    return <p className="text-muted-foreground py-4 text-sm">还没有原始记录</p>
  }
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>来源</TableHead>
          <TableHead>入口</TableHead>
          <TableHead>状态码</TableHead>
          <TableHead>标题</TableHead>
          <TableHead>观测时间</TableHead>
          <TableHead className="w-16" />
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((r) => (
          <TableRow key={r.id}>
            <TableCell className="text-xs">{r.source}</TableCell>
            <TableCell className="max-w-[260px] truncate font-mono text-xs">{r.value}</TableCell>
            <TableCell>
              <Badge variant={r.status_code >= 200 && r.status_code < 400 ? 'default' : 'secondary'}>
                {r.status_code || '—'}
              </Badge>
            </TableCell>
            <TableCell className="max-w-[220px] truncate text-sm">{r.title || '—'}</TableCell>
            <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
              {fmtDate(r.observed_at)}
            </TableCell>
            <TableCell>
              {hasKeys(r.evidence) && (
                <details>
                  <summary className="text-muted-foreground cursor-pointer text-xs">证据</summary>
                  <pre className="bg-muted mt-1 max-h-40 w-64 overflow-auto rounded p-2 text-[11px]">
                    {JSON.stringify(r.evidence, null, 2)}
                  </pre>
                </details>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function Relations({ items }: { items: AssetRelation[] }) {
  if (items.length === 0) {
    return (
      <p className="text-muted-foreground py-4 text-sm">
        暂无关系边。关系只从有原始记录证据的站点生成。
      </p>
    )
  }
  return (
    <div className="space-y-2">
      {items.map((r) => (
        <div key={r.id} className="rounded-md border p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <Badge variant="info">{relationLabel[r.type] ?? r.type}</Badge>
              <Link
                to={`/assets/${r.peer.id}`}
                className="text-primary min-w-0 truncate font-mono text-sm hover:underline"
              >
                {r.peer.value || r.peer.host}
              </Link>
              <span className="text-muted-foreground text-xs">
                置信度 {(r.confidence * 100).toFixed(0)}%
              </span>
            </div>
            <Link to={`/assets/${r.peer.id}`} className="text-muted-foreground text-xs">
              打开关联资产
            </Link>
          </div>
          {r.peer.title && <p className="text-muted-foreground mt-1 text-xs">{r.peer.title}</p>}
          {r.evidence.length > 0 ? (
            <ul className="mt-2 space-y-1">
              {r.evidence.map((ev) => (
                <li key={`${r.id}-${ev.record_id}`} className="text-xs">
                  <span className="text-muted-foreground">记录 #{ev.record_id}</span>
                  <span className="mx-1">·</span>
                  <span className="font-mono">{ev.source || '—'}</span>
                  <span className="mx-1">·</span>
                  <span className="break-all">{ev.value || ev.note || '—'}</span>
                  <span className="text-muted-foreground ml-1">({fmtDate(ev.observed_at)})</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground mt-1 text-xs">这条边没有可展示的证据记录</p>
          )}
        </div>
      ))}
    </div>
  )
}

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>()
  const idNum = Number(id)
  const validId = Number.isFinite(idNum) && idNum > 0
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [refreshing, setRefreshing] = useState(false)

  const detailQuery = useQuery({
    queryKey: ['asset-detail', idNum],
    queryFn: () => assetApi.detail(idNum),
    enabled: validId,
  })

  const probe = useMutation({
    mutationFn: () => assetApi.probe(idNum),
    onSuccess: (res) => {
      toast({ title: res.message || '探测完成' })
      queryClient.invalidateQueries({ queryKey: ['asset-detail', idNum] })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
    onError: (e: any) => {
      toast({
        title: '探测失败',
        description: e?.message || '请稍后重试',
        variant: 'destructive',
      })
    },
  })

  const refresh = async () => {
    setRefreshing(true)
    try {
      await detailQuery.refetch()
    } finally {
      setRefreshing(false)
    }
  }

  if (!validId) {
    return (
      <Card>
        <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16">
          资产 ID 不合法
          <Button asChild variant="outline" size="sm">
            <Link to="/assets">返回资产列表</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-20 w-full" />
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="h-72 w-full" />
      </div>
    )
  }

  const detail = detailQuery.data?.data
  if (!detail) {
    return (
      <Card>
        <CardContent className="text-muted-foreground flex flex-col items-center gap-3 py-16">
          <AlertTriangle className="text-destructive h-8 w-8" />
          {detailQuery.isError ? '资产详情加载失败' : '资产不存在'}
          <Button asChild variant="outline" size="sm">
            <Link to="/assets">返回资产列表</Link>
          </Button>
        </CardContent>
      </Card>
    )
  }

  const site: Site = detail.site
  const iconURL = site.icon_sha256 ? assetApi.iconURL(site.icon_sha256) : ''
  const endpoints = site.endpoints ?? []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <Button variant="ghost" size="icon" asChild aria-label="返回资产列表">
            <Link to={`/assets?project_id=${site.project_id}`} aria-label="返回资产列表">
              <ArrowLeft className="h-5 w-5" />
            </Link>
          </Button>
          {iconURL ? (
            <img
              src={iconURL}
              alt=""
              className="size-11 shrink-0 rounded-xl border bg-white object-contain p-1"
              onError={(e) => {
                ;(e.currentTarget as HTMLImageElement).style.visibility = 'hidden'
              }}
            />
          ) : (
            <span className="bg-muted flex size-11 shrink-0 items-center justify-center rounded-xl">
              <Globe className="size-5" />
            </span>
          )}
          <div className="min-w-0">
            <h1 className="truncate font-mono text-xl font-bold" title={site.value}>
              {site.value || `${site.host}:${site.port}`}
            </h1>
            <div className="text-muted-foreground mt-1 flex flex-wrap items-center gap-2 text-sm">
              <Link to={`/projects/${site.project_id}`} className="hover:text-foreground hover:underline">
                {site.project_name}
              </Link>
              <span>·</span>
              <span className="font-mono">{site.host}</span>
              {site.title && (
                <>
                  <span>·</span>
                  <span className="max-w-[360px] truncate">{site.title}</span>
                </>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" onClick={refresh} disabled={refreshing}>
            <RefreshCw className={cn('mr-2 h-4 w-4', refreshing && 'animate-spin')} />
            刷新
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => probe.mutate()}
            disabled={probe.isPending}
          >
            <Radar className="mr-2 h-4 w-4" />
            真实探测
          </Button>
          {site.value && (
            <Button variant="outline" size="sm" asChild>
              <a href={site.value} target="_blank" rel="noreferrer">
                <ExternalLink className="mr-2 h-4 w-4" />
                打开站点
              </a>
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={stateVariant(site.state)}>{stateLabel[site.state] ?? site.state}</Badge>
        <Badge variant={priorityVariant(site.priority)} title={`风险评分 ${site.risk_score}`}>
          {site.priority ? site.priority.toUpperCase() : '—'} · {site.risk_score}
        </Badge>
        <Badge variant={verificationVariant(site.verification_status)}>
          {verificationLabel[site.verification_status] ?? site.verification_status}
        </Badge>
        {endpoints.map((e) => (
          <Badge key={`${e.scheme}-${e.port}`} variant="outline" className="font-mono">
            {e.scheme}:{e.port}
            {e.status_code > 0 && ` · ${e.status_code}`}
          </Badge>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Stat icon={ShieldAlert} label="风险评分" value={`${site.risk_score} / 100`} />
        <Stat icon={Server} label="HTTP 状态" value={site.http_status || '—'} />
        <Stat icon={Link2} label="入口 / 原始记录" value={`${endpoints.length} / ${detail.records.length}`} />
        <Stat icon={Fingerprint} label="指纹命中" value={detail.fingerprints.length} />
        <Stat icon={GitBranch} label="关系边" value={detail.relations.length} />
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <SectionCard
            title="入口"
            description="站点按 host 归并，http / https / 非标端口都保留在这里。"
          >
            {endpoints.length === 0 ? (
              <p className="text-muted-foreground py-4 text-sm">还没有入口记录</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>协议</TableHead>
                    <TableHead>端口</TableHead>
                    <TableHead>最近状态码</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {endpoints.map((e) => (
                    <TableRow key={`${e.scheme}-${e.port}`}>
                      <TableCell className="font-mono text-sm">{e.scheme}</TableCell>
                      <TableCell className="font-mono text-sm">{e.port}</TableCell>
                      <TableCell>
                        <Badge variant={e.status_code > 0 ? 'default' : 'secondary'}>
                          {e.status_code || '—'}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </SectionCard>

          <SectionCard
            title="关系与证据"
            description="只有两侧站点都有原始记录时才建边；证据来自 relation_evidence。"
          >
            <Relations items={detail.relations} />
          </SectionCard>

          <SectionCard
            title={`原始记录（${detail.records.length}）`}
            description="每次采集的观测证据，按时间倒序，最多展示 100 条。"
          >
            <Records items={detail.records} />
          </SectionCard>
        </div>

        <div className="space-y-4">
          <SectionCard
            title="采集状态"
            description="连通性退避与人工删除保护期。"
          >
            <div className="space-y-2 text-sm">
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">首次发现</span>
                <span>{fmtDate(site.first_seen)}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">最后发现</span>
                <span>{fmtDate(site.last_seen)}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">连续失败</span>
                <span className={site.consecutive_failures > 0 ? 'text-destructive' : ''}>
                  {site.consecutive_failures} / {site.max_attempts}
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">重试阶梯</span>
                <span>第 {site.retry_step} 级</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">最近验证</span>
                <span>{fmtDate(site.verified_at)}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">下次验证</span>
                <span>{fmtDate(site.next_verification_at)}</span>
              </div>
              {site.cleanup_eligible && (
                <div className="text-destructive flex items-center gap-1 pt-1 text-xs">
                  <AlertTriangle className="size-3.5" />
                  已进入清理候选
                </div>
              )}
              {site.verification_reason && (
                <p className="text-muted-foreground border-t pt-2 text-xs">
                  {site.verification_reason}
                </p>
              )}
            </div>
          </SectionCard>

          <SectionCard title="技术栈">
            {site.technology_stack.length === 0 ? (
              <p className="text-muted-foreground py-2 text-sm">还没有识别到技术栈</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {site.technology_stack.map((t) => (
                  <Badge key={t} variant="outline">
                    {t}
                  </Badge>
                ))}
              </div>
            )}
          </SectionCard>

          <SectionCard title={`验证历史（${detail.verifications.length}）`}>
            <Verifications items={detail.verifications} />
          </SectionCard>

          <SectionCard title={`指纹命中（${detail.fingerprints.length}）`}>
            <Fingerprints items={detail.fingerprints} />
          </SectionCard>

          <SectionCard title={`变更事件（${detail.events.length}）`}>
            <Events items={detail.events} />
          </SectionCard>
        </div>
      </div>
    </div>
  )
}

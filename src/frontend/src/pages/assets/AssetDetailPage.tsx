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
import { FileSearch } from 'lucide-react'
import { Button, Card, Descriptions, Modal, Skeleton, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'

import {
  assetApi,
  type AssetEvent,
  type AssetFingerprintHit,
  type AssetRawRecord,
  type AssetRelation,
  type AssetVerification,
  type Site,
} from '@/api/assets'
import { discoveryApi } from '@/api/discovery'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate } from '@/lib/utils'
import { statusTagClass } from '@/components/ui/StatusTag'
import { CertExpiryTag, GovernanceCard } from './components/GovernanceCard'

type BadgeVariant = 'default' | 'secondary' | 'destructive' | 'outline' | 'success' | 'warning' | 'info'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass
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

const priorityVariant = (p: string): BadgeVariant => {
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

const verificationVariant = (status: string): BadgeVariant => {
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
    <Card styles={{ body: { padding: '10px 12px' } }}>
      <div className="flex items-center gap-2.5">
        <span
          className={cn(
            'flex size-8 shrink-0 items-center justify-center rounded-lg',
            tone === 'danger'
              ? 'bg-destructive/10 text-destructive'
              : tone === 'success'
                ? 'bg-emerald-500/10 text-emerald-600'
                : 'bg-primary/10 text-primary',
          )}
        >
          <Icon className="size-3.5" />
        </span>
        <div className="min-w-0">
          <div className="text-muted-foreground text-xs">{label}</div>
          <div className="truncate text-base font-semibold tabular-nums">{value}</div>
        </div>
      </div>
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
    <Card
      title={
        <div>
          <div className="text-base font-medium">{title}</div>
          {description && (
            <p className="text-muted-foreground mt-1 text-xs font-normal">{description}</p>
          )}
        </div>
      }
      extra={action}
    >
      {children}
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
              <Tag className={badgeCls(verificationVariant(v.status))}>
                {verificationLabel[v.status] ?? v.status}
              </Tag>
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
              {f.category && <Tag>{f.category}</Tag>}
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
                <Tag>{eventLabel[e.event_type] ?? e.event_type}</Tag>
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
  const [evidenceRow, setEvidenceRow] = useState<AssetRawRecord | null>(null)
  const recordColumns: TableProps<AssetRawRecord>['columns'] = [
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      render: (v: string) => <span className="text-xs">{v}</span>,
    },
    {
      title: '入口',
      dataIndex: 'value',
      key: 'value',
      ellipsis: true,
      render: (v: string) => <span className="max-w-[260px] truncate font-mono text-xs">{v}</span>,
    },
    {
      title: '状态码',
      dataIndex: 'status_code',
      key: 'status_code',
      render: (v: number) => (
        <Tag className={badgeCls(v >= 200 && v < 400 ? 'default' : 'secondary')}>{v || '—'}</Tag>
      ),
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
      render: (v: string) => <span className="max-w-[220px] truncate text-sm">{v || '—'}</span>,
    },
    {
      title: '观测时间',
      dataIndex: 'observed_at',
      key: 'observed_at',
      render: (v: string) => (
        <span className="text-muted-foreground whitespace-nowrap text-xs">{fmtDate(v)}</span>
      ),
    },
    {
      title: '操作',
      key: 'evidence',
      width: 88,
      render: (_, r) =>
        hasKeys(r.evidence) ? (
          <Button
            type="text"
            size="small"
            icon={<FileSearch className="h-3.5 w-3.5" />}
            onClick={() => setEvidenceRow(r)}
          >
            证据
          </Button>
        ) : null,
    },
  ]
  if (items.length === 0) {
    return <p className="text-muted-foreground py-4 text-sm">还没有原始记录</p>
  }
  return (
    <>
    <Table
      columns={recordColumns}
      dataSource={items}
      rowKey="id"
      pagination={false}
    />
    <Modal
      open={!!evidenceRow}
      onCancel={() => setEvidenceRow(null)}
      title={evidenceRow ? `采集证据 · ${evidenceRow.value}` : '采集证据'}
      width={560}
      centered
      footer={null}
    >
      <pre className="bg-muted/50 max-h-[60vh] overflow-auto rounded-md border p-3 font-mono text-xs whitespace-pre-wrap break-all">
        {evidenceRow ? JSON.stringify(evidenceRow.evidence, null, 2) : ''}
      </pre>
    </Modal>
    </>
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
              <Tag className={badgeCls('info')}>{relationLabel[r.type] ?? r.type}</Tag>
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

  // 资产即站点，路由 ID 直接对应 /sites/:id 的巡检接口
  const watchStatusQuery = useQuery({
    queryKey: ['site-watch-status', idNum],
    queryFn: () => discoveryApi.watchStatus(idNum),
    enabled: validId,
  })
  const watch = watchStatusQuery.data?.data

  const watchExcludeMutation = useMutation({
    mutationFn: (excluded: boolean) => discoveryApi.setWatchExcluded(idNum, excluded),
    onSuccess: () => {
      toast({ title: '巡检设置已保存' })
      queryClient.invalidateQueries({ queryKey: ['site-watch-status', idNum] })
    },
    onError: (e: any) => {
      toast({
        title: '保存巡检设置失败',
        description: e?.message || '请稍后重试',
        variant: 'destructive',
      })
    },
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
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-10">
          资产 ID 不合法
          <Link to="/assets">
            <Button size="small">返回资产列表</Button>
          </Link>
        </div>
      </Card>
    )
  }

  if (detailQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Card styles={{ body: { padding: 16 } }}>
          <Skeleton active title={false} paragraph={{ rows: 2 }} />
        </Card>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
          {Array.from({ length: 5 }).map((_, i) => (
            <Card key={i} styles={{ body: { padding: 16 } }}>
              <Skeleton active title={false} paragraph={{ rows: 1 }} />
            </Card>
          ))}
        </div>
        <Card styles={{ body: { padding: 16 } }}>
          <Skeleton active title={false} paragraph={{ rows: 8 }} />
        </Card>
      </div>
    )
  }

  const detail = detailQuery.data?.data
  if (!detail) {
    return (
      <Card>
        <div className="text-muted-foreground flex flex-col items-center gap-3 py-10">
          <AlertTriangle className="text-destructive h-8 w-8" />
          {detailQuery.isError ? '资产详情加载失败' : '资产不存在'}
          <div className="flex gap-2">
            {detailQuery.isError && (
              <Button size="small" type="primary" onClick={() => detailQuery.refetch()}>
                重试
              </Button>
            )}
            <Link to="/assets">
              <Button size="small">返回资产列表</Button>
            </Link>
          </div>
        </div>
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
          <Link to={`/assets?project_id=${site.project_id}`} aria-label="返回资产列表">
            <Button type="text" aria-label="返回资产列表" icon={<ArrowLeft className="h-5 w-5" />} />
          </Link>
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
          <Button size="small" onClick={refresh} disabled={refreshing}>
            <RefreshCw className={cn('mr-2 h-4 w-4', refreshing && 'animate-spin')} />
            刷新
          </Button>
          <Button size="small" onClick={() => probe.mutate()} disabled={probe.isPending}>
            <Radar className="mr-2 h-4 w-4" />
            真实探测
          </Button>
          {site.value && (
            <Button size="small" href={site.value} target="_blank" rel="noreferrer">
              <ExternalLink className="mr-2 h-4 w-4" />
              打开站点
            </Button>
          )}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Tag className={badgeCls(stateVariant(site.state))}>
          {stateLabel[site.state] ?? site.state}
        </Tag>
        <Tag className={badgeCls(priorityVariant(site.priority))} title={`风险评分 ${site.risk_score}`}>
          {site.priority ? site.priority.toUpperCase() : '—'} · {site.risk_score}
        </Tag>
        <Tag className={badgeCls(verificationVariant(site.verification_status))}>
          {verificationLabel[site.verification_status] ?? site.verification_status}
        </Tag>
        {endpoints.map((e) => (
          <Tag key={`${e.scheme}-${e.port}`} className="font-mono">
            {e.scheme}:{e.port}
            {e.status_code > 0 && ` · ${e.status_code}`}
          </Tag>
        ))}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <Stat icon={ShieldAlert} label="风险评分" value={`${site.risk_score} / 100`} />
        <Stat icon={Server} label="HTTP 状态" value={site.http_status || '—'} />
        <Stat icon={Link2} label="入口 / 原始记录" value={`${endpoints.length} / ${detail.records.length}`} />
        <Stat icon={Fingerprint} label="指纹命中" value={detail.fingerprints.length} />
        <Stat icon={GitBranch} label="关系边" value={detail.relations.length} />
      </div>

      {site.icp && (
        <div className="rounded-md border bg-muted/40 px-3 py-2 text-sm">
          <span className="text-muted-foreground">ICP 备案：</span>
          <span className="font-mono">{site.icp}</span>
          {site.icp_seen_at && (
            <span className="ml-2 text-xs text-muted-foreground">
              提取于 {site.icp_seen_at.slice(0, 10)}
            </span>
          )}
        </div>
      )}

      {site.cert_not_after && (
        <div className="flex items-center gap-2">
          <CertExpiryTag notAfter={site.cert_not_after} />
        </div>
      )}

      <SectionCard title="治理" description="星标 / 标签 / 备注：人工运营字段，扫描流程不会改动。">
        <GovernanceCard key={site.id} site={site} />
      </SectionCard>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <SectionCard
            title="入口"
            description="站点按 host 归并，http / https / 非标端口都保留在这里。"
          >
            {endpoints.length === 0 ? (
              <p className="text-muted-foreground py-4 text-sm">还没有入口记录</p>
            ) : (
              <Table
                columns={[
                  {
                    title: '协议',
                    dataIndex: 'scheme',
                    key: 'scheme',
                    render: (v: string) => <span className="font-mono text-sm">{v}</span>,
                  },
                  {
                    title: '端口',
                    dataIndex: 'port',
                    key: 'port',
                    render: (v: number) => <span className="font-mono text-sm">{v}</span>,
                  },
                  {
                    title: '最近状态码',
                    dataIndex: 'status_code',
                    key: 'status_code',
                    render: (v: number) => (
                      <Tag className={badgeCls(v > 0 ? 'default' : 'secondary')}>{v || '—'}</Tag>
                    ),
                  },
                ]}
                dataSource={endpoints}
                rowKey={(e) => `${e.scheme}-${e.port}`}
                pagination={false}
              />
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
            <Descriptions
              column={1}
              size="small"
              className="text-sm"
              items={[
                { key: 'first_seen', label: '首次发现', children: fmtDate(site.first_seen) },
                { key: 'last_seen', label: '最后发现', children: fmtDate(site.last_seen) },
                {
                  key: 'failures',
                  label: '连续失败',
                  children: (
                    <span className={site.consecutive_failures > 0 ? 'text-destructive' : ''}>
                      {site.consecutive_failures} / {site.max_attempts}
                    </span>
                  ),
                },
                { key: 'retry_step', label: '重试阶梯', children: `第 ${site.retry_step} 级` },
                { key: 'verified_at', label: '最近验证', children: fmtDate(site.verified_at) },
                {
                  key: 'next_verification_at',
                  label: '下次验证',
                  children: fmtDate(site.next_verification_at),
                },
              ]}
            />
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
          </SectionCard>

          <SectionCard
            title="内容巡检"
            description="巡航时抓取页面并比对内容指纹，用于发现挂马、黑页与改版。"
          >
            {watchStatusQuery.isLoading ? (
              <Skeleton active title={false} paragraph={{ rows: 2 }} />
            ) : !watch ? (
              <p className="text-muted-foreground py-2 text-sm">暂时拿不到巡检状态</p>
            ) : (
              <>
                <Descriptions
                  column={1}
                  size="small"
                  className="text-sm"
                  items={[
                    { key: 'checked', label: '上次检查', children: fmtDate(watch.content_checked_at) },
                    { key: 'changed', label: '最近变更', children: fmtDate(watch.content_changed_at) },
                  ]}
                />
                <div className="flex items-start justify-between gap-3 border-t pt-3">
                  <div>
                    <div className="text-sm font-medium">免巡检</div>
                    <p className="text-muted-foreground mt-1 text-xs">
                      打开后巡航跳过此站点的内容比对，适合登录页、无意义页面。
                    </p>
                  </div>
                  <Switch
                    checked={watch.watch_excluded}
                    loading={watchExcludeMutation.isPending}
                    onChange={(checked) => watchExcludeMutation.mutate(checked)}
                  />
                </div>
              </>
            )}
          </SectionCard>

          <SectionCard title="技术栈">
            {site.technology_stack.length === 0 ? (
              <p className="text-muted-foreground py-2 text-sm">还没有识别到技术栈</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {site.technology_stack.map((t) => (
                  <Tag key={t}>{t}</Tag>
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

import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Checkbox, Drawer, Table, Tag } from 'antd'
import { Star } from 'lucide-react'
import { assetApi, type Site } from '@/api/assets'
import { formatDate } from '@/lib/utils'
import { statusTagClass, type BadgeVariant } from '@/components/ui/StatusTag'
import { CertExpiryTag } from './GovernanceCard'

export type DrawerTab = 'overview' | 'endpoints' | 'records' | 'fingerprints' | 'verifications'

export const stateLabel: Record<string, string> = {
  reachable: '可访问',
  lost: '失联',
  archived: '已归档',
  pending: '待验证',
}

// 从 AssetsPage 迁出的详情抽屉:站点档案(入口/原始记录/指纹/验证)。
// 自持详情与原始记录分页查询;页签受控于父级——展开行的「查看全部记录」
// 会直接以 records 页签打开。
export default function AssetDetailDrawer({
  site,
  tab,
  onTabChange,
  onClose,
  onOpenFullPage,
}: {
  site: Site
  tab: DrawerTab
  onTabChange: (t: DrawerTab) => void
  onClose: () => void
  onOpenFullPage: (id: number) => void
}) {
  const [recordsCursorStack, setRecordsCursorStack] = useState<Array<string | undefined>>([undefined])
  const [recordsInterfaceOnly, setRecordsInterfaceOnly] = useState(false)
  const recordsCursor = recordsCursorStack[recordsCursorStack.length - 1]

  useEffect(() => {
    setRecordsCursorStack([undefined])
    setRecordsInterfaceOnly(false)
  }, [site?.id])

  const detailQuery = useQuery({
    queryKey: ['asset-detail', site?.id],
    queryFn: () => assetApi.detail(site!.id),
    enabled: !!site,
    staleTime: 30_000,
  })
  const detail = detailQuery.data?.data
  const recordsQuery = useQuery({
    queryKey: ['asset-records', site?.id, recordsCursor, recordsInterfaceOnly],
    queryFn: () =>
      assetApi.records(site!.id, {
        cursor: recordsCursor ?? '',
        limit: 50,
        ...(recordsInterfaceOnly ? { interface: 1 as const } : {}),
      }),
    enabled: !!site && tab === 'records',
    staleTime: 30_000,
  })
  const recordsPage = recordsQuery.data?.data
  const records = recordsPage?.items ?? []

  const stateVariant = (state: string): BadgeVariant => {
    if (state === 'reachable') return 'default'
    if (state === 'lost') return 'destructive'
    if (state === 'archived') return 'outline'
    return 'secondary'
  }

  return (
    <Drawer
      open={!!site}
      onClose={onClose}
      width={460}
      // antd Drawer 自带遮罩/ESC/焦点管理,替代手写面板——此前大屏遮罩被
      // xl:hidden 隐藏,点外部关不掉,只能找右上角 X
      title={
        site && (
          <div className="min-w-0">
            <div className="truncate font-mono text-sm font-semibold">
              {site.value || site.host}
            </div>
            <div className="mt-1 flex items-center gap-2 text-xs text-muted-foreground">
              <Tag className={statusTagClass(stateVariant(site.state))}>
                {stateLabel[site.state] ?? site.state}
              </Tag>
              {site.starred && <Star className="h-3.5 w-3.5 fill-amber-400 text-amber-400" aria-label="已星标" />}
              {site.cert_not_after && <CertExpiryTag notAfter={site.cert_not_after} />}
              <span>{site.project_name}</span>
              <span>·</span>
              <span className="tabular-nums">P{site.priority?.replace(/^p/i, '') || '—'} · {site.risk_score}</span>
            </div>
          </div>
        )
      }
      styles={{ body: { padding: 16, display: 'flex', flexDirection: 'column', overflow: 'hidden' } }}
    >
      <div className="flex gap-1 overflow-x-auto border-b px-1 pb-2">
        {([
          ['overview', '概览'],
          ['endpoints', '入口'],
          ['records', '原始记录'],
          ['fingerprints', '指纹'],
          ['verifications', '验证'],
        ] as const).map(([id, label]) => (
          <button
            key={id}
            type="button"
            onClick={() => onTabChange(id)}
            className={
              'shrink-0 rounded-sm px-2.5 py-1.5 text-[13px] transition-colors ' +
              (tab === id
                ? 'bg-foreground text-background'
                : 'text-muted-foreground hover:bg-muted')
            }
          >
            {label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {detailQuery.isLoading ? (
          <div className="py-10 text-center text-sm text-muted-foreground">加载资产档案…</div>
        ) : !detail ? (
          <div className="py-10 text-center text-sm text-muted-foreground">详情加载失败</div>
        ) : (
          <>
            {tab === 'overview' && (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-2">
                  {[
                    ['入口', site.endpoint_count ?? 0],
                    ['原始记录', site.record_count ?? 0],
                    ['指纹命中', site.fingerprint_count ?? 0],
                    ['验证记录', detail.verifications.length],
                  ].map(([label, value]) => (
                    <div key={String(label)} className="rounded-md border px-3 py-2">
                      <div className="text-xs text-muted-foreground">{label}</div>
                      <div className="mt-1 text-xl font-semibold tabular-nums">{value}</div>
                    </div>
                  ))}
                </div>
                <div className="divide-y text-sm">
                  {[
                    ['状态', stateLabel[site.state] ?? site.state],
                    ['标题', site.title || '—'],
                    ['IP', site.ip || '—'],
                    ['协议 / 端口', `${site.protocol}:${site.port}`],
                    ['首次发现', formatDate(site.first_seen)],
                    ['最近发现', formatDate(site.last_record_at || site.last_seen)],
                    ...((site.tags?.length ?? 0) > 0 ? [['标签', site.tags!.join(' / ')]] : []),
                    ...((site.note ?? '') ? [['备注', site.note]] : []),
                  ].map(([label, value]) => (
                    <div key={label} className="flex items-start justify-between gap-3 py-2">
                      <span className="shrink-0 text-muted-foreground">{label}</span>
                      <span className="min-w-0 break-all text-right">{value}</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="mb-1.5 text-xs text-muted-foreground">技术栈</div>
                  <div className="flex flex-wrap gap-1.5">
                    {(site.technology_stack ?? []).length === 0 ? (
                      <span className="text-sm text-muted-foreground">—</span>
                    ) : site.technology_stack.map((t) => (
                      <Tag key={t} className={`${statusTagClass('secondary')} text-xs`}>{t}</Tag>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {tab === 'endpoints' && (
              <div className="space-y-2">
                {(site.endpoints ?? []).length === 0 ? (
                  <p className="text-sm text-muted-foreground">暂无入口。</p>
                ) : site.endpoints.map((e) => (
                  <div key={`${e.scheme}-${e.port}`} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                    <span className="font-mono">{e.scheme}:{e.port}</span>
                    <Tag className={statusTagClass(e.status_code >= 200 && e.status_code < 400 ? 'default' : 'secondary')}>
                      {e.status_code || '—'}
                    </Tag>
                  </div>
                ))}
              </div>
            )}

            {tab === 'records' && (
              <div className="space-y-3">
                <span className="flex items-center gap-2 text-[13px] text-muted-foreground">
                  <Checkbox
                    checked={recordsInterfaceOnly}
                    onChange={(e) => {
                      setRecordsInterfaceOnly(e.target.checked)
                      setRecordsCursorStack([undefined])
                    }}
                  >
                    只看接口
                  </Checkbox>
                </span>
                {recordsQuery.isLoading ? (
                  <p className="text-sm text-muted-foreground">加载原始记录…</p>
                ) : records.length === 0 ? (
                  <p className="text-sm text-muted-foreground">暂无原始记录。</p>
                ) : (
                  <div className="rounded-md border">
                    <Table
                      size="small"
                      pagination={false}
                      rowKey={(r) => String(r.id)}
                      dataSource={records}
                      columns={[
                        {
                          title: '记录',
                          render: (_, r) => (
                            <div className="max-w-[270px] break-all font-mono text-xs">
                              <div className="flex items-start gap-1">
                                <span>{r.value}</span>
                                {r.is_interface && (
                                  <Tag className={`${statusTagClass('outline')} shrink-0 text-[10px]`}>接口</Tag>
                                )}
                              </div>
                              <div className="mt-0.5 text-[11px] text-muted-foreground">
                                {formatDate(r.observed_at)}
                              </div>
                            </div>
                          ),
                        },
                        {
                          title: '来源',
                          width: 54,
                          render: (_, r) => (
                            <div className="text-xs text-muted-foreground">
                              <div>{r.source}</div>
                              <div>{r.method || 'GET'}</div>
                            </div>
                          ),
                        },
                        {
                          title: '状态',
                          width: 54,
                          align: 'right',
                          render: (_, r) => <span className="text-xs tabular-nums">{r.status_code || '—'}</span>,
                        },
                      ]}
                    />
                  </div>
                )}
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>已加载 {records.length} 条</span>
                  <div className="flex gap-1">
                    <Button
                      size="small"
                      disabled={recordsCursorStack.length <= 1}
                      onClick={() => setRecordsCursorStack((stack) => stack.slice(0, -1))}
                    >
                      上一页
                    </Button>
                    <Button
                      size="small"
                      disabled={!recordsPage?.has_more || !recordsPage?.next_cursor}
                      onClick={() => setRecordsCursorStack((stack) => [...stack, recordsPage?.next_cursor])}
                    >
                      下一页
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {tab === 'fingerprints' && (
              <div className="space-y-2">
                {detail.fingerprints.length === 0 ? (
                  <p className="text-sm text-muted-foreground">暂无指纹命中。</p>
                ) : detail.fingerprints.map((f) => (
                  <div key={`${f.rule_id}-${f.observed_at}`} className="rounded-md border px-3 py-2 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium">{f.rule_name || f.rule_id}</span>
                      <span className="text-xs text-muted-foreground">{formatDate(f.observed_at)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {tab === 'verifications' && (
              <div className="space-y-2">
                {detail.verifications.length === 0 ? (
                  <p className="text-sm text-muted-foreground">暂无验证记录。</p>
                ) : detail.verifications.map((v) => (
                  <div key={v.id} className="rounded-md border px-3 py-2 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <Tag className={statusTagClass(v.status === 'reachable' ? 'success' : 'secondary')}>{v.status}</Tag>
                      <span className="text-xs text-muted-foreground">{formatDate(v.observed_at)}</span>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      状态码 {v.http_status || '—'} · 尝试 {v.attempts || 0}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      <div className="border-t p-3">
        <Button
          type="primary"
          className="w-full"
          onClick={() => {
            onClose()
            onOpenFullPage(site.id)
          }}
        >
          打开完整详情页
        </Button>
      </div>
    </Drawer>
  )
}

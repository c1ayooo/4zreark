import { useMemo, useState, type ReactNode } from 'react'
import {keepPreviousData, useMutation, useQuery, useQueryClient} from '@tanstack/react-query'
import { intelApi, IntelItem } from '@/api/intel'
import { Button, Card, Input, Modal, Pagination, Select, Skeleton, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, getSeverityColor } from '@/lib/utils'
import {
  RefreshCw,
  Search,
  ExternalLink,
  Github,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Shield,
  Bug,
  Sparkles,
  Loader2,
} from 'lucide-react'

const SEVERITY_LABEL: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const SEVERITY_ACCENT: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-blue-500',
  info: 'text-muted-foreground',
}

export default function IntelPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [severity, setSeverity] = useState('all')
  const [sourceName, setSourceName] = useState('all')
  const [keyword, setKeyword] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [selected, setSelected] = useState<IntelItem | null>(null)

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['intel', page, severity, sourceName, keyword],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      intelApi.list({
        page,
        pageSize,
        severity: severity === 'all' ? undefined : severity,
        source_name: sourceName === 'all' ? undefined : sourceName,
        q: keyword || undefined,
      }),
  })

  const { data: stats } = useQuery({
    queryKey: ['intel-stats'],
    queryFn: () => intelApi.stats(),
  })

  const { data: enrichment } = useQuery({
    queryKey: ['enrichment-status'],
    queryFn: () => intelApi.enrichmentStatus(),
  })

  const items = data?.items || []
  const total = data?.total || 0

  const sources = stats?.by_source || []

  const severityCounts = useMemo(() => {
    const out: Record<string, number> = {}
    for (const s of stats?.by_severity || []) out[s.severity] = s.count
    return out
  }, [stats])

  const enrich = useMutation({
    mutationFn: (key: string) => intelApi.enrich(key),
    onSuccess: (res, key) => {
      toast({
        title: '富化完成',
        description: `可用 PoC ${res.poc_count} 个，CVSS ${res.cvss_score || '-'}`,
      })
      queryClient.invalidateQueries({ queryKey: ['intel'] })
      queryClient.invalidateQueries({ queryKey: ['intel-stats'] })
      setSelected((prev) =>
        prev && prev.unique_key === key
          ? { ...prev, enriched_at: new Date().toISOString(), has_poc: res.poc_count > 0 }
          : prev
      )
    },
    onError: (err: unknown) => {
      const msg =
        (err as { message?: string })?.message ||
        (err as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        '富化失败'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const poll = useMutation({
    mutationFn: () => intelApi.triggerPoll(),
    onSuccess: (res) => {
      toast({
        title: '轮询完成',
        description: `新增 ${res.new}，更新 ${res.updated}，失败 ${res.failed}/${res.sources}`,
      })
      queryClient.invalidateQueries({ queryKey: ['intel'] })
      queryClient.invalidateQueries({ queryKey: ['intel-stats'] })
    },
    onError: (err: unknown) => {
      const msg = (err as { message?: string })?.message || '轮询失败'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const statCards: Array<{
    key: string
    label: string
    icon: typeof Bug
    count: number
    hint?: string
  }> = [
    { key: 'total', label: '情报总量', icon: Bug, count: stats?.total || 0, hint: '来自 9 个公开源' },
    { key: 'critical', label: '严重', icon: ShieldX, count: severityCounts.critical || 0 },
    { key: 'high', label: '高危', icon: ShieldAlert, count: severityCounts.high || 0 },
    { key: 'medium', label: '中危', icon: Shield, count: severityCounts.medium || 0 },
    {
      key: 'enriched',
      label: '已富化',
      icon: Github,
      count: enrichment?.enriched || 0,
      hint: `PoC ${enrichment?.poc_total || 0} 个 / lab_only ${enrichment?.lab_only || 0}`,
    },
  ]

  const columns: TableProps<IntelItem>['columns'] = [
    {
      title: '等级',
      dataIndex: 'severity',
      key: 'severity',
      width: 110,
      render: (v: string) => (
        <Tag className={cn('font-normal', getSeverityColor(v))}>
          {SEVERITY_LABEL[v] || v}
        </Tag>
      ),
    },
    {
      title: '标题',
      dataIndex: 'title',
      key: 'title',
      ellipsis: true,
      render: (v: string, item) => (
        <button
          type="button"
          onClick={() => setSelected(item)}
          className="text-left font-medium hover:underline line-clamp-1"
          title={v}
        >
          {v}
        </button>
      ),
    },
    {
      title: 'CVE',
      dataIndex: 'cve',
      key: 'cve',
      width: 150,
      render: (v: string) => (
        <span className="font-mono text-xs text-muted-foreground">{v || '—'}</span>
      ),
    },
    {
      title: '来源',
      key: 'source',
      width: 130,
      render: (_, item) => (
        <span className="text-sm text-muted-foreground">
          {item.source_name || item.source || '—'}
        </span>
      ),
    },
    {
      title: '披露时间',
      key: 'disclosure',
      width: 150,
      render: (_, item) => (
        <span className="text-sm text-muted-foreground">
          {item.disclosure || (item.created_at ? formatDate(item.created_at) : '—')}
        </span>
      ),
    },
    {
      title: 'PoC',
      dataIndex: 'has_poc',
      key: 'has_poc',
      width: 90,
      render: (v: boolean, item) =>
        v ? (
          <Tag className="border-transparent bg-primary font-normal text-primary-foreground">
            {item.github_poc?.length || 0} 个
          </Tag>
        ) : item.enriched_at ? (
          <span className="text-xs text-muted-foreground">无</span>
        ) : (
          <span className="text-xs text-muted-foreground">未查</span>
        ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      align: 'right',
      render: (_, item) => (
        <Button
          type="text"
          size="small"
          disabled={!item.cve || enrich.isPending}
          onClick={() => enrich.mutate(item.unique_key)}
          title={item.cve ? '检索 GitHub PoC 并分诊' : '没有 CVE 编号，无法检索'}
          icon={
            enrich.isPending && enrich.variables === item.unique_key ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Github className="h-4 w-4" />
            )
          }
        />
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">漏洞情报</h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()} disabled={isFetching}>
            <RefreshCw className={cn('h-4 w-4 mr-2', isFetching && 'animate-spin')} />
            刷新
          </Button>
          <Button
            type="primary"
            size="small"
            onClick={() => poll.mutate()}
            disabled={poll.isPending}
          >
            {poll.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Sparkles className="h-4 w-4 mr-2" />
            )}
            {poll.isPending ? '轮询中…' : '立即轮询'}
          </Button>
        </div>
      </div>

      {/* 概览卡片：与仪表盘同一套中性卡片，只保留一个低饱和度的图标着色 */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        {statCards.map((item) => {
          const Icon = item.icon
          return (
            <Card key={item.key} styles={{ body: { paddingTop: 12, paddingBottom: 12 } }}>
              <div className="flex items-center justify-between pb-2">
                <span className="text-sm font-medium">{item.label}</span>
                <Icon
                  className={cn(
                    'h-4 w-4',
                    SEVERITY_ACCENT[item.key] || 'text-muted-foreground'
                  )}
                />
              </div>
              <div className="text-2xl font-bold">{item.count}</div>
              <p className="text-xs text-muted-foreground">
                {item.hint ?? '占比 ' + percent(item.count, stats?.total || 0) + '%'}
              </p>
            </Card>
          )
        })}
      </div>

      {/* 筛选 */}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          className="min-w-[220px] flex-1"
          placeholder="搜索标题 / 描述，回车确认"
          prefix={<Search className="h-4 w-4 text-muted-foreground" />}
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              setKeyword(searchInput.trim())
              setPage(1)
            }
          }}
        />
        <Select
          className="w-[140px]"
          placeholder="严重度"
          value={severity}
          onChange={(v) => {
            setSeverity(v)
            setPage(1)
          }}
          options={[
            { value: 'all', label: '全部等级' },
            { value: 'critical', label: '严重' },
            { value: 'high', label: '高危' },
            { value: 'medium', label: '中危' },
            { value: 'low', label: '低危' },
            { value: 'info', label: '信息' },
          ]}
        />
        <Select
          className="w-[180px]"
          placeholder="来源"
          value={sourceName}
          onChange={(v) => {
            setSourceName(v)
            setPage(1)
          }}
          options={[
            { value: 'all', label: '全部来源' },
            ...sources.map((s) => ({ value: s.source_name, label: s.source_name })),
          ]}
        />
      </div>

      {/* 列表 */}
      <Card styles={{ body: { padding: 0 } }}>
        {isLoading ? (
          <div className="p-6">
            <Skeleton loading active paragraph={{ rows: 8 }} />
          </div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center text-muted-foreground">
            <ShieldCheck className="h-10 w-10 mx-auto mb-3 opacity-40" />
            <p>没有匹配的情报</p>
            <p className="text-xs mt-1">
              点「立即轮询」从 9 个公开源拉取；采集器默认只收中危及以上
            </p>
          </div>
        ) : (
          <Table<IntelItem>
            columns={columns}
            dataSource={items}
            rowKey="unique_key"
            pagination={false}
          />
        )}
      </Card>

      {total > pageSize && (
        <Pagination
          current={page}
          pageSize={pageSize}
          total={total}
          showQuickJumper
          // page_size 固定 20、无独立 pageSize 状态，不展示切换器
          showSizeChanger={false}
          onChange={(p) => setPage(p)}
        />
      )}

      <IntelDetailDialog
        item={selected}
        onClose={() => setSelected(null)}
        onEnrich={(key) => enrich.mutate(key)}
        enriching={enrich.isPending && enrich.variables === selected?.unique_key}
      />
    </div>
  )
}

function percent(part: number, total: number): string {
  if (!total) return '0'
  return Math.round((part / total) * 100).toString()
}

function IntelDetailDialog({
  item,
  onClose,
  onEnrich,
  enriching,
}: {
  item: IntelItem | null
  onClose: () => void
  onEnrich: (key: string) => void
  enriching: boolean
}) {
  if (!item) return null
  return (
    <Modal
      open={!!item}
      onCancel={() => onClose()}
      width={768}
      footer={null}
      title={<span className="pr-8 leading-snug">{item.title}</span>}
    >
      <div className="max-h-[85vh] space-y-5 overflow-y-auto">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Tag className={cn('font-normal', getSeverityColor(item.severity))}>
            {SEVERITY_LABEL[item.severity] || item.severity}
          </Tag>
          {item.cve && <Tag className="font-mono">{item.cve}</Tag>}
          <span className="text-muted-foreground">{item.source_name || item.source}</span>
          {item.disclosure && (
            <span className="text-muted-foreground">披露 {item.disclosure}</span>
          )}
          {item.source_url && (
            <a
              href={item.source_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-primary hover:underline"
            >
              原文 <ExternalLink className="h-3 w-3" />
            </a>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <DetailBlock label="CVSS" value={item.cvss_score ? item.cvss_score.toFixed(1) : '—'} />
          <DetailBlock
            label="CWE"
            value={item.cwes && item.cwes.length ? item.cwes.map((c) => `CWE-${c}`).join(', ') : '—'}
          />
          <DetailBlock
            label="富化状态"
            value={item.enriched_at ? (item.lab_only ? '已查（仅实验环境）' : '已查') : '未查'}
          />
        </div>

        {item.affected && item.affected.length > 0 && (
          <Section title="影响组件">
            <div className="flex flex-wrap gap-1.5">
              {item.affected.map((a) => (
                <Tag key={a} className="bg-secondary font-mono text-xs font-normal text-secondary-foreground">
                  {a}
                </Tag>
              ))}
            </div>
          </Section>
        )}

        {item.description && (
          <Section title="漏洞描述">
            <p className="text-sm text-muted-foreground whitespace-pre-wrap line-clamp-[12]">
              {item.description}
            </p>
          </Section>
        )}

        {item.solutions && (
          <Section title="修复建议">
            <p className="text-sm text-muted-foreground whitespace-pre-wrap line-clamp-[12]">
              {item.solutions}
            </p>
          </Section>
        )}

        <Section title="GitHub PoC">
          {item.github_poc && item.github_poc.length > 0 ? (
            <div className="space-y-2">
              {item.github_poc.map((p) => (
                <div
                  key={p.full_name}
                  className="flex items-center justify-between rounded-md border px-3 py-2"
                >
                  <div className="min-w-0">
                    <a
                      href={p.url}
                      target="_blank"
                      rel="noreferrer"
                      className="text-sm font-medium hover:underline"
                    >
                      {p.full_name}
                    </a>
                    <div className="text-xs text-muted-foreground">
                      ★ {p.stars} · 分诊 {p.verdict}（{p.triage_score}）
                    </div>
                  </div>
                  <ExternalLink className="h-4 w-4 text-muted-foreground shrink-0" />
                </div>
              ))}
            </div>
          ) : (
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <span>{item.enriched_at ? '未找到通过分诊的公开 PoC' : '尚未检索'}</span>
              <Button
                size="small"
                disabled={!item.cve || enriching}
                onClick={() => onEnrich(item.unique_key)}
              >
                {enriching ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
                ) : (
                  <Github className="h-3.5 w-3.5 mr-1" />
                )}
                检索 PoC
              </Button>
            </div>
          )}
        </Section>

        {item.references && item.references.length > 0 && (
          <Section title="参考链接">
            <ul className="space-y-1">
              {item.references.slice(0, 10).map((r) => (
                <li key={r}>
                  <a
                    href={r}
                    target="_blank"
                    rel="noreferrer"
                    className="text-sm text-primary hover:underline break-all"
                  >
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </div>
    </Modal>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-semibold">{title}</h4>
      {children}
    </div>
  )
}

function DetailBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border px-3 py-2">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-sm font-medium mt-0.5">{value}</div>
    </div>
  )
}

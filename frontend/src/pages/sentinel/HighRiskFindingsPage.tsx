/**
 * 哨兵 · 高危漏洞工作台
 *
 * 只收 severity ∈ {high, critical} 的发现，视角是「验证与产物」：
 *   - 列表直接展示验证产物状态（python-poc / nuclei / poc-verify）；
 *   - 行展开即方案 B 验证卡（环境事实 + 时间线 + verdict 横幅），不跳页；
 *   - 「判定依据」跳分析结果页（那是判定视角：reasoning + hunk 证据）。
 *
 * 真实接口：
 *   GET /api/sentinel/findings/summary              → 统计卡
 *   GET /api/sentinel/findings?min_severity=high&…  → 列表（含产物摘要）
 */
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Table, Tooltip } from 'antd'
import type { TableProps } from 'antd'
import { CheckCircle2, Flame, ListChecks, ShieldCheck } from 'lucide-react'
import { sentinelApi, type SentinelArtifactStatus, type SentinelFinding } from '@/api/sentinel'
import PocVerifyCard from './audit/PocVerifyCard'
import JudgmentBasisCard from './audit/JudgmentBasisCard'
import { PageHeader, SeverityTag, VulnClassTag, FindingGradeTag, FindingStatusTag, fmtNumber, fmtTime } from './audit/shared'

type ArtifactSummary = NonNullable<SentinelFinding['artifacts']>[number]

/** 产物状态 → 徽标样式（verified 绿 / draft 橙 / 其他灰） */
function artifactBadge(a: ArtifactSummary) {
  const style: Record<SentinelArtifactStatus | string, string> = {
    verified: 'border-[#b7eb8f] bg-accent text-primary',
    draft: 'border-[#ffe58f] bg-[#fffbe6] text-[#d48806]',
    pending_review: 'border-[#ffe58f] bg-[#fffbe6] text-[#d48806]',
    rejected: 'border-border bg-muted text-muted-foreground',
    deprecated: 'border-border bg-muted text-muted-foreground line-through',
  }
  return style[a.status] ?? 'border-border bg-muted text-muted-foreground'
}

/** 三类验证产物的展示定义：label + 匹配规则（与后端生成端约定一致） */
const TRACKED_ARTIFACTS: { key: string; label: string; match: (a: ArtifactSummary) => boolean; hint: string }[] = [
  {
    key: 'python-poc',
    label: 'python-poc',
    match: (a) => a.kind === 'poc' && a.title === 'python-poc',
    hint: 'Python 验证脚本：verified 后自动入队靶场验证',
  },
  {
    key: 'nuclei',
    label: 'nuclei',
    match: (a) => a.kind === 'nuclei',
    hint: 'nuclei 模板草稿：verified 后可发布 PoC 库',
  },
  {
    key: 'poc-verify',
    label: 'poc-verify',
    match: (a) => a.kind === 'repro_log' && a.title === 'poc-verify',
    hint: '靶场验证结论产物（机器生成，verified）',
  },
]

function ArtifactCell({ finding }: { finding: SentinelFinding }) {
  const arts = finding.artifacts ?? []
  if (!arts.length) {
    return <span className="text-[11px] text-muted-foreground">产物链生成中…</span>
  }
  return (
    <div className="flex flex-wrap gap-1">
      {TRACKED_ARTIFACTS.map((t) => {
        const a = arts.find(t.match)
        if (!a) return <span key={t.key} className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground/60">{t.label} 无</span>
        return (
          <Tooltip key={t.key} title={`${t.hint} · 状态 ${a.status}`}>
            <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${artifactBadge(a)}`}>
              {t.label} {a.status}
            </span>
          </Tooltip>
        )
      })}
    </div>
  )
}

export default function HighRiskFindingsPage() {
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)
  const [expandedKeys, setExpandedKeys] = useState<readonly React.Key[]>([])

  const summaryQuery = useQuery({
    queryKey: ['sentinel', 'findings-summary'],
    queryFn: () => sentinelApi.findingsSummary(),
    refetchInterval: 30_000,
  })
  const sum = summaryQuery.data

  const findingsQuery = useQuery({
    queryKey: ['sentinel', 'findings', { min_severity: 'high', page, size }],
    queryFn: () => sentinelApi.findings({ min_severity: 'high', page, size }),
    refetchInterval: 30_000,
  })
  const items = findingsQuery.data?.list ?? []
  const total = findingsQuery.data?.total ?? 0

  const cards = useMemo(
    () => [
      { key: 'high', title: '高危发现', value: sum?.high_risk, icon: Flame, hint: 'severity ∈ {high, critical}', tone: 'text-destructive' },
      { key: 'verified', title: '已机器验证', value: sum?.verified, icon: ShieldCheck, hint: '靶场验证 / 差分复现通过', tone: 'text-primary' },
      { key: 'pending', title: '待验证', value: sum?.pending_poc, icon: ListChecks, hint: '尚未机器确认（产物链进行中）', tone: 'text-orange-500' },
      { key: 'confirmed', title: '人工确认', value: sum?.confirmed, icon: CheckCircle2, hint: 'status = confirmed', tone: 'text-blue-500' },
    ],
    [sum],
  )

  const columns: TableProps<SentinelFinding>['columns'] = [
    {
      title: '发现',
      dataIndex: 'title',
      ellipsis: true,
      render: (_, row) => (
        <div className="space-y-0.5">
          <div className="text-[13px] font-medium">{row.title}</div>
          <div className="font-mono text-[10.5px] text-muted-foreground">
            {row.repo_full_name} · {row.sha.slice(0, 8)} · {fmtTime(row.created_at)}
          </div>
        </div>
      ),
    },
    {
      title: '类别',
      dataIndex: 'vuln_class',
      width: 110,
      render: (v: string) => <VulnClassTag vulnClass={v} />,
    },
    {
      title: '严重度',
      dataIndex: 'severity',
      width: 95,
      render: (v: string) => <SeverityTag severity={v} />,
    },
    {
      title: '评级',
      dataIndex: 'grade',
      width: 65,
      render: (v: string) => <FindingGradeTag grade={v ?? ''} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 95,
      render: (v: string) => <FindingStatusTag status={v} />,
    },
    {
      title: '验证产物',
      dataIndex: 'artifacts',
      width: 280,
      render: (_, row) => <ArtifactCell finding={row} />,
    },
    {
      title: '机器验证',
      dataIndex: 'verified_at',
      width: 110,
      render: (v: string | null) =>
        v ? (
          <span
            className="inline-flex items-center gap-1 rounded border border-[#b7eb8f] bg-accent px-1.5 py-0.5 text-[11px] text-primary"
            title={`verified_by 靶场验证/差分复现 · ${fmtTime(v)}`}
          >
            <ShieldCheck size={11} />
            通过
          </span>
        ) : (
          <span className="text-[11px] text-muted-foreground">验证链进行中</span>
        ),
    },
    {
      title: '',
      key: 'op',
      width: 96,
      render: (_, row) => (
        <span
          className="cursor-pointer text-[12px] text-primary hover:underline"
          title="展开查看判定依据与靶场验证卡"
          onClick={(e) => {
            e.stopPropagation()
            const key = expandedKeys.includes(row.id) ? expandedKeys.filter((k) => k !== row.id) : [...expandedKeys, row.id]
            setExpandedKeys(key)
          }}
        >
          查看依据
        </span>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="高危漏洞"
        desc="验证视角：只收 severity ∈ {high, critical} 的发现，验证产物（python-poc / nuclei / poc-verify）状态直接在列，行展开即靶场验证卡（AI 选靶场 → 隔离内网 → PoC 三态判定）。判定依据（reasoning / hunk 证据）在「分析结果」页。"
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {cards.map((c) => (
          <div key={c.key} className="rounded-2xl border border-border bg-card px-5 py-4">
            <div className="mb-1 flex items-center gap-2 text-[12px] text-muted-foreground">
              <c.icon size={14} className={c.tone} />
              {c.title}
            </div>
            <div className="text-2xl font-bold tracking-tight">{fmtNumber(c.value)}</div>
            <div className="mt-0.5 text-[10.5px] text-muted-foreground/80">{c.hint}</div>
          </div>
        ))}
      </div>

      <Table<SentinelFinding>
        rowKey="id"
        size="small"
        loading={findingsQuery.isLoading}
        columns={columns}
        dataSource={items}
        expandable={{
          /** 行展开 = 判定依据卡 + 方案 B 靶场验证卡：不跳页，原地看「凭什么判」与「验证结论」并触发验证 */
          expandedRowRender: (r) => (
            <div className="space-y-3 py-1">
              <JudgmentBasisCard commitId={r.commit_id} finding={r} />
              <PocVerifyCard findingId={r.id} />
            </div>
          ),
          rowExpandable: () => true,
          expandedRowKeys: expandedKeys,
          onExpandedRowsChange: (keys) => setExpandedKeys(keys),
        }}
        pagination={{
          current: page,
          pageSize: size,
          total,
          showSizeChanger: true,
          showTotal: (t) => `共 ${fmtNumber(t)} 条高危发现`,
          onChange: (p, s) => {
            setPage(p)
            setSize(s)
          },
        }}
      />
    </div>
  )
}

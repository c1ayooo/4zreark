/**
 * 哨兵 · 高危漏洞工作台
 *
 * 与「提交 / 分析结果」平级的一级入口：只看 severity ∈ {high, critical} 的发现，
 * 把验证进度（python-poc → 靶场验证 → 机器确认）做成首屏卡片。
 * 行点击跳「分析结果」并自动打开对应提交详情（?commit=）。
 *
 * 真实接口：
 *   GET /api/sentinel/findings/summary        → 统计卡
 *   GET /api/sentinel/findings?min_severity=high&…  → 列表
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { CheckCircle2, FileSearch, Flame, ListChecks, ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { sentinelApi, type SentinelFinding } from '@/api/sentinel'
import { PageHeader, SeverityTag, VulnClassTag, FindingGradeTag, FindingStatusTag, fmtNumber, fmtTime } from './audit/shared'

export default function HighRiskFindingsPage() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [size, setSize] = useState(20)

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

  const cards = [
    { key: 'high', title: '高危发现', value: sum?.high_risk, icon: Flame, hint: 'severity ∈ {high, critical}', tone: 'text-destructive' },
    { key: 'verified', title: '已机器验证', value: sum?.verified, icon: ShieldCheck, hint: '靶场验证 / 差分复现通过', tone: 'text-primary' },
    { key: 'pending', title: '待验证', value: sum?.pending_poc, icon: ListChecks, hint: '尚未机器确认（产物链进行中）', tone: 'text-orange-500' },
    { key: 'confirmed', title: '人工确认', value: sum?.confirmed, icon: CheckCircle2, hint: 'status = confirmed', tone: 'text-blue-500' },
  ]

  const columns: TableProps<SentinelFinding>['columns'] = [
    {
      title: '发现',
      dataIndex: 'title',
      ellipsis: true,
      render: (_, row) => (
        <div className="space-y-0.5">
          <div className="text-[13px] font-medium">{row.title}</div>
          <div className="font-mono text-[10.5px] text-muted-foreground">
            {row.repo_full_name} · {row.sha.slice(0, 8)}
          </div>
        </div>
      ),
    },
    {
      title: '类别',
      dataIndex: 'vuln_class',
      width: 120,
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
      width: 70,
      render: (v: string) => <FindingGradeTag grade={v ?? ''} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 95,
      render: (v: string) => <FindingStatusTag status={v} />,
    },
    {
      title: '机器验证',
      dataIndex: 'verified_at',
      width: 130,
      render: (v: string | null) =>
        v ? (
          <Tag color="success" title={`verified_by 靶场验证/差分复现 · ${fmtTime(v)}`}>
            <ShieldCheck size={10} className="mr-0.5 inline" />
            通过
          </Tag>
        ) : (
          <Tag>验证链进行中</Tag>
        ),
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      width: 150,
      render: (v: string) => <span className="text-xs text-muted-foreground">{fmtTime(v)}</span>,
    },
    {
      title: '',
      key: 'op',
      width: 90,
      render: (_, row) => (
        <Button
          size="small"
          type="text"
          icon={<FileSearch size={12} />}
          onClick={(e) => {
            e.stopPropagation()
            navigate(`/sentinel/audit/results?commit=${row.commit_id}`)
          }}
        >
          详情
        </Button>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title="高危漏洞"
        desc="只收 severity ∈ {high, critical} 的发现：产物链（深审 / python-poc / 利用文档 / nuclei）与验证进度（靶场验证 / 差分复现）都在这里收口。验证结论由 PoC 输出决定，落 poc-verify 产物。"
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
        rowClassName="cursor-pointer"
        onRow={(r) => ({ onClick: () => navigate(`/sentinel/audit/results?commit=${r.commit_id}`) })}
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

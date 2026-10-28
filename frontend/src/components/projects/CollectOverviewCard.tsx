import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, Building2, Globe, Info, Link2, ShieldAlert } from 'lucide-react'
import { Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { Link } from 'react-router-dom'

import { projectApi, type CollectJobRow, type CollectQualityNote } from '@/api/projects'
import { statusTagClass } from '@/components/ui/StatusTag'

// 项目详情「采集详情」：采集到了什么 / 任务跑得怎么样 / 有没有问题。
// 质量信号（漏采对外投资、节点上限中止、待确认候选）显式浮出来，不再靠用户对照两页表格。

const jobStatusLabel: Record<string, string> = {
  running: '采集中',
  done: '已完成',
  error: '失败',
  canceled: '已取消',
}

function QualityRow({ note }: { note: CollectQualityNote }) {
  const icon =
    note.level === 'error' ? (
      <ShieldAlert className="text-destructive h-4 w-4 shrink-0" />
    ) : note.level === 'warn' ? (
      <AlertTriangle className="text-amber-600 dark:text-amber-400 h-4 w-4 shrink-0" />
    ) : (
      <Info className="text-muted-foreground h-4 w-4 shrink-0" />
    )
  return (
    <div className="flex items-start gap-2 text-sm leading-relaxed">
      {icon}
      <span className={note.level === 'error' ? 'text-destructive' : undefined}>{note.message}</span>
    </div>
  )
}

export default function CollectOverviewCard({ projectId, canEdit }: {
  projectId: number
  canEdit: boolean
}) {
  const overview = useQuery({
    queryKey: ['collect-overview', projectId],
    queryFn: () => projectApi.collectOverview(projectId),
    refetchInterval: (query) =>
      (query.state.data?.data?.jobs ?? []).some((j) => j.status === 'running') ? 5000 : false,
  })
  const data = overview.data?.data
  const pending = data?.candidates?.candidate ?? 0
  const imported = data?.candidates?.imported ?? 0
  const rejected = data?.candidates?.rejected ?? 0

  const jobColumns: TableProps<CollectJobRow>['columns'] = [
    {
      title: '数据源',
      dataIndex: 'provider',
      key: 'provider',
      width: 80,
      render: (_, j) => <span className="text-xs font-medium">{j.provider}</span>,
    },
    {
      title: '根企业',
      dataIndex: 'keyword',
      key: 'keyword',
      render: (_, j) => <span className="text-sm">{j.keyword || '—'}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 84,
      render: (_, j) => (
        <Tag
          className={statusTagClass(
            j.status === 'running'
              ? 'default'
              : j.status === 'error'
                ? 'destructive'
                : j.status === 'done'
                  ? 'success'
                  : 'outline'
          )}
          title={j.error || undefined}
        >
          {jobStatusLabel[j.status] ?? j.status}
        </Tag>
      ),
    },
    {
      title: '节点 / 实体 / 域名',
      key: 'counts',
      width: 130,
      render: (_, j) => (
        <span className="font-mono text-xs text-muted-foreground">
          {j.nodes} / {j.entities} / {j.domains}
        </span>
      ),
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 130,
      render: (_, j) => (
        <span className="font-mono text-xs text-muted-foreground">
          {j.created_at}
          {j.finished_at ? ` → ${j.finished_at}` : ''}
        </span>
      ),
    },
  ]

  return (
    <div className="space-y-3">
      {data?.quality && data.quality.length > 0 && (
        <div className="space-y-1.5 rounded-lg border p-3">
          {data.quality.map((n, i) => (
            <QualityRow key={i} note={n} />
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="rounded-lg border p-3">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Building2 className="h-3.5 w-3.5" /> 企业实体
          </p>
          <p className="mt-1 text-xl font-semibold tabular-nums">{data?.entity_total ?? 0}</p>
          <p className="text-muted-foreground mt-0.5 text-xs">
            投资 {data?.entity_type?.invest ?? 0} · 分支 {data?.entity_type?.branch ?? 0} · 集团{' '}
            {data?.entity_type?.group ?? 0}
          </p>
        </div>
        <div className="rounded-lg border p-3">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Link2 className="h-3.5 w-3.5" /> 域名候选
          </p>
          <p className="mt-1 text-xl font-semibold tabular-nums">
            {pending + imported + rejected}
          </p>
          <p className="text-muted-foreground mt-0.5 text-xs">
            待确认 {pending} · 已转种子 {imported}
            {data && data.candidate_no_icp > 0 ? ` · 无备案 ${data.candidate_no_icp}` : ''}
          </p>
        </div>
        <div className="rounded-lg border p-3">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Globe className="h-3.5 w-3.5" /> 域名种子
          </p>
          <p className="mt-1 text-xl font-semibold tabular-nums">{data?.seed_count ?? 0}</p>
          <p className="text-muted-foreground mt-0.5 text-xs">进入扫描范围的目标</p>
        </div>
        <div className="rounded-lg border p-3">
          <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Globe className="h-3.5 w-3.5" /> 站点资产
          </p>
          <p className="mt-1 text-xl font-semibold tabular-nums">{data?.site_count ?? 0}</p>
          <p className="text-muted-foreground mt-0.5 text-xs">
            {pending > 0 && canEdit ? (
              <Link to="/enterprise" className="text-primary hover:underline">
                去确认候选域名 →
              </Link>
            ) : (
              '流水线扫描产出'
            )}
          </p>
        </div>
      </div>

      <Table<CollectJobRow>
        size="small"
        columns={jobColumns}
        dataSource={data?.jobs ?? []}
        rowKey={(j) => `${j.provider}-${j.created_at}-${j.keyword}`}
        loading={overview.isLoading}
        pagination={false}
        locale={{ emptyText: '还没有企业采集任务（项目页「一键侦察」或企业身份页「深度采集」发起）' }}
      />
    </div>
  )
}

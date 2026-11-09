import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Select, Table, Tabs, Tag, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { Activity, ListChecks, RefreshCw } from 'lucide-react'
import { SkillLibraryPanel } from '@/components/settings/SkillLibraryPanel'
import { chatApi, type SkillUsageItem } from '@/api/chat'

/**
 * 代码审计 → 技能库。
 *
 * 两个 tab 是一次完整的「定义 → 使用」闭环：
 *   - 技能库：定义检查清单（新建 / 编辑 / 导入文件 / 设判定默认）
 *   - 调用记录：每一次注入技能的真实执行情况（模型、tokens、耗时、失败原因）
 *
 * 放在代码审计下而不是系统设置：技能是审计口径的一部分，改它等于改判定标准，
 * 和「模型接入 / 用户管理」这类平台配置不是一类东西，埋进设置里没人会去找。
 */
export default function SkillsPage() {
  return (
    <div className="space-y-4 p-1">
      <div>
        <h1 className="text-lg font-semibold tracking-tight">技能库</h1>
        <p className="mt-1 text-[12px] leading-relaxed text-muted-foreground">
          技能是一段注入给模型的检查清单与顺序，对话按会话选、判定用默认技能。
        </p>
      </div>

      <Tabs
        defaultActiveKey="library"
        destroyInactiveTabPane={false}
        items={[
          {
            key: 'library',
            label: (
              <span className="flex items-center gap-1.5">
                <ListChecks size={14} /> 技能库
              </span>
            ),
            children: <SkillLibraryPanel />,
          },
          {
            key: 'usage',
            label: (
              <span className="flex items-center gap-1.5">
                <Activity size={14} /> 调用记录
              </span>
            ),
            children: <SkillUsagePanel />,
          },
        ]}
      />
    </div>
  )
}

function SkillUsagePanel() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [skillId, setSkillId] = useState('')
  const [status, setStatus] = useState('')

  const skillsQuery = useQuery({
    queryKey: ['chat', 'skills', 'manage'],
    queryFn: chatApi.listSkillsManage,
  })

  const usageQuery = useQuery({
    queryKey: ['chat', 'skills', 'usage', page, pageSize, skillId, status],
    queryFn: () =>
      chatApi.skillUsage({
        page,
        page_size: pageSize,
        skill_id: skillId || undefined,
        status: status || undefined,
      }),
    placeholderData: (prev) => prev,
  })

  const summary = usageQuery.data?.summary
  const successRate =
    summary && summary.total > 0 ? Math.round((summary.finished / summary.total) * 100) : 0

  const columns: ColumnsType<SkillUsageItem> = [
    {
      title: '时间',
      dataIndex: 'created_at',
      width: 150,
      render: (v: string) => (
        <span className="font-mono text-[11px] text-muted-foreground">{fmtTime(v)}</span>
      ),
    },
    {
      title: '技能',
      dataIndex: 'skill_name',
      render: (_: unknown, r) => (
        <div className="min-w-0">
          <div className="truncate text-[12px] font-medium">{r.skill_name || r.skill_id}</div>
          <div className="font-mono text-[10px] text-muted-foreground">
            {r.skill_id} {r.skill_version}
          </div>
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) =>
        v === 'finished' ? (
          <Tag className="m-0 border-transparent bg-emerald-600 text-[10px] text-white">完成</Tag>
        ) : v === 'running' ? (
          <Tag className="m-0 border-transparent bg-sky-600 text-[10px] text-white">运行中</Tag>
        ) : (
          <Tag className="m-0 border-transparent bg-red-600 text-[10px] text-white">失败</Tag>
        ),
    },
    {
      title: '模型',
      dataIndex: 'model',
      width: 130,
      render: (v: string) => (
        <span className="font-mono text-[11px] text-muted-foreground">{v || '-'}</span>
      ),
    },
    {
      title: 'tokens',
      width: 110,
      render: (_: unknown, r) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {r.tokens_in} / {r.tokens_out}
        </span>
      ),
    },
    {
      title: '耗时',
      dataIndex: 'duration_ms',
      width: 85,
      render: (v: number) => (
        <span className="font-mono text-[11px] text-muted-foreground">
          {v > 0 ? `${(v / 1000).toFixed(1)}s` : '-'}
        </span>
      ),
    },
    {
      title: '会话',
      dataIndex: 'conversation_id',
      width: 100,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <span className="font-mono text-[10px] text-muted-foreground">{v.slice(0, 8)}</span>
          </Tooltip>
        ) : (
          <span className="text-[11px] text-muted-foreground">-</span>
        ),
    },
    {
      title: '错误',
      dataIndex: 'error',
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <span className="text-[11px] text-red-600">{v}</span>
          </Tooltip>
        ) : (
          <span className="text-[11px] text-muted-foreground">-</span>
        ),
    },
  ]

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <StatCard label="总调用" value={String(summary?.total ?? 0)} hint={`失败 ${summary?.failed ?? 0}`} />
        <StatCard
          label="成功率"
          value={`${successRate}%`}
          hint={`完成 ${summary?.finished ?? 0}`}
          tone={successRate >= 90 ? 'good' : summary && summary.failed > 0 ? 'bad' : 'plain'}
        />
        <StatCard
          label="平均耗时"
          value={summary?.avg_duration_ms ? `${(summary.avg_duration_ms / 1000).toFixed(1)}s` : '-'}
        />
        <StatCard
          label="tokens 合计"
          value={summary ? `${summary.tokens_in} / ${summary.tokens_out}` : '-'}
          hint="输入 / 输出"
        />
      </div>

      <Card
        size="small"
        title="调用明细"
        extra={
          <div className="flex flex-wrap items-center gap-1.5">
            <Select
              size="small"
              allowClear
              placeholder="全部技能"
              style={{ width: 180 }}
              value={skillId || undefined}
              onChange={(v) => {
                setSkillId(v ?? '')
                setPage(1)
              }}
              options={(skillsQuery.data ?? []).map((s) => ({ value: s.id, label: s.name }))}
            />
            <Select
              size="small"
              allowClear
              placeholder="全部状态"
              style={{ width: 110 }}
              value={status || undefined}
              onChange={(v) => {
                setStatus(v ?? '')
                setPage(1)
              }}
              options={[
                { value: 'finished', label: '完成' },
                { value: 'running', label: '运行中' },
                { value: 'error', label: '失败' },
              ]}
            />
            <Button
              size="small"
              icon={<RefreshCw size={12} />}
              loading={usageQuery.isFetching}
              onClick={() => usageQuery.refetch()}
            />
          </div>
        }
      >
        <Table
          size="small"
          rowKey="id"
          columns={columns}
          dataSource={usageQuery.data?.items ?? []}
          loading={usageQuery.isLoading}
          pagination={{
            current: page,
            pageSize,
            total: usageQuery.data?.total ?? 0,
            size: 'small',
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
          }}
          locale={{ emptyText: '还没有调用记录，去「对话」里选一个技能发一条消息。' }}
        />
      </Card>
    </div>
  )
}

function StatCard({
  label,
  value,
  hint,
  tone = 'plain',
}: {
  label: string
  value: string
  hint?: string
  tone?: 'plain' | 'good' | 'bad'
}) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div
        className={
          tone === 'good'
            ? 'mt-0.5 text-lg font-semibold text-emerald-600'
            : tone === 'bad'
              ? 'mt-0.5 text-lg font-semibold text-red-600'
              : 'mt-0.5 text-lg font-semibold'
        }
      >
        {value}
      </div>
      {hint && <div className="text-[10px] text-muted-foreground">{hint}</div>}
    </div>
  )
}

function fmtTime(v: string) {
  if (!v) return '-'
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return v
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

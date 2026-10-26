import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Modal, Table } from 'antd'
import type { TableProps } from 'antd'
import { AlertTriangle, RefreshCw, ShieldCheck, Trash2 } from 'lucide-react'

import {
  assessmentApi,
  type AssessmentSite,
  type AssessmentSiteFilter,
  type CollectionAssessment,
} from '@/api/assessment'
import { useConfirm } from '@/components/common/confirm-provider'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

// 项目资产面综合评估卡片：最新评估（资产概览 + 风险清单 + 处置动作）+ 趋势快照表。
// 风险分三类可下钻（明文 HTTP / 非常规端口 / 证书到期）；注销主体支持一键清理。

interface RiskAction {
  filter?: AssessmentSiteFilter
  purge?: boolean
  label: string
}

function riskAction(risk: string): RiskAction | null {
  if (risk.includes('明文 HTTP')) return { filter: 'plain_http', label: '下钻站点' }
  if (risk.includes('非常规端口')) return { filter: 'odd_port', label: '下钻站点' }
  if (risk.includes('证书')) return { filter: 'cert_expiring', label: '下钻站点' }
  if (risk.includes('注销/吊销')) return { purge: true, label: '立即清理' }
  return null
}

const statTag = (label: string, value: number, danger?: boolean) => (
  <span className="text-sm">
    <span className="text-muted-foreground">{label} </span>
    <span className={danger && value > 0 ? 'font-medium text-red-500' : 'font-medium'}>{value}</span>
  </span>
)

export default function ProjectAssessmentCard({ projectId }: { projectId: number }) {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [drillFilter, setDrillFilter] = useState<AssessmentSiteFilter | null>(null)

  const assessment = useQuery({
    queryKey: ['project-assessment', projectId],
    queryFn: () => assessmentApi.get(projectId),
    retry: false,
  })

  const sitesQuery = useQuery({
    queryKey: ['assessment-sites', projectId, drillFilter],
    queryFn: () => assessmentApi.sites(projectId, drillFilter!),
    enabled: !!drillFilter,
  })

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['project-assessment', projectId] })
    queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
  }

  const purge = useMutation({
    mutationFn: () => assessmentApi.purgeDead(projectId),
    onSuccess: (res) => {
      const d = res.data
      toast({
        title: '清理完成',
        description: `注销/吊销主体 ${d?.entities ?? 0} 家 · 数字候选 ${d?.digital_candidates ?? 0} · 域名候选 ${d?.domain_candidates ?? 0}`,
      })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '清理失败', description: e?.message, variant: 'destructive' }),
  })

  if (assessment.isLoading) return null
  // 从未有评估快照：卡片隐藏（完成一次采集后出现）
  const raw = assessment.data?.data
  if (!raw || !raw.latest) return null

  const latest: CollectionAssessment = raw.latest
  const trend = (raw.trend ?? []).slice(-10)

  const siteColumns: TableProps<AssessmentSite>['columns'] = [
    { title: '站点', key: 'site', render: (_, s) => `${s.protocol}://${s.host}${s.port && ![80, 443].includes(s.port) ? ':' + s.port : ''}` },
    { title: '端口', dataIndex: 'port', width: 80 },
    { title: '状态码', dataIndex: 'http_status', width: 90, render: (v: number) => v || '—' },
    { title: '标题', dataIndex: 'title', ellipsis: true, render: (v: string) => v || '—' },
  ]

  const trendColumns: TableProps<{ taken_at: string } & Record<string, any>>['columns'] = [
    { title: '时间', dataIndex: 'taken_at', width: 130, render: (v: string) => formatDate(v) },
    { title: '主体', dataIndex: 'entities', width: 70 },
    { title: '数字资产', dataIndex: 'digital_assets', width: 90 },
    { title: '域名候选', dataIndex: 'domain_candidates', width: 90 },
    { title: '种子', dataIndex: 'seeds', width: 70 },
    { title: '站点', dataIndex: 'sites', width: 70 },
    {
      title: '风险',
      key: 'risks',
      width: 70,
      render: (_, r) =>
        (r.risks?.length ?? 0) > 0 ? (
          <span className="text-red-500">{r.risks.length}</span>
        ) : (
          <span className="text-muted-foreground">0</span>
        ),
    },
  ]

  return (
    <div className="space-y-3 rounded-md border">
      <div className="flex flex-wrap items-center gap-3 border-b px-4 py-2">
        <span className="flex items-center gap-1.5 text-sm font-medium">
          {latest.risks.length > 0 ? (
            <AlertTriangle className="h-4 w-4 text-red-500" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          )}
          资产面综合评估
        </span>
        <span className="text-xs text-muted-foreground">{latest.trigger}</span>
        <Button
          className="ml-auto"
          size="small"
          icon={<RefreshCw className="h-3.5 w-3.5" />}
          loading={assessment.isFetching}
          onClick={() => assessment.refetch()}
        >
          重新评估
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 px-4 py-2">
        {statTag('主体', latest.entities)}
        {statTag('数字资产', latest.digital_assets)}
        {statTag('域名候选', latest.domain_candidates)}
        {statTag('种子', latest.seeds)}
        {statTag('站点', latest.sites)}
        {statTag('风险', latest.risks.length, true)}
        <span className="text-xs text-muted-foreground">{latest.summary.split('；风险')[0]}</span>
      </div>

      {latest.risks.length > 0 && (
        <div className="space-y-1 px-4 pb-2">
          {latest.risks.map((risk, i) => {
            const act = riskAction(risk)
            return (
              <div key={i} className="flex items-center justify-between gap-2 text-sm">
                <span className="text-red-500">• {risk}</span>
                {act && (
                  <Button
                    size="small"
                    icon={act.purge ? <Trash2 className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                    onClick={async () => {
                      if (act.purge) {
                        if (await confirm('清理所有注销/吊销主体及其关联候选？此操作不可撤销。')) {
                          purge.mutate()
                        }
                        return
                      }
                      setDrillFilter(act.filter ?? null)
                    }}
                  >
                    {act.label}
                  </Button>
                )}
              </div>
            )
          })}
        </div>
      )}

      {trend.length > 1 && (
        <div className="px-4 pb-3">
          <div className="mb-1 text-xs text-muted-foreground">近期趋势（每次采集落一个快照）</div>
          <Table
            columns={trendColumns}
            dataSource={trend}
            rowKey="taken_at"
            size="small"
            pagination={false}
          />
        </div>
      )}

      <Modal
        open={!!drillFilter}
        onCancel={() => setDrillFilter(null)}
        width={720}
        title={
          drillFilter === 'plain_http'
            ? '明文 HTTP 站点'
            : drillFilter === 'odd_port'
              ? '非常规端口站点'
              : '证书 30 天内到期站点'
        }
        footer={
          <Button onClick={() => setDrillFilter(null)}>关闭</Button>
        }
      >
        <Table
          columns={siteColumns}
          dataSource={sitesQuery.data?.data?.items ?? []}
          rowKey="id"
          loading={sitesQuery.isLoading}
          size="small"
          pagination={false}
        />
      </Modal>
    </div>
  )
}

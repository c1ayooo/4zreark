import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Card, Progress, Skeleton, Tag, message } from 'antd'
import { ArrowLeft, RefreshCw, ShieldCheck } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { sentinelApi, type SentinelFindingStatus } from '@/api/sentinel'
import { formatDate } from '@/lib/utils'
import { getErrorMessage } from '@/lib/errors'
import { FindingStatusSelect } from './audit/shared'

const severityColor: Record<string, string> = {
  critical: 'magenta',
  high: 'red',
  medium: 'orange',
  low: 'gold',
  info: 'default',
}

function DiffPanel({ diff }: { diff?: string }) {
  if (!diff) {
    return <p className="text-sm text-muted-foreground">该提交没有可展示的 diff（或已被噪音规则跳过）。</p>
  }
  const lines = diff.split('\n')
  return (
    <pre className="max-h-[520px] overflow-auto rounded-lg border border-border/60 bg-[#0F1419] p-4 text-xs leading-5 text-slate-200">
      {lines.map((line, index) => {
        const color = line.startsWith('+')
          ? 'text-emerald-400'
          : line.startsWith('-')
            ? 'text-rose-400'
            : line.startsWith('@@')
              ? 'text-sky-400'
              : line.startsWith('diff --git')
                ? 'text-amber-300'
                : 'text-slate-400'
        return (
          <div key={index} className={color}>
            {line || ' '}
          </div>
        )
      })}
    </pre>
  )
}

export default function SentinelCommitDetailPage() {
  const params = useParams()
  const id = Number(params.id)
  const queryClient = useQueryClient()

  const detailQuery = useQuery({
    queryKey: ['sentinel-commit', id],
    queryFn: () => sentinelApi.commitDetail(id),
    enabled: Number.isFinite(id) && id > 0,
  })

  const judgeMutation = useMutation({
    mutationFn: () => sentinelApi.judgeCommit(id),
    onSuccess: () => {
      message.success('已加入判定队列，稍后刷新查看结论')
      queryClient.invalidateQueries({ queryKey: ['sentinel-commit', id] })
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  const patchFindingMutation = useMutation({
    mutationFn: ({ findingId, status }: { findingId: number; status: SentinelFindingStatus }) =>
      sentinelApi.patchFinding(findingId, status),
    onSuccess: (f) => {
      message.success(`发现 #${f.id} 状态已更新`)
      queryClient.invalidateQueries({ queryKey: ['sentinel-commit', id] })
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  if (detailQuery.isLoading) {
    return (
      <div>
        <Skeleton active paragraph={{ rows: 8 }} />
      </div>
    )
  }

  const data = detailQuery.data
  const commit = data?.commit
  const judgment = data?.judgment
  const evidence = judgment?.evidence ?? []

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <Link to="/sentinel/commits" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-primary">
            <ArrowLeft className="h-3.5 w-3.5" /> 返回提交列表
          </Link>
          <h1 className="text-2xl font-semibold tracking-tight">{commit?.subject || '提交详情'}</h1>
          <p className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <span className="font-mono">{commit?.sha?.slice(0, 12)}</span>
            <span>·</span>
            <span>{commit?.repo_full_name}</span>
            <span>·</span>
            <span>{commit?.author_name}</span>
            <span>·</span>
            <span>{commit?.committed_at ? formatDate(commit.committed_at) : ''}</span>
          </p>
        </div>
        <Button
          icon={<RefreshCw className="h-4 w-4" />}
          loading={judgeMutation.isPending}
          disabled={Boolean(judgment)}
          onClick={() => judgeMutation.mutate()}
        >
          {judgment ? '已判定（永不重判）' : '立即判定'}
        </Button>
      </header>

      {judgment?.partial ? (
        <Alert
          type="warning"
          showIcon
          message="这次是 partial 结论"
          description="模型输出未通过枚举/evidence 校验，或当前用的是桩模型。结论仅供参考，不进入正式统计。"
        />
      ) : null}

      <Card className="border-border/60" title="判定结论">
        {judgment ? (
          <div className="grid gap-6 md:grid-cols-[220px_1fr]">
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className={judgment.is_security_fix ? 'h-6 w-6 text-rose-500' : 'h-6 w-6 text-slate-400'} />
                <span className="text-lg font-semibold">
                  {judgment.is_security_fix ? '是安全修复' : '不是安全修复'}
                </span>
              </div>
              <div className="flex flex-wrap gap-1.5">
                <Tag color="blue" className="font-mono">
                  {judgment.vuln_class}
                </Tag>
                <Tag color={severityColor[judgment.severity] ?? 'default'}>{judgment.severity}</Tag>
              </div>
              <div>
                <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
                  <span>置信度</span>
                  <span className="font-mono">{Math.round((judgment.confidence ?? 0) * 100)}%</span>
                </div>
                <Progress percent={Math.round((judgment.confidence ?? 0) * 100)} showInfo={false} strokeColor="hsl(var(--primary))" />
              </div>
              <p className="text-xs text-muted-foreground">
                模型 {judgment.model} · prompt {judgment.prompt_tokens} / completion {judgment.completion_tokens} tokens
              </p>
            </div>
            <div className="space-y-3">
              <div>
                <div className="text-xs font-medium text-muted-foreground">位置</div>
                <div className="font-mono text-sm">{judgment.title}</div>
              </div>
              <div>
                <div className="text-xs font-medium text-muted-foreground">理由</div>
                <p className="text-sm leading-6">{judgment.reasoning}</p>
              </div>
              <div>
                <div className="mb-1 text-xs font-medium text-muted-foreground">evidence</div>
                {evidence.length > 0 ? (
                  <ul className="space-y-1">
                    {evidence.map((item, index) => (
                      <li
                        key={index}
                        className="rounded-md border border-sky-500/30 bg-sky-500/5 px-2.5 py-1.5 font-mono text-xs text-sky-700 dark:text-sky-300"
                      >
                        {item}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-xs text-muted-foreground">无（非安全修复不要求 evidence）</p>
                )}
              </div>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">
            {commit?.status === 'skipped'
              ? `已被噪音规则跳过（${commit.skip_reason}），不进入判定。`
              : '尚未判定：点击右上角「立即判定」加入判定队列。'}
          </p>
        )}
      </Card>

      {(data?.findings?.length ?? 0) > 0 && (
        <Card className="border-border/60" title={`发现（${data!.findings.length}）`}>
          <div className="space-y-3">
            {data!.findings.map((finding) => (
              <div key={finding.id} className="rounded-lg border border-border/40 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Tag color="red">{finding.vuln_class}</Tag>
                  <Tag color={severityColor[finding.severity] ?? 'default'}>{finding.severity}</Tag>
                  {finding.grade ? <Tag color={finding.grade === 'S' ? 'magenta' : finding.grade === 'A' ? 'orange' : 'default'}>grade {finding.grade}</Tag> : null}
                  <span className="ml-auto font-mono text-xs text-muted-foreground">{finding.repo_full_name}</span>
                  <FindingStatusSelect
                    status={finding.status}
                    loading={
                      patchFindingMutation.isPending &&
                      patchFindingMutation.variables?.findingId === finding.id
                    }
                    onChange={(next) =>
                      patchFindingMutation.mutate({ findingId: finding.id, status: next })
                    }
                  />
                </div>
                <div className="mt-2 font-mono text-sm">{finding.title}</div>
                <p className="mt-1 text-sm leading-6 text-muted-foreground">{finding.detail}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="border-border/60" title="原始 diff">
        <DiffPanel diff={commit?.diff} />
      </Card>
    </div>
  )
}

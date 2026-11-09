/**
 * 判定依据卡：模型一级判定的依据（reasoning + hunk 证据 + 关键代码摘录），
 * 让高危漏洞页行展开即可看「凭什么判的」，不必跳「分析结果」页。
 *
 * 数据源 GET /sentinel/commits/:id → {commit, judgment, findings}。
 * 完整 diff / 交互操作仍在「分析结果」页（页内提供跳转链接）。
 */
import { useQuery } from '@tanstack/react-query'
import { Skeleton } from 'antd'
import { ExternalLink, Gavel } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { sentinelApi, type SentinelFinding } from '@/api/sentinel'
import { ConfidenceBar, SeverityTag, VulnClassTag, VerdictTag, fmtTime } from './shared'

/** evidence 是 []string（真实 hunk 头），后端会对不上 hunk 的结论降权。 */
function evidenceList(ev: unknown): string[] {
  if (!Array.isArray(ev)) return []
  return ev.filter((x): x is string => typeof x === 'string' && x.trim() !== '')
}

function snippetList(ev: unknown): string[] {
  if (!Array.isArray(ev)) return []
  return ev.filter((x): x is string => typeof x === 'string' && x.trim() !== '')
}

export default function JudgmentBasisCard({
  commitId,
  finding,
}: {
  commitId: number
  finding?: SentinelFinding
}) {
  const navigate = useNavigate()
  const detailQuery = useQuery({
    queryKey: ['sentinel', 'commit', commitId],
    queryFn: () => sentinelApi.commit(commitId),
  })
  const detail = detailQuery.data
  const judgment = detail?.judgment ?? null
  const evidence = evidenceList(judgment?.evidence)
  const snippets = snippetList(judgment?.evidence_snippets)

  return (
    <div className="rounded-xl border border-border bg-card px-3.5 py-3">
      <div className="mb-2 flex items-center gap-2">
        <Gavel size={13} className="text-primary" />
        <span className="text-[12px] font-semibold">判定依据</span>
        {judgment && (
          <>
            <VerdictTag judged={!detail?.commit || detail.commit.status === 'judged'} isSecurityFix={!!judgment.is_security_fix} />
            <span className="ml-1 flex items-center gap-1.5">
              <ConfidenceBar value={judgment.confidence} />
            </span>
          </>
        )}
        <a
          className="ml-auto inline-flex items-center gap-1 text-[11.5px] text-primary hover:underline"
          onClick={() => navigate(`/sentinel/audit/results?commit=${commitId}`)}
        >
          完整提交与 diff 在分析结果页
          <ExternalLink size={11} />
        </a>
      </div>

      {detailQuery.isLoading ? (
        <Skeleton active paragraph={{ rows: 2 }} className="!mt-1" />
      ) : !detail ? (
        <div className="py-1 text-[11.5px] text-muted-foreground">提交详情加载失败，可稍后重试或到分析结果页查看。</div>
      ) : (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[11px] text-muted-foreground">
              {detail.commit.repo_full_name} · {detail.commit.sha.slice(0, 8)} · {fmtTime(detail.commit.committed_at)}
            </span>
            {finding && <SeverityTag severity={finding.severity} />}
            {finding && <VulnClassTag vulnClass={finding.vuln_class} />}
          </div>
          {detail.commit.subject && (
            <div className="text-[12px] text-foreground">{detail.commit.subject}</div>
          )}

          {judgment?.reasoning && (
            <div className="rounded-lg border border-border bg-muted/30 px-2.5 py-2 text-[11.5px] leading-relaxed text-secondary-foreground">
              {judgment.reasoning}
            </div>
          )}

          {evidence.length > 0 && (
            <div>
              <div className="mb-1 text-[10.5px] text-muted-foreground">证据 hunk {evidence.length} 条</div>
              <div className="space-y-1">
                {evidence.slice(0, 6).map((ev, i) => (
                  <div
                    key={i}
                    className="rounded-lg border border-border bg-muted/30 px-2 py-1 font-mono text-[10.5px] leading-relaxed text-secondary-foreground"
                  >
                    {ev}
                  </div>
                ))}
                {evidence.length > 6 && (
                  <div className="text-[10.5px] text-muted-foreground/70">其余 {evidence.length - 6} 条见分析结果页</div>
                )}
              </div>
            </div>
          )}

          {snippets.length > 0 && snippets.length !== evidence.length && (
            <div>
              <div className="mb-1 text-[10.5px] text-muted-foreground">关键代码摘录 {snippets.length} 段</div>
              {snippets.slice(0, 3).map((snip, i) => (
                <pre
                  key={i}
                  className="m-0 max-h-28 overflow-auto rounded-lg border border-border bg-muted/30 px-2 py-1 font-mono text-[10.5px] leading-relaxed text-secondary-foreground"
                >
                  {snip}
                </pre>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

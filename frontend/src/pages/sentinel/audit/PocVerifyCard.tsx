/**
 * POC 靶场验证状态卡（Tier 3b，方案 B 落地）
 *
 * 放在发现条目下方：左侧环境事实 + 隔离边界，右侧流水线时间线，底部 verdict 横幅。
 * 数据源 GET /sentinel/findings/:id/poc-verify；执行中 10s 轮询，静态时停表。
 * 触发 POST /sentinel/findings/:id/poc-verify（verified python-poc 才可用）。
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Popconfirm, Spin, Tag, Tooltip } from 'antd'
import { FlaskConical, Play, RotateCcw, ShieldCheck } from 'lucide-react'
import { sentinelApi, type PocVerifyStatus } from '@/api/sentinel'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import { fmtTime } from './shared'

const VERDICT_META: Record<string, { label: string; cls: string }> = {
  vulnerable: { label: 'VULNERABLE', cls: 'bg-primary text-white' },
  not_vulnerable: { label: 'NOT VULNERABLE', cls: 'bg-[#ff7875] text-white' },
  error: { label: 'ERROR', cls: 'bg-[#faad14] text-[#613400]' },
}

function VerdictBanner({ status }: { status: PocVerifyStatus }) {
  if (status.verified) {
    const v = status.verify
    return (
      <div className="mt-3 flex flex-wrap items-center gap-3 rounded-xl border border-primary/30 bg-accent px-4 py-2.5">
        <span className="font-mono text-[13px] font-bold text-primary">✓ {v ? VERDICT_META[v.verdict]?.label ?? v.verdict : 'VERIFIED'}</span>
        <span className="flex-1 text-[12px] text-foreground">{v?.reason || '机器验证已通过'}</span>
        {v?.exec_detail && <span className="text-[11px] text-muted-foreground">{v.exec_detail}</span>}
      </div>
    )
  }
  if (status.verify) {
    const meta = VERDICT_META[status.verify.verdict] ?? { label: status.verify.verdict, cls: 'bg-muted text-muted-foreground' }
    return (
      <div className="mt-3 flex flex-wrap items-center gap-3 rounded-xl border border-border bg-muted/40 px-4 py-2.5">
        <span className={`font-mono text-[12px] font-bold ${meta.cls} rounded-md px-2 py-0.5`}>{meta.label}</span>
        <span className="flex-1 text-[12px] text-secondary-foreground">{status.verify.reason}</span>
      </div>
    )
  }
  return null
}

export default function PocVerifyCard({ findingId }: { findingId: number }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const statusQuery = useQuery({
    queryKey: ['sentinel', 'poc-verify', findingId],
    queryFn: () => sentinelApi.pocVerifyStatus(findingId),
    refetchInterval: (q) => (q.state.data?.running ? 10_000 : false),
  })
  const status = statusQuery.data
  const busy = !!status?.running

  const verifyMutation = useMutation({
    mutationFn: ({ force }: { force: boolean }) => sentinelApi.verifyPoc(findingId, force),
    onSuccess: () => {
      toast({ title: '已入队靶场验证', description: 'worker 在 pocsmith 进程串行执行：AI 选靶场 → 隔离内网 → 跑 PoC。' })
      queryClient.invalidateQueries({ queryKey: ['sentinel', 'poc-verify', findingId] })
    },
    onError: (e: Error) =>
      toast({ title: '发起验证失败', description: getErrorMessage(e), variant: 'destructive' }),
  })

  return (
    <div className="mt-2 rounded-xl border border-border bg-card px-3.5 py-3">
      <div className="mb-2.5 flex items-center gap-2">
        <FlaskConical size={13} className="text-primary" />
        <span className="text-[12px] font-semibold text-foreground">靶场验证</span>
        {status?.running && <Tag color="processing">执行中</Tag>}
        {status?.verified && (
          <Tooltip
            title={
              status.has_poc
                ? '靶场验证通过，finding 已自动 MarkFindingVerified'
                : '该发现通过差分复现（Tier 3a）完成机器验证：差分复现验证的是修复有效性（预构建镜像 vuln/fix 对比），不依赖 python-poc，因此靶场验证对其不适用'
            }
          >
            <Tag color="success">
              <ShieldCheck size={10} className="mr-0.5 inline" />
              已机器验证{!status.has_poc && '（差分复现）'}
            </Tag>
          </Tooltip>
        )}
        <span className="ml-auto flex items-center gap-1.5">
          {!status?.has_poc && !status?.has_nuclei && !status?.verified && (
            <Tooltip title="需要一份 verified 的 python-poc 或 nuclei 模板产物（高危命中后 LLM 自动草拟，到「分析产物」审核 verified 后即可发起靶场验证，两种引擎任一即可）">
              <span className="text-[11px] text-muted-foreground">缺少 verified python-poc / nuclei 模板，暂不可验证</span>
            </Tooltip>
          )}
          {(status?.has_poc || status?.has_nuclei) && !status.verified && !busy && (
            <Popconfirm
              title="发起靶场验证？"
              description={
                status.has_nuclei && !status.has_poc
                  ? 'AI 选公开靶场镜像（白名单约束）→ docker 起 --internal 隔离内网靶场 → 用 nuclei 模板打靶判定。无外网出口。'
                  : 'AI 选公开靶场镜像（白名单约束）→ docker 起 --internal 隔离内网靶场 → 执行 python-poc 判定可行性。无外网出口。'
              }
              onConfirm={() => verifyMutation.mutate({ force: false })}
            >
              <Button size="small" type="primary" icon={<Play size={11} />} loading={verifyMutation.isPending}>
                发起验证
              </Button>
            </Popconfirm>
          )}
          {(status?.verified || !!status?.verify) && (
            <Popconfirm
              title="强制重跑？"
              description="忽略已有 poc-verify 结论重新验证。"
              onConfirm={() => verifyMutation.mutate({ force: true })}
            >
              <Button size="small" icon={<RotateCcw size={11} />} loading={verifyMutation.isPending}>
                强制重跑
              </Button>
            </Popconfirm>
          )}
        </span>
      </div>

      {statusQuery.isLoading ? (
        <div className="flex items-center gap-2 py-2 text-[12px] text-muted-foreground">
          <Spin size="small" /> 加载验证状态…
        </div>
      ) : !status ? null : (
        <>
          <div className="grid gap-x-6 gap-y-1.5 md:grid-cols-2">
            <div className="space-y-1.5">
              {status.verify?.env && (
                <>
                  <KV k="靶场镜像" v={String(status.verify.env.image ?? '—')} mono />
                  <KV k="TARGET" v={String(status.verify.env.target_url ?? '—')} mono />
                </>
              )}
              <KV
                k="输入 PoC"
                v={
                  status.has_poc
                    ? 'python-poc（verified）'
                    : status.has_nuclei
                      ? 'nuclei 模板（verified，引擎=nuclei）'
                      : '无 verified python-poc / nuclei 模板'
                }
              />
              <KV
                k="隔离边界"
                v="docker --internal 无外网出口 · 镜像白名单 · AI 仅出声明式方案"
              />
            </div>
            <div>
              {status.timeline?.length ? (
                <ol className="relative space-y-2 pl-6 before:absolute before:left-[7px] before:top-1.5 before:bottom-1.5 before:w-px before:bg-border">
                  {status.timeline.map((s, i) => (
                    <li key={i} className="relative">
                      <span
                        className={`absolute -left-6 top-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full text-[9px] text-white ${
                          s.state === 'fail' ? 'bg-destructive' : s.state === 'info' ? 'bg-muted-foreground/50' : 'bg-primary'
                        }`}
                      >
                        {s.state === 'fail' ? '×' : '✓'}
                      </span>
                      <div className="text-[12px] font-medium leading-4">{s.title}</div>
                      {s.detail && (
                        <div className="truncate text-[10.5px] text-muted-foreground" title={s.detail}>
                          {s.detail}
                        </div>
                      )}
                      <div className="text-[9.5px] text-muted-foreground/70">{fmtTime(s.time)}</div>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="py-1 text-[11.5px] text-muted-foreground">
                  尚未执行。发起后这里会回放：环境方案 → 拉镜像 → 起靶场 → 就绪探测 → 执行 PoC → 清理。
                </div>
              )}
            </div>
          </div>
          <VerdictBanner status={status} />
        </>
      )}
    </div>
  )
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex text-[11.5px]">
      <span className="w-16 flex-shrink-0 text-muted-foreground">{k}</span>
      <span className={`flex-1 break-all text-secondary-foreground ${mono ? 'font-mono' : ''}`}>{v}</span>
    </div>
  )
}

/**
 * 验证产物内容卡：直接展示 LLM 产物流水线生成的产物本体——
 * python-poc 脚本 / nuclei 模板 / exploit-guide 利用文档 / deep-analysis 深审报告。
 * 数据源 GET /sentinel/findings/:id/artifacts（含 content），行展开时才拉取。
 * 状态徽标只做辅助，内容才是主角（draft 可直接读，verified 才能发起靶场验证）。
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Skeleton, Tooltip } from 'antd'
import { Check, ChevronDown, ChevronRight, Copy, FileCode2, FileText, ShieldAlert, Wrench } from 'lucide-react'
import { sentinelApi, type SentinelArtifact, type SentinelArtifactStatus } from '@/api/sentinel'
import { fmtTime } from './shared'

const STATUS_CLS: Record<SentinelArtifactStatus | string, string> = {
  verified: 'border-[#b7eb8f] bg-accent text-primary',
  draft: 'border-[#ffe58f] bg-[#fffbe6] text-[#d48806]',
  pending_review: 'border-[#ffe58f] bg-[#fffbe6] text-[#d48806]',
  rejected: 'border-border bg-muted text-muted-foreground',
  deprecated: 'border-border bg-muted text-muted-foreground line-through',
}

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <Tooltip title={done ? '已复制' : '复制内容'}>
      <Button
        size="small"
        type="text"
        icon={done ? <Check size={12} className="text-primary" /> : <Copy size={12} />}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(text)
            setDone(true)
            setTimeout(() => setDone(false), 1500)
          } catch {
            /* 剪贴板不可用时静默 */
          }
        }}
      />
    </Tooltip>
  )
}

function CodeBlock({ content }: { content: string }) {
  return (
    <div className="relative">
      <pre className="m-0 max-h-72 overflow-auto rounded-lg border border-border bg-muted/30 px-3 py-2 font-mono text-[11px] leading-relaxed text-secondary-foreground">
        {content}
      </pre>
      <div className="absolute right-1 top-1">
        <CopyButton text={content} />
      </div>
    </div>
  )
}

/** 一类产物的标题行：图标 + 标题 + 说明 + 状态徽标 */
function ArtifactHeader({
  icon: Icon,
  title,
  desc,
  status,
  updatedAt,
}: {
  icon: typeof FileCode2
  title: string
  desc: string
  status: string
  updatedAt: string
}) {
  return (
    <div className="mb-1.5 flex flex-wrap items-center gap-2">
      <Icon size={13} className="text-primary" />
      <span className="font-mono text-[12px] font-semibold">{title}</span>
      <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${STATUS_CLS[status] ?? 'border-border bg-muted text-muted-foreground'}`}>
        {status}
      </span>
      <span className="text-[10px] text-muted-foreground/70">{fmtTime(updatedAt)}</span>
      <span className="text-[10.5px] text-muted-foreground">{desc}</span>
    </div>
  )
}

function ArtifactSection({ a, desc }: { a: SentinelArtifact; desc: string }) {
  return (
    <div>
      <ArtifactHeader icon={FileCode2} title={a.title} desc={desc} status={a.status} updatedAt={a.updated_at} />
      <CodeBlock content={a.content} />
    </div>
  )
}

/** 深审报告：默认折叠（结论摘要在判定依据卡里已有），需要复核时展开原文 */
function ReportSection({ a, icon: Icon, title, desc }: { a: SentinelArtifact; icon: typeof FileText; title: string; desc: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div>
      <div className="mb-1.5 flex items-center gap-2">
        <button type="button" className="flex items-center gap-2" onClick={() => setOpen(!open)}>
          {open ? <ChevronDown size={13} className="text-muted-foreground" /> : <ChevronRight size={13} className="text-muted-foreground" />}
          <Icon size={13} className="text-primary" />
          <span className="font-mono text-[12px] font-semibold">{title}</span>
        </button>
        <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${STATUS_CLS[a.status] ?? 'border-border bg-muted text-muted-foreground'}`}>
          {a.status}
        </span>
        <span className="text-[10.5px] text-muted-foreground">{desc}</span>
        {open && (
          <span className="ml-auto">
            <CopyButton text={a.content} />
          </span>
        )}
      </div>
      {open && <CodeBlock content={a.content} />}
    </div>
  )
}

const pick = (arts: SentinelArtifact[], kind: string, title: string) =>
  arts.find((a) => a.kind === kind && a.title === title)

export default function FindingArtifactsCard({ findingId }: { findingId: number }) {
  const artsQuery = useQuery({
    queryKey: ['sentinel', 'artifacts', findingId],
    queryFn: () => sentinelApi.findingArtifacts(findingId),
  })
  const arts = artsQuery.data ?? []

  const poc = pick(arts, 'poc', 'python-poc')
  const nuclei = arts.find((a) => a.kind === 'nuclei')
  const guide = pick(arts, 'report', 'exploit-guide')
  const deep = pick(arts, 'report', 'deep-analysis')
  const repro = pick(arts, 'report', 'repro-guide')

  return (
    <div className="rounded-xl border border-border bg-card px-3.5 py-3">
      <div className="mb-2.5 flex items-center gap-2">
        <Wrench size={13} className="text-primary" />
        <span className="text-[12px] font-semibold">LLM 验证产物</span>
        <span className="text-[10.5px] text-muted-foreground">深审 → python-poc → exploit-guide → nuclei，流水线自动草拟（draft），人工 verified 后生效</span>
      </div>

      {artsQuery.isLoading ? (
        <Skeleton active paragraph={{ rows: 2 }} className="!mt-1" />
      ) : !arts.length ? (
        <div className="py-1 text-[11.5px] text-muted-foreground">
          尚无产物。高危命中后会自动触发 LLM 产物流水线；旧数据可到「分析结果」页对该发现手动触发。
        </div>
      ) : (
        <div className="space-y-3">
          {poc && <ArtifactSection a={poc} desc="Python 验证脚本：TARGET 参数化、三态判定输出，verified 后自动入队靶场验证" />}
          {nuclei && <ArtifactSection a={nuclei} desc="nuclei 模板：verified 后可在「POC 模板库」发布" />}
          {guide && <ArtifactSection a={guide} desc="利用文档：前置条件 / 利用步骤 / 影响评估 / 修复确认" />}
          {repro && (
            <ReportSection a={repro} icon={ShieldAlert} title="repro-guide" desc="分步复现指南：攻击路径 / 前置条件 / 复现步骤 / POC 命中" />
          )}
          {deep && (
            <ReportSection a={deep} icon={FileText} title="deep-analysis" desc="二轮深审报告（基于变更文件全文复核），优先于一级判定理由采信" />
          )}
        </div>
      )}
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal, Select } from 'antd'
import {
  vulnApi,
  vulnStatusLabel,
  vulnTransitions,
  type VulnReview,
  type VulnStatus,
} from '@/api/vulnerabilities'
import { useToast } from '@/components/ui/use-toast'
import { ClipboardCheck } from 'lucide-react'

interface VulnReviewDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  vulnId: string
  vulnName: string
  currentStatus: VulnStatus
}

/**
 * 漏洞复核弹窗：按后端状态机只列出可流转的目标状态，
 * 复核意见必填——没有理由的结论在复核流里没有意义。
 */
export function VulnReviewDialog({
  open,
  onOpenChange,
  vulnId,
  vulnName,
  currentStatus,
}: VulnReviewDialogProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const allowed = vulnTransitions[currentStatus] ?? []
  const [toStatus, setToStatus] = useState<VulnStatus | ''>('')
  const [note, setNote] = useState('')

  useEffect(() => {
    if (open) {
      setToStatus(allowed[0] ?? '')
      setNote('')
    }
    // allowed 只在打开时决定初始值；状态变化后不该偷偷改用户的选择。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const reviewsQuery = useQuery({
    queryKey: ['vuln-reviews', vulnId],
    queryFn: () => vulnApi.getReviews(vulnId),
    enabled: open,
  })

  const mutation = useMutation({
    mutationFn: () => vulnApi.reviewVulnerability(vulnId, toStatus as VulnStatus, note.trim()),
    onSuccess: () => {
      toast({ title: '复核已记录', description: `${vulnStatusLabel[currentStatus]} → ${vulnStatusLabel[toStatus as VulnStatus]}` })
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
      queryClient.invalidateQueries({ queryKey: ['vulnerability', vulnId] })
      queryClient.invalidateQueries({ queryKey: ['vuln-reviews', vulnId] })
      onOpenChange(false)
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        '复核失败'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const reviews = reviewsQuery.data ?? []

  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      width={512}
      title={
        <span className="flex items-center gap-2">
          <ClipboardCheck className="h-4 w-4" />
          漏洞复核
        </span>
      }
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>取消</Button>
          <Button
            type="primary"
            loading={mutation.isPending}
            disabled={!toStatus || !note.trim() || allowed.length === 0}
            onClick={() => mutation.mutate()}
          >
            提交复核
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        {vulnName} · 当前状态「{vulnStatusLabel[currentStatus]}」
      </p>

      <div className="space-y-4">
        <div className="space-y-2">
          <label className="text-sm font-medium">复核结论</label>
          {allowed.length === 0 ? (
            <p className="text-muted-foreground text-sm">该状态无可流转的结论。</p>
          ) : (
            <Select
              className="w-full"
              value={toStatus || undefined}
              onChange={(v) => setToStatus(v as VulnStatus)}
              placeholder="选择结论"
              options={allowed.map((s) => ({ value: s, label: vulnStatusLabel[s] }))}
            />
          )}
        </div>

        <div className="space-y-2">
          <label htmlFor="review-note" className="text-sm font-medium">
            复核意见（必填）
          </label>
          <Input.TextArea
            id="review-note"
            placeholder="为什么是这个结论？复测结果、判定依据、遗留风险……"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={4}
          />
        </div>

        <div className="space-y-2">
          <label className="text-sm font-medium">复核历史</label>
          {reviewsQuery.isLoading ? (
            <p className="text-muted-foreground text-sm">加载中…</p>
          ) : reviews.length === 0 ? (
            <p className="text-muted-foreground text-sm">还没有复核记录。</p>
          ) : (
            <ul className="max-h-48 space-y-2 overflow-y-auto text-sm">
              {reviews.map((r: VulnReview) => (
                <li key={r.id} className="border-l-2 border-muted pl-3">
                  <div className="text-muted-foreground text-xs">
                    {new Date(r.created_at).toLocaleString()} ·{' '}
                    {r.auto ? '系统' : r.reviewer || '未知'}
                  </div>
                  <div className="font-medium">
                    {vulnStatusLabel[r.from_status]} → {vulnStatusLabel[r.to_status]}
                  </div>
                  {r.note && <div className="whitespace-pre-wrap">{r.note}</div>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </Modal>
  )
}

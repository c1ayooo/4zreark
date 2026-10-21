import { useState, useEffect } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  vulnApi,
  vulnStatusLabel,
  vulnTransitions,
  type VulnReview,
  type VulnStatus,
} from '@/api/vulnerabilities'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { useToast } from '@/components/ui/use-toast'
import { ClipboardCheck, Loader2 } from 'lucide-react'

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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4" />
            漏洞复核
          </DialogTitle>
          <DialogDescription>
            {vulnName} · 当前状态「{vulnStatusLabel[currentStatus]}」
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label>复核结论</Label>
            {allowed.length === 0 ? (
              <p className="text-muted-foreground text-sm">该状态无可流转的结论。</p>
            ) : (
              <Select value={toStatus} onValueChange={(v) => setToStatus(v as VulnStatus)}>
                <SelectTrigger>
                  <SelectValue placeholder="选择结论" />
                </SelectTrigger>
                <SelectContent>
                  {allowed.map((s) => (
                    <SelectItem key={s} value={s}>
                      {vulnStatusLabel[s]}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="review-note">复核意见（必填）</Label>
            <Textarea
              id="review-note"
              placeholder="为什么是这个结论？复测结果、判定依据、遗留风险……"
              value={note}
              onChange={(e) => setNote(e.target.value)}
              rows={4}
            />
          </div>

          <div className="space-y-2">
            <Label>复核历史</Label>
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

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || !toStatus || !note.trim() || allowed.length === 0}
          >
            {mutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                提交中
              </>
            ) : (
              '提交复核'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

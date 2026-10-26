import { useState } from 'react'
import { Input, Tag } from 'antd'
import { Plus, Star, X } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { assetApi, type Site } from '@/api/assets'
import { useToast } from '@/components/ui/use-toast'
import { cn } from '@/lib/utils'

// 资产治理卡片：星标 / 标签 / 备注，人工运营字段，扫描流程不碰。
// 以 site.id 为 key 挂载，站点切换时内部草稿自动重置。
export function GovernanceCard({ site }: { site: Site }) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [noteDraft, setNoteDraft] = useState(site.note ?? '')
  const [tagDraft, setTagDraft] = useState('')

  const governance = useMutation({
    mutationFn: (body: { starred?: boolean; tags?: string[]; note?: string }) =>
      assetApi.governance(site.id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['asset-detail', site.id] })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
    onError: (e: any) => toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const addTag = () => {
    const t = tagDraft.trim()
    if (!t) return
    if ((site.tags ?? []).includes(t)) {
      setTagDraft('')
      return
    }
    governance.mutate({ tags: [...(site.tags ?? []), t] })
    setTagDraft('')
  }

  const removeTag = (t: string) => {
    governance.mutate({ tags: (site.tags ?? []).filter((x) => x !== t) })
  }

  const saveNote = () => {
    if (noteDraft === (site.note ?? '')) return
    governance.mutate({ note: noteDraft })
  }

  const tags = site.tags ?? []

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          aria-label={site.starred ? '取消星标' : '加星标'}
          className={cn(
            'flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm',
            site.starred ? 'border-amber-300 bg-amber-50 text-amber-600' : 'text-muted-foreground hover:bg-muted'
          )}
          onClick={() => governance.mutate({ starred: !site.starred })}
          disabled={governance.isPending}
        >
          <Star className={cn('h-4 w-4', site.starred && 'fill-amber-400 text-amber-400')} />
          {site.starred ? '已星标' : '星标'}
        </button>
        {tags.map((t) => (
          <Tag
            key={t}
            closable
            closeIcon={<X className="h-3 w-3" />}
            onClose={() => removeTag(t)}
            className="flex items-center gap-1"
          >
            {t}
          </Tag>
        ))}
        <Input
          size="small"
          className="w-[140px]"
          placeholder="添加标签"
          value={tagDraft}
          maxLength={64}
          onChange={(e) => setTagDraft(e.target.value)}
          onPressEnter={addTag}
          suffix={
            <button
              type="button"
              aria-label="添加标签"
              className="text-muted-foreground hover:text-foreground"
              onClick={addTag}
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          }
        />
      </div>
      <Input.TextArea
        rows={3}
        maxLength={2000}
        showCount
        placeholder="备注：资产负责人、业务归属、误报说明…"
        value={noteDraft}
        onChange={(e) => setNoteDraft(e.target.value)}
        onBlur={saveNote}
        disabled={governance.isPending}
      />
      {governance.isPending && <p className="text-xs text-muted-foreground">保存中…</p>}
    </div>
  )
}

// 证书到期标签：按剩余天数配色（过期/7 天内红色、30 天内橙色、其余灰色）。
export function CertExpiryTag({ notAfter }: { notAfter: string }) {
  const days = Math.ceil((new Date(notAfter).getTime() - Date.now()) / 86_400_000)
  const label = days <= 0 ? '证书已过期' : `证书 ${days} 天后到期`
  const cls =
    days <= 7
      ? 'bg-destructive/10 text-destructive border-destructive/30'
      : days <= 30
        ? 'bg-amber-500/10 text-amber-600 border-amber-500/30'
        : 'bg-muted text-muted-foreground border-transparent'
  return (
    <span
      className={cn('inline-flex items-center rounded px-2 py-0.5 text-xs font-medium', cls)}
      title={`证书到期时间 ${notAfter.slice(0, 10)}`}
    >
      {label}
    </span>
  )
}

import { useState } from 'react'
import { Button, Card, Input, Tag } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'

const { TextArea } = Input

export default function QuotePanel() {
  const { toast } = useToast()
  const [quote, setQuote] = useState('')
  const [text, setText] = useState('')
  const [found, setFound] = useState<boolean | null>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    try {
      setFound(await toolsApi.quoteCheck(quote, text))
    } catch (e) {
      toast({ title: (e as Error)?.message || '校验失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="证据引文校验">
      <div className="space-y-3">
        <TextArea placeholder="引文（proof/evidence 摘录）" value={quote} onChange={(e) => setQuote(e.target.value)} />
        <TextArea className="min-h-40 font-mono text-xs" placeholder="回执原文（请求/响应报文）" value={text} onChange={(e) => setText(e.target.value)} />
        <div className="flex items-center gap-3">
          <Button type="primary" onClick={run} disabled={!text} loading={busy}>校验</Button>
          {found !== null && <Tag color={found ? 'success' : 'error'}>{found ? '命中（引文在回执中）' : '未命中'}</Tag>}
        </div>
      </div>
    </Card>
  )
}

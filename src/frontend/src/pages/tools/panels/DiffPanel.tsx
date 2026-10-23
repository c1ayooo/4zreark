import { useState } from 'react'
import { Button, Card, Input } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

const { TextArea } = Input

export default function DiffPanel() {
  const { toast } = useToast()
  const [json, setJson] = useState(`{
  "project_id": 1,
  "baseline": { "label": "baseline", "method": "GET", "url": "https://example.com/api?id=1" },
  "variants": [{ "label": "quote", "method": "GET", "url": "https://example.com/api?id=1'" }]
}`)
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    setResult(null)
    try {
      setResult(await toolsApi.diffprobe(JSON.parse(json)))
    } catch (e) {
      toast({ title: (e as Error)?.message || '差分失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="HTTP 差分测量">
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          输入 baseline 与 variants，输出状态/长度/相似度/时延/DBMS 错误特征。只给建议性信号，不直接下漏洞结论。
        </p>
        <TextArea className="min-h-52 font-mono text-xs" value={json} onChange={(e) => setJson(e.target.value)} />
        <Button type="primary" onClick={run} loading={busy}>运行差分</Button>
        <ResultBlock value={result} />
      </div>
    </Card>
  )
}

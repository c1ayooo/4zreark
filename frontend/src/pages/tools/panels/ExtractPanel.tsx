import { useState } from 'react'
import { Button, Card, Input } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

const { TextArea } = Input

export default function ExtractPanel() {
  const { toast } = useToast()
  const [templateID, setTemplateID] = useState('git-config')
  const [response, setResponse] = useState('')
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true); setResult(null)
    try {
      setResult(await toolsApi.extract({ template_id: templateID, response }))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '提取失败'
      toast({ title: msg, variant: 'destructive' })
    } finally { setBusy(false) }
  }

  return (
    <Card title="命中报文提取">
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">已注册：git-config、phpinfo、备份文件、SFTP 配置等。只解析已有报文，不额外下载。</p>
        <Input placeholder="模板 ID，如 git-config" value={templateID} onChange={(e) => setTemplateID(e.target.value)} />
        <TextArea className="min-h-40 font-mono text-xs" placeholder="命中响应原文" value={response} onChange={(e) => setResponse(e.target.value)} />
        <Button type="primary" onClick={run} disabled={!templateID || !response} loading={busy}>提取</Button>
        <ResultBlock value={result} />
      </div>
    </Card>
  )
}

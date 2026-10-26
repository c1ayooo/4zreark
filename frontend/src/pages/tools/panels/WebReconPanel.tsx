import { useState } from 'react'
import { Button, Card, Checkbox, Input } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

export default function WebReconPanel() {
  const { toast } = useToast()
  const [projectID, setProjectID] = useState('')
  const [baseURL, setBaseURL] = useState('')
  const [unauth, setUnauth] = useState(false)
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    setResult(null)
    try {
      setResult(await toolsApi.webrecon({
        project_id: Number(projectID), base_url: baseURL, unauth_sweep: unauth,
      }))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '侦察失败'
      toast({ title: msg, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="JS 端点与敏感信息侦察">
      <div className="space-y-3">
        <div className="grid gap-3 md:grid-cols-3">
          <Input placeholder="项目 ID（scope 依据）" value={projectID} onChange={(e) => setProjectID(e.target.value)} />
          <Input placeholder="https://target.example.com" value={baseURL} onChange={(e) => setBaseURL(e.target.value)} />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={unauth} onChange={(e) => setUnauth(e.target.checked)} />
            同时跑未授权端点字典
          </label>
        </div>
        <Button type="primary" onClick={run} loading={busy}>开始侦察</Button>
        <ResultBlock value={result} />
      </div>
    </Card>
  )
}

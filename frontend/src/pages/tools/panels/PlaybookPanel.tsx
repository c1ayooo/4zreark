import { useState } from 'react'
import { Button, Card, Input, Select } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

const { TextArea } = Input

export default function PlaybookPanel() {
  const { toast } = useToast()
  const [items, setItems] = useState<{ id: string; name?: string; note?: string }[]>([])
  const [playbook, setPlaybook] = useState('')
  const [projectID, setProjectID] = useState('')
  const [baseURL, setBaseURL] = useState('')
  const [vars, setVars] = useState('{}')
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try {
      const res = await toolsApi.playbooks()
      setItems(res.items || [])
      if (!playbook && res.items?.length) setPlaybook(res.items[0].id)
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取剧本失败', variant: 'destructive' })
    }
  }

  const run = async () => {
    setBusy(true)
    setResult(null)
    try {
      let parsed: Record<string, string> = {}
      try { parsed = JSON.parse(vars || '{}') } catch { throw new Error('vars 不是合法 JSON') }
      setResult(await toolsApi.runPlaybook({
        project_id: Number(projectID), playbook, base_url: baseURL, vars: parsed,
      }))
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '执行失败'
      toast({ title: msg, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="验证剧本">
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          确定性只读剧本（actuator/env 暴露、git 泄露、ES 未授权等）。限速由剧本 limits 硬顶，串行执行。
        </p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={load}>加载剧本列表</Button>
          <Select
            className="w-64"
            value={playbook || undefined}
            onChange={(v) => setPlaybook(v)}
            placeholder="选择剧本"
            options={items.map((it) => ({ value: it.id, label: it.name || it.id }))}
          />
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="项目 ID（scope 依据）" value={projectID} onChange={(e) => setProjectID(e.target.value)} />
          <Input placeholder="https://target.example.com" value={baseURL} onChange={(e) => setBaseURL(e.target.value)} />
        </div>
        <TextArea className="min-h-20 font-mono text-xs" value={vars} onChange={(e) => setVars(e.target.value)} placeholder='变量 JSON，如 {"host":"target.example.com"}' />
        <Button type="primary" onClick={run} disabled={!playbook || !baseURL || !projectID} loading={busy}>
          执行剧本
        </Button>
        <ResultBlock value={result} />
      </div>
    </Card>
  )
}

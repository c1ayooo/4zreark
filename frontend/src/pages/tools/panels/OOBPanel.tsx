import { useEffect, useState } from 'react'
import { Button, Card, Input } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'

export default function OOBPanel() {
  const { toast } = useToast()
  const [base, setBase] = useState('')
  const [domain, setDomain] = useState('')
  const [records, setRecords] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  // 全局默认服务地址：进面板回填（一处配置全局生效，不用每次手填）
  useEffect(() => {
    toolsApi.oobBase().then(setBase).catch(() => {})
  }, [])

  const saveDefault = async () => {
    try {
      const saved = await toolsApi.saveOobBase(base.trim())
      toast({ title: saved ? '已保存为全局默认' : '已恢复默认 dnslog.cn' })
    } catch (e) {
      toast({ title: (e as Error)?.message || '保存失败', variant: 'destructive' })
    }
  }

  const getDomain = async () => {
    setBusy(true)
    try {
      const d = await toolsApi.oobDomain(base)
      setDomain(d)
      setRecords([])
    } catch (e) {
      toast({ title: (e as Error)?.message || '申请失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  const query = async () => {
    if (!domain) return
    setBusy(true)
    try {
      setRecords(await toolsApi.oobRecords(domain, base, 3))
    } catch (e) {
      toast({ title: (e as Error)?.message || '查询失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="DNSLog 带外验证">
      <div className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Input
            className="min-w-0 flex-1"
            placeholder="dnslog 服务地址（留空用 dnslog.cn，可填自建）"
            value={base}
            onChange={(e) => setBase(e.target.value)}
          />
          <Button onClick={saveDefault}>存为默认</Button>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button type="primary" onClick={getDomain} loading={busy}>申请域名</Button>
          <Button onClick={query} disabled={!domain || busy}>查询记录</Button>
        </div>
        {domain && <div className="text-sm">临时域名：<code className="font-mono">{domain}</code></div>}
        {records.length > 0 && (
          <div className="space-y-1">
            {records.map((r, i) => <div key={i} className="rounded border px-2 py-1 font-mono text-xs">{r}</div>)}
          </div>
        )}
      </div>
    </Card>
  )
}

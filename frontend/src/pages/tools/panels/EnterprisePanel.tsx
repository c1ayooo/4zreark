import { useState } from 'react'
import { Button, Card, Input, Select } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type EnterpriseProvider, type EnterpriseRef } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

export default function EnterprisePanel() {
  const { toast } = useToast()
  const [providers, setProviders] = useState<EnterpriseProvider[]>([])
  const [provider, setProvider] = useState('aqc')
  const [cookie, setCookie] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [keyword, setKeyword] = useState('')
  const [items, setItems] = useState<EnterpriseRef[]>([])
  const [detail, setDetail] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try { setProviders(await toolsApi.enterpriseProviders()) } catch (e) {
      toast({ title: (e as Error)?.message || '读取数据源失败', variant: 'destructive' })
    }
  }

  const run = async () => {
    setBusy(true); setItems([]); setDetail(null)
    try {
      const cfg: Record<string, string> = {}
      if (cookie) cfg.cookie = cookie
      if (username) cfg.username = username
      if (password) cfg.password = password
      const res = await toolsApi.enterpriseSearch({ provider, config: cfg, keyword, limit: 10, detail: true })
      setItems(res.items || [])
      setDetail(res.detail || null)
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '检索失败'
      toast({ title: msg, variant: 'destructive' })
    } finally { setBusy(false) }
  }

  return (
    <Card title="企业数据源检索">
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">会话凭据只在本次请求内使用，不落库。小蓝本/风鸟支持账号密码，其余用网页 Cookie。</p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={load}>加载数据源</Button>
          <Select
            className="w-52"
            value={provider}
            onChange={(v) => setProvider(v)}
            options={(providers.length ? providers : [{ Name: 'aqc', Label: '爱企查', Auth: '', Available: true, Hint: '' }]).map((p) => ({
              value: p.Name,
              label: `${p.Label}${p.Available ? '' : '（未启用）'}`,
              disabled: !p.Available,
            }))}
          />
        </div>
        <Input placeholder="Cookie（aqc/tyc/kuaicha/风鸟）" value={cookie} onChange={(e) => setCookie(e.target.value)} />
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="账号（小蓝本/风鸟）" value={username} onChange={(e) => setUsername(e.target.value)} />
          <Input placeholder="密码（小蓝本/风鸟）" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <div className="flex gap-2">
          <Input placeholder="企业关键词" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
          <Button type="primary" onClick={run} disabled={!keyword} loading={busy}>检索</Button>
        </div>
        {items.length > 0 && (
          <div className="divide-y rounded border">
            {items.map((it) => (
              <div key={it.ExtID} className="px-3 py-2 text-sm">
                <span className="font-medium">{it.Name}</span>
                <span className="ml-2 text-xs text-muted-foreground">{it.ExtID}</span>
              </div>
            ))}
          </div>
        )}
        <ResultBlock value={detail} />
      </div>
    </Card>
  )
}

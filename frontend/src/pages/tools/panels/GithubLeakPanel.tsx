import { useState } from 'react'
import { Button, Card, Input, Select, Tag } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type GithubDork, type GithubLeakCandidate } from '@/api/tools'

export default function GithubLeakPanel() {
  const { toast } = useToast()
  const [dorks, setDorks] = useState<GithubDork[]>([])
  const [dorkID, setDorkID] = useState('')
  const [query, setQuery] = useState('')
  const [org, setOrg] = useState('')
  const [domain, setDomain] = useState('')
  const [maxResults, setMaxResults] = useState('50')
  const [items, setItems] = useState<GithubLeakCandidate[]>([])
  const [meta, setMeta] = useState('')
  const [busy, setBusy] = useState(false)

  const load = async () => {
    try {
      setDorks(await toolsApi.githubDorks())
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取模板失败', variant: 'destructive' })
    }
  }

  const run = async () => {
    setBusy(true)
    setItems([])
    setMeta('')
    try {
      const res = await toolsApi.githubLeakScan({
        dork_id: dorkID || undefined, query: query || undefined,
        org: org || undefined, domain: domain || undefined,
        max_results: Number(maxResults) || 50,
      })
      setItems(res.candidates || [])
      setMeta(`候选文件 ${res.items} 个，检测命中 ${res.candidates?.length || 0} 条${res.truncated ? '（已截断）' : ''}`)
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '检索失败'
      toast({ title: msg, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="GitHub 泄露检索">
      <div className="space-y-3">
        <p className="text-xs text-muted-foreground">
          需要 GITHUB_TOKEN。只返回脱敏片段，原始密钥不会回传。
        </p>
        <div className="flex flex-wrap gap-2">
          <Button onClick={load}>加载 dork 模板</Button>
          <Select
            className="w-72"
            value={dorkID || undefined}
            onChange={(v) => setDorkID(v)}
            placeholder="选择 dork（可留空手写 query）"
            options={dorks.map((d) => ({ value: d.id, label: d.title }))}
          />
        </div>
        <Input placeholder="自定义查询（dork 为空时使用）" value={query} onChange={(e) => setQuery(e.target.value)} />
        <div className="grid gap-3 md:grid-cols-3">
          <Input placeholder="org（可选）" value={org} onChange={(e) => setOrg(e.target.value)} />
          <Input placeholder="domain（可选）" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <Input placeholder="最大结果数" value={maxResults} onChange={(e) => setMaxResults(e.target.value)} />
        </div>
        <Button type="primary" onClick={run} disabled={(!dorkID && !query)} loading={busy}>开始检索</Button>
        {meta && <div className="text-xs text-muted-foreground">{meta}</div>}
        {items.length > 0 && (
          <div className="divide-y rounded border">
            {items.map((c, i) => (
              <div key={i} className="space-y-1 px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Tag color={c.Severity === 'high' || c.Severity === 'critical' ? 'error' : undefined}>{c.SecretType || c.RuleName}</Tag>
                  <span className="text-xs text-muted-foreground">{c.Confidence}</span>
                  <a className="ml-auto text-xs text-blue-600 hover:underline" href={c.HTMLURL} target="_blank" rel="noreferrer">打开文件</a>
                </div>
                <div className="font-mono text-xs break-all">{c.Repository}/{c.Path}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

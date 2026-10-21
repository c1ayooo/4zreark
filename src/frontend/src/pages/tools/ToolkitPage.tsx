import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type ComponentCVE, type GithubDork, type GithubLeakCandidate, type EnterpriseProvider, type EnterpriseRef, type NucleiRuntimeStatus, type VerifyStats } from '@/api/tools'
import { Loader2, Radio, KeyRound, GitCompare, Code2, Quote, Boxes, ScrollText, Github, Building2, PackageSearch, Terminal } from 'lucide-react'

function ResultBlock({ value }: { value: unknown }) {
  if (value === null || value === undefined) return null
  return (
    <pre className="mt-3 max-h-80 overflow-auto rounded-md border bg-muted/40 p-3 text-xs whitespace-pre-wrap break-all">
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  )
}

export default function ToolkitPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">工具箱</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          手工验证工具。所有会发流量的操作都要求项目授权（项目种子），凭据验证只做只读探测。
        </p>
      </div>

      <Tabs defaultValue="oob">
        <TabsList className="flex-wrap">
          <TabsTrigger value="oob" className="gap-2"><Radio className="h-4 w-4" />带外验证</TabsTrigger>
          <TabsTrigger value="creds" className="gap-2"><KeyRound className="h-4 w-4" />凭据验证</TabsTrigger>
          <TabsTrigger value="diff" className="gap-2"><GitCompare className="h-4 w-4" />差分组</TabsTrigger>
          <TabsTrigger value="web" className="gap-2"><Code2 className="h-4 w-4" />JS 侦察</TabsTrigger>
          <TabsTrigger value="quote" className="gap-2"><Quote className="h-4 w-4" />引文校验</TabsTrigger>
          <TabsTrigger value="component" className="gap-2"><Boxes className="h-4 w-4" />组件 CVE</TabsTrigger>
          <TabsTrigger value="playbook" className="gap-2"><ScrollText className="h-4 w-4" />验证剧本</TabsTrigger>
          <TabsTrigger value="ghleak" className="gap-2"><Github className="h-4 w-4" />GitHub 泄露</TabsTrigger>
          <TabsTrigger value="enterprise" className="gap-2"><Building2 className="h-4 w-4" />企业检索</TabsTrigger>
          <TabsTrigger value="extract" className="gap-2"><PackageSearch className="h-4 w-4" />报文提取</TabsTrigger>
          <TabsTrigger value="runtime" className="gap-2"><Terminal className="h-4 w-4" />运行时</TabsTrigger>
        </TabsList>

        <TabsContent value="oob"><OOBPanel /></TabsContent>
        <TabsContent value="creds"><CredsPanel /></TabsContent>
        <TabsContent value="diff"><DiffPanel /></TabsContent>
        <TabsContent value="web"><WebReconPanel /></TabsContent>
        <TabsContent value="quote"><QuotePanel /></TabsContent>
        <TabsContent value="component"><ComponentPanel /></TabsContent>
        <TabsContent value="playbook"><PlaybookPanel /></TabsContent>
        <TabsContent value="ghleak"><GithubLeakPanel /></TabsContent>
        <TabsContent value="enterprise"><EnterprisePanel /></TabsContent>
        <TabsContent value="extract"><ExtractPanel /></TabsContent>
        <TabsContent value="runtime"><RuntimePanel /></TabsContent>
      </Tabs>
    </div>
  )
}

function OOBPanel() {
  const { toast } = useToast()
  const [base, setBase] = useState('')
  const [domain, setDomain] = useState('')
  const [records, setRecords] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

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
    <Card>
      <CardHeader><CardTitle className="text-base">DNSLog 带外验证</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <Input placeholder="dnslog 服务地址（留空用 dnslog.cn，可填自建）" value={base} onChange={(e) => setBase(e.target.value)} />
        <div className="flex flex-wrap gap-2">
          <Button onClick={getDomain} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}申请域名</Button>
          <Button variant="outline" onClick={query} disabled={!domain || busy}>查询记录</Button>
        </div>
        {domain && <div className="text-sm">临时域名：<code className="font-mono">{domain}</code></div>}
        {records.length > 0 && (
          <div className="space-y-1">
            {records.map((r, i) => <div key={i} className="rounded border px-2 py-1 font-mono text-xs">{r}</div>)}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function CredsPanel() {
  const { toast } = useToast()
  const [kind, setKind] = useState('db')
  const [projectID, setProjectID] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [dbType, setDbType] = useState('postgres')
  const [database, setDatabase] = useState('')
  const [provider, setProvider] = useState('aliyun')
  const [accessKey, setAccessKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setBusy(true)
    setResult(null)
    try {
      if (kind === 'cloud') {
        setResult(await toolsApi.verifyCloud({ provider, access_key_id: accessKey, secret_key: secretKey }))
      } else if (kind === 'db') {
        setResult(await toolsApi.verifyDB({
          project_id: Number(projectID), type: dbType, host, port: Number(port) || 0,
          username, password, database,
        }))
      } else {
        setResult(await toolsApi.verifySSH({
          project_id: Number(projectID), host, port: Number(port) || 0, username, password,
        }))
      }
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '验证失败'
      toast({ title: msg, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader><CardTitle className="text-base">凭据只读验证</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <div className="mb-1 text-xs text-muted-foreground">类型</div>
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="db">数据库</SelectItem>
                <SelectItem value="ssh">SSH</SelectItem>
                <SelectItem value="cloud">云 AK/SK</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {kind === 'cloud' ? (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">云厂商</div>
              <Select value={provider} onValueChange={setProvider}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="aliyun">阿里云</SelectItem>
                  <SelectItem value="tencent">腾讯云</SelectItem>
                  <SelectItem value="aws">AWS</SelectItem>
                  <SelectItem value="huawei">华为云</SelectItem>
                  <SelectItem value="volc">火山引擎</SelectItem>
                </SelectContent>
              </Select>
            </div>
          ) : (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">项目 ID（scope 依据）</div>
              <Input value={projectID} onChange={(e) => setProjectID(e.target.value)} placeholder="如 1" />
            </div>
          )}
        </div>

        {kind === 'cloud' ? (
          <div className="grid gap-3 md:grid-cols-2">
            <Input placeholder="AccessKeyId" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} />
            <Input placeholder="SecretKey" type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} />
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            {kind === 'db' && (
              <Select value={dbType} onValueChange={setDbType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="postgres">PostgreSQL</SelectItem>
                  <SelectItem value="redis">Redis</SelectItem>
                </SelectContent>
              </Select>
            )}
            <Input placeholder="主机" value={host} onChange={(e) => setHost(e.target.value)} />
            <Input placeholder="端口（可空）" value={port} onChange={(e) => setPort(e.target.value)} />
            <Input placeholder="用户名" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="密码 / 私钥" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            {kind === 'db' && <Input placeholder="库名（可空）" value={database} onChange={(e) => setDatabase(e.target.value)} />}
          </div>
        )}

        <Button onClick={submit} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}验证</Button>
        <ResultBlock value={result} />
      </CardContent>
    </Card>
  )
}

function DiffPanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">HTTP 差分测量</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          输入 baseline 与 variants，输出状态/长度/相似度/时延/DBMS 错误特征。只给建议性信号，不直接下漏洞结论。
        </p>
        <Textarea className="min-h-52 font-mono text-xs" value={json} onChange={(e) => setJson(e.target.value)} />
        <Button onClick={run} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}运行差分</Button>
        <ResultBlock value={result} />
      </CardContent>
    </Card>
  )
}

function WebReconPanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">JS 端点与敏感信息侦察</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 md:grid-cols-3">
          <Input placeholder="项目 ID（scope 依据）" value={projectID} onChange={(e) => setProjectID(e.target.value)} />
          <Input placeholder="https://target.example.com" value={baseURL} onChange={(e) => setBaseURL(e.target.value)} />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={unauth} onCheckedChange={(v) => setUnauth(v === true)} />
            同时跑未授权端点字典
          </label>
        </div>
        <Button onClick={run} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}开始侦察</Button>
        <ResultBlock value={result} />
      </CardContent>
    </Card>
  )
}

function QuotePanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">证据引文校验</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <Textarea placeholder="引文（proof/evidence 摘录）" value={quote} onChange={(e) => setQuote(e.target.value)} />
        <Textarea className="min-h-40 font-mono text-xs" placeholder="回执原文（请求/响应报文）" value={text} onChange={(e) => setText(e.target.value)} />
        <div className="flex items-center gap-3">
          <Button onClick={run} disabled={busy || !text}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}校验</Button>
          {found !== null && <Badge variant={found ? 'success' : 'destructive'}>{found ? '命中（引文在回执中）' : '未命中'}</Badge>}
        </div>
      </CardContent>
    </Card>
  )
}

function ComponentPanel() {
  const { toast } = useToast()
  const [product, setProduct] = useState('')
  const [items, setItems] = useState<ComponentCVE[]>([])
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    try {
      setItems(await toolsApi.componentCVEs(product))
    } catch (e) {
      toast({ title: (e as Error)?.message || '查询失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader><CardTitle className="text-base">组件 → CVE</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-2">
          <Input placeholder="产品名，如 apache-tomcat / nginx" value={product} onChange={(e) => setProduct(e.target.value)} />
          <Button onClick={run} disabled={busy || !product}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}查询</Button>
        </div>
        {items.length === 0 && !busy && <p className="text-xs text-muted-foreground">暂无结果。索引来自本机 POC 库的 template-id/tags 与指纹规则名。</p>}
        {items.length > 0 && (
          <div className="divide-y rounded border">
            {items.map((c) => (
              <div key={c.product + c.cve} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                <span className="font-mono">{c.cve}</span>
                <span className="truncate text-xs text-muted-foreground">{c.evidence}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}


function PlaybookPanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">验证剧本</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          确定性只读剧本（actuator/env 暴露、git 泄露、ES 未授权等）。限速由剧本 limits 硬顶，串行执行。
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={load}>加载剧本列表</Button>
          <Select value={playbook} onValueChange={setPlaybook}>
            <SelectTrigger className="w-64"><SelectValue placeholder="选择剧本" /></SelectTrigger>
            <SelectContent>
              {items.map((it) => <SelectItem key={it.id} value={it.id}>{it.name || it.id}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="项目 ID（scope 依据）" value={projectID} onChange={(e) => setProjectID(e.target.value)} />
          <Input placeholder="https://target.example.com" value={baseURL} onChange={(e) => setBaseURL(e.target.value)} />
        </div>
        <Textarea className="min-h-20 font-mono text-xs" value={vars} onChange={(e) => setVars(e.target.value)} placeholder='变量 JSON，如 {"host":"target.example.com"}' />
        <Button onClick={run} disabled={busy || !playbook || !baseURL || !projectID}>
          {busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}执行剧本
        </Button>
        <ResultBlock value={result} />
      </CardContent>
    </Card>
  )
}


function GithubLeakPanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">GitHub 泄露检索</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">
          需要 GITHUB_TOKEN。只返回脱敏片段，原始密钥不会回传。
        </p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={load}>加载 dork 模板</Button>
          <Select value={dorkID} onValueChange={setDorkID}>
            <SelectTrigger className="w-72"><SelectValue placeholder="选择 dork（可留空手写 query）" /></SelectTrigger>
            <SelectContent>
              {dorks.map((d) => <SelectItem key={d.id} value={d.id}>{d.title}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <Input placeholder="自定义查询（dork 为空时使用）" value={query} onChange={(e) => setQuery(e.target.value)} />
        <div className="grid gap-3 md:grid-cols-3">
          <Input placeholder="org（可选）" value={org} onChange={(e) => setOrg(e.target.value)} />
          <Input placeholder="domain（可选）" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <Input placeholder="最大结果数" value={maxResults} onChange={(e) => setMaxResults(e.target.value)} />
        </div>
        <Button onClick={run} disabled={busy || (!dorkID && !query)}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}开始检索</Button>
        {meta && <div className="text-xs text-muted-foreground">{meta}</div>}
        {items.length > 0 && (
          <div className="divide-y rounded border">
            {items.map((c, i) => (
              <div key={i} className="space-y-1 px-3 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant={c.Severity === 'high' || c.Severity === 'critical' ? 'destructive' : 'secondary'}>{c.SecretType || c.RuleName}</Badge>
                  <span className="text-xs text-muted-foreground">{c.Confidence}</span>
                  <a className="ml-auto text-xs text-blue-600 hover:underline" href={c.HTMLURL} target="_blank" rel="noreferrer">打开文件</a>
                </div>
                <div className="font-mono text-xs break-all">{c.Repository}/{c.Path}</div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}


function EnterprisePanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">企业数据源检索</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">会话凭据只在本次请求内使用，不落库。小蓝本/风鸟支持账号密码，其余用网页 Cookie。</p>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={load}>加载数据源</Button>
          <Select value={provider} onValueChange={setProvider}>
            <SelectTrigger className="w-52"><SelectValue /></SelectTrigger>
            <SelectContent>
              {(providers.length ? providers : [{ Name: 'aqc', Label: '爱企查', Auth: '', Available: true, Hint: '' }]).map((p) => (
                <SelectItem key={p.Name} value={p.Name} disabled={!p.Available}>{p.Label}{p.Available ? '' : '（未启用）'}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Input placeholder="Cookie（aqc/tyc/kuaicha/风鸟）" value={cookie} onChange={(e) => setCookie(e.target.value)} />
        <div className="grid gap-3 md:grid-cols-2">
          <Input placeholder="账号（小蓝本/风鸟）" value={username} onChange={(e) => setUsername(e.target.value)} />
          <Input placeholder="密码（小蓝本/风鸟）" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <div className="flex gap-2">
          <Input placeholder="企业关键词" value={keyword} onChange={(e) => setKeyword(e.target.value)} />
          <Button onClick={run} disabled={busy || !keyword}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}检索</Button>
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
      </CardContent>
    </Card>
  )
}

function ExtractPanel() {
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
    <Card>
      <CardHeader><CardTitle className="text-base">命中报文提取</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">已注册：git-config、phpinfo、备份文件、SFTP 配置等。只解析已有报文，不额外下载。</p>
        <Input placeholder="模板 ID，如 git-config" value={templateID} onChange={(e) => setTemplateID(e.target.value)} />
        <Textarea className="min-h-40 font-mono text-xs" placeholder="命中响应原文" value={response} onChange={(e) => setResponse(e.target.value)} />
        <Button onClick={run} disabled={busy || !templateID || !response}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}提取</Button>
        <ResultBlock value={result} />
      </CardContent>
    </Card>
  )
}


function RuntimePanel() {
  const { toast } = useToast()
  const [status, setStatus] = useState<NucleiRuntimeStatus | null>(null)
  const [stats, setStats] = useState<VerifyStats | null>(null)
  const [busy, setBusy] = useState(false)

  const load = async () => {
    setBusy(true)
    try {
      const [st, vs] = await Promise.all([toolsApi.nucleiRuntimeStatus(), toolsApi.verifyStats(30)])
      setStatus(st)
      setStats(vs)
    } catch (e) {
      toast({ title: (e as Error)?.message || '读取运行时状态失败', variant: 'destructive' })
    } finally { setBusy(false) }
  }

  const ensure = async () => {
    setBusy(true)
    try {
      await toolsApi.nucleiRuntimeEnsure(true)
      toast({ title: '运行时检查完成' })
      await load()
    } catch (e) {
      toast({ title: (e as Error)?.message || '检查失败', variant: 'destructive' })
    } finally { setBusy(false) }
  }

  const update = async () => {
    setBusy(true)
    try {
      await toolsApi.nucleiRuntimeUpdate({ force: false })
      toast({ title: 'nuclei 运行时已更新' })
      await load()
    } catch (e) {
      toast({ title: (e as Error)?.message || '更新失败', variant: 'destructive' })
    } finally { setBusy(false) }
  }

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle className="text-base">nuclei 运行时</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={load} disabled={busy}>{busy && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}刷新状态</Button>
            <Button variant="outline" onClick={ensure} disabled={busy}>检查/补齐</Button>
            <Button onClick={update} disabled={busy}>更新二进制与模板</Button>
          </div>
          {status && (
            <div className="space-y-1 text-sm">
              <div>二进制：<code className="font-mono text-xs">{status.BinaryPath}</code> <Badge variant={status.BinaryExists ? 'success' : 'destructive'}>{status.BinaryExists ? status.BinaryVersion || '已安装' : '缺失'}</Badge></div>
              <div>官方模板：{status.TemplateCount} 个 <Badge variant={status.TemplatesExists ? 'success' : 'destructive'}>{status.TemplatesExists ? '已同步' : '缺失'}</Badge></div>
              <div>自定义模板：{status.CustomTemplateCount} 个</div>
              <div className="text-xs text-muted-foreground">自动更新：{status.AutoUpdate ? '开' : '关'} · 间隔 {status.UpdateIntervalHours}h · 引导版本 {status.VersionSetting}</div>
              {status.Warnings?.map((w, i) => <div key={i} className="text-xs text-amber-600">{w}</div>)}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">自动验证统计（近 30 天）</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          {stats ? (
            <>
              <div>完结任务：{stats.finished} · 命中 {stats.hits} · 未命中 {stats.misses} · 失败 {stats.failures} · 跳过 {stats.skipped}</div>
              <div className="text-xs text-muted-foreground">状态分布：{Object.entries(stats.by_status || {}).map(([k, v]) => `${k}=${v}`).join(' · ') || '无'}</div>
            </>
          ) : <p className="text-xs text-muted-foreground">点击刷新读取统计。</p>}
        </CardContent>
      </Card>
    </div>
  )
}

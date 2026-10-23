import { useState } from 'react'
import { Button, Card, Checkbox, Input, Select, Tabs, Tag } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type ComponentCVE, type GithubDork, type GithubLeakCandidate, type EnterpriseProvider, type EnterpriseRef, type NucleiRuntimeStatus, type VerifyStats } from '@/api/tools'
import { Radio, KeyRound, GitCompare, Code2, Quote, Boxes, ScrollText, Github, Building2, PackageSearch, Terminal, RefreshCw } from 'lucide-react'
import ToolUpdatePanel from '@/pages/tools/ToolUpdatePanel'

const { TextArea } = Input

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

      <Tabs
        defaultActiveKey="oob"
        items={[
          { key: 'oob', label: <span className="flex items-center gap-2"><Radio className="h-4 w-4" />带外验证</span>, children: <OOBPanel /> },
          { key: 'creds', label: <span className="flex items-center gap-2"><KeyRound className="h-4 w-4" />凭据验证</span>, children: <CredsPanel /> },
          { key: 'diff', label: <span className="flex items-center gap-2"><GitCompare className="h-4 w-4" />差分组</span>, children: <DiffPanel /> },
          { key: 'web', label: <span className="flex items-center gap-2"><Code2 className="h-4 w-4" />JS 侦察</span>, children: <WebReconPanel /> },
          { key: 'quote', label: <span className="flex items-center gap-2"><Quote className="h-4 w-4" />引文校验</span>, children: <QuotePanel /> },
          { key: 'component', label: <span className="flex items-center gap-2"><Boxes className="h-4 w-4" />组件 CVE</span>, children: <ComponentPanel /> },
          { key: 'playbook', label: <span className="flex items-center gap-2"><ScrollText className="h-4 w-4" />验证剧本</span>, children: <PlaybookPanel /> },
          { key: 'ghleak', label: <span className="flex items-center gap-2"><Github className="h-4 w-4" />GitHub 泄露</span>, children: <GithubLeakPanel /> },
          { key: 'enterprise', label: <span className="flex items-center gap-2"><Building2 className="h-4 w-4" />企业检索</span>, children: <EnterprisePanel /> },
          { key: 'extract', label: <span className="flex items-center gap-2"><PackageSearch className="h-4 w-4" />报文提取</span>, children: <ExtractPanel /> },
          { key: 'updates', label: <span className="flex items-center gap-2"><RefreshCw className="h-4 w-4" />更新策略</span>, children: <ToolUpdatePanel /> },
          { key: 'runtime', label: <span className="flex items-center gap-2"><Terminal className="h-4 w-4" />运行时</span>, children: <RuntimePanel /> },
        ]}
      />
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
    <Card title="DNSLog 带外验证">
      <div className="space-y-3">
        <Input placeholder="dnslog 服务地址（留空用 dnslog.cn，可填自建）" value={base} onChange={(e) => setBase(e.target.value)} />
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
    <Card title="凭据只读验证">
      <div className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <div className="mb-1 text-xs text-muted-foreground">类型</div>
            <Select
              value={kind}
              onChange={(v) => setKind(v)}
              options={[
                { value: 'db', label: '数据库' },
                { value: 'ssh', label: 'SSH' },
                { value: 'cloud', label: '云 AK/SK' },
              ]}
            />
          </div>
          {kind === 'cloud' ? (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">云厂商</div>
              <Select
                value={provider}
                onChange={(v) => setProvider(v)}
                options={[
                  { value: 'aliyun', label: '阿里云' },
                  { value: 'tencent', label: '腾讯云' },
                  { value: 'aws', label: 'AWS' },
                  { value: 'huawei', label: '华为云' },
                  { value: 'volc', label: '火山引擎' },
                ]}
              />
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
              <Select
                value={dbType}
                onChange={(v) => setDbType(v)}
                options={[
                  { value: 'postgres', label: 'PostgreSQL' },
                  { value: 'redis', label: 'Redis' },
                ]}
              />
            )}
            <Input placeholder="主机" value={host} onChange={(e) => setHost(e.target.value)} />
            <Input placeholder="端口（可空）" value={port} onChange={(e) => setPort(e.target.value)} />
            <Input placeholder="用户名" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="密码 / 私钥" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            {kind === 'db' && <Input placeholder="库名（可空）" value={database} onChange={(e) => setDatabase(e.target.value)} />}
          </div>
        )}

        <Button type="primary" onClick={submit} loading={busy}>验证</Button>
        <ResultBlock value={result} />
      </div>
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
    <Card title="组件 → CVE">
      <div className="space-y-3">
        <div className="flex gap-2">
          <Input placeholder="产品名，如 apache-tomcat / nginx" value={product} onChange={(e) => setProduct(e.target.value)} />
          <Button type="primary" onClick={run} disabled={!product} loading={busy}>查询</Button>
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
      </div>
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
      <Card title="nuclei 运行时">
        <div className="space-y-3">
          <div className="flex flex-wrap gap-2">
            <Button onClick={load} loading={busy}>刷新状态</Button>
            <Button onClick={ensure} disabled={busy}>检查/补齐</Button>
            <Button type="primary" onClick={update} disabled={busy}>更新二进制与模板</Button>
          </div>
          {status && (
            <div className="space-y-1 text-sm">
              <div>二进制：<code className="font-mono text-xs">{status.BinaryPath}</code> <Tag color={status.BinaryExists ? 'success' : 'error'}>{status.BinaryExists ? status.BinaryVersion || '已安装' : '缺失'}</Tag></div>
              <div>官方模板：{status.TemplateCount} 个 <Tag color={status.TemplatesExists ? 'success' : 'error'}>{status.TemplatesExists ? '已同步' : '缺失'}</Tag></div>
              <div>自定义模板：{status.CustomTemplateCount} 个</div>
              <div className="text-xs text-muted-foreground">自动更新：{status.AutoUpdate ? '开' : '关'} · 间隔 {status.UpdateIntervalHours}h · 引导版本 {status.VersionSetting}</div>
              {status.Warnings?.map((w, i) => <div key={i} className="text-xs text-amber-600">{w}</div>)}
            </div>
          )}
        </div>
      </Card>

      <Card title="自动验证统计（近 30 天）">
        <div className="space-y-2 text-sm">
          {stats ? (
            <>
              <div>完结任务：{stats.finished} · 命中 {stats.hits} · 未命中 {stats.misses} · 失败 {stats.failures} · 跳过 {stats.skipped}</div>
              <div className="text-xs text-muted-foreground">状态分布：{Object.entries(stats.by_status || {}).map(([k, v]) => `${k}=${v}`).join(' · ') || '无'}</div>
            </>
          ) : <p className="text-xs text-muted-foreground">点击刷新读取统计。</p>}
        </div>
      </Card>
    </div>
  )
}

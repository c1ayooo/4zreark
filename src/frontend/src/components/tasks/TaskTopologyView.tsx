import { useMemo } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from 'antd'
import { RefreshCw } from 'lucide-react'

import type { AssetGraphData, AssetGraphEdge, AssetGraphNode, AssetGraphRel } from '@/api/assets'
import { resultApi, type ResultType } from '@/api/results'
import { AssetGraphCanvas } from '@/components/assets/AssetGraphCanvas'
import { cn } from '@/lib/utils'

interface TaskTopologyViewProps {
  taskId: string
  taskName: string
}

type ResultItem = Record<string, unknown>

const PAGE_SIZE = 1000
const EMPTY: ResultItem[] = []

const text = (v: unknown): string => (typeof v === 'string' ? v.trim() : '')
const num = (v: unknown): number => {
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v)
    return Number.isFinite(n) ? n : 0
  }
  return 0
}
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string' && x.trim() !== '') : []

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/
const isIP = (host: string) => IPV4.test(host)

// 常见两级公共后缀。前端不引入 PSL 依赖，只保证这些后缀下的根域名取对。
const MULTI_LABEL_SUFFIXES = new Set([
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'com.hk', 'com.tw', 'com.mo', 'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
  'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'or.kr', 'com.au', 'net.au', 'org.au',
  'co.nz', 'com.sg', 'com.my', 'co.id', 'co.in', 'net.in', 'com.br',
  'com.mx', 'com.ar', 'com.tr', 'com.ru', 'com.ua', 'co.za', 'com.sa', 'com.eg',
])

function rootDomain(host: string): string {
  const labels = host.split('.').filter(Boolean)
  if (labels.length <= 2) return labels.join('.')
  const lastTwo = labels.slice(-2).join('.')
  return MULTI_LABEL_SUFFIXES.has(lastTwo) ? labels.slice(-3).join('.') : lastTwo
}

function normalizeHost(raw: string): string {
  let v = raw.trim().toLowerCase()
  if (!v) return ''
  if (v.includes('://')) {
    try {
      v = new URL(v).hostname.toLowerCase()
    } catch {
      /* 保留原值继续清理 */
    }
  }
  const slash = v.indexOf('/')
  if (slash >= 0) v = v.slice(0, slash)
  // 去掉端口；IPv6 字面量（多个冒号）原样保留。
  if ((v.match(/:/g)?.length ?? 0) === 1) v = v.split(':')[0]
  return v.replace(/\.$/, '')
}

function parseURL(raw: string): { host: string; scheme: string; port: number; path: string } | null {
  const v = raw.trim()
  if (!v) return null
  try {
    const u = new URL(v)
    const scheme = u.protocol.replace(':', '').toLowerCase()
    const port = u.port
      ? Number(u.port)
      : scheme === 'https'
        ? 443
        : scheme === 'http'
          ? 80
          : 0
    const host = normalizeHost(u.hostname)
    if (!host || !port) return null
    return { host, scheme, port, path: `${u.pathname || '/'}${u.search}` }
  } catch {
    return null
  }
}

function techList(item: ResultItem): string[] {
  const merged = [
    ...strings(item.technologies),
    ...strings(item.fingerprints),
    ...strings(item.fingerprint),
  ]
  return [...new Set(merged)]
}

/**
 * 把任务结果映射成与项目级资产星图相同的层级：
 * 任务 → 根域名 → 子域名 → IP → 服务 → 入口 / 路由。
 * 节点 key 与后端 BuildAssetGraph 保持同样的前缀习惯，方便对照。
 */
function buildTaskGraph(
  taskId: string,
  taskName: string,
  subdomains: ResultItem[],
  ports: ResultItem[],
  services: ResultItem[],
  urls: ResultItem[],
): AssetGraphData {
  const nodes = new Map<string, AssetGraphNode>()
  const edges: AssetGraphEdge[] = []
  const edgeSeen = new Set<string>()

  const addNode = (node: AssetGraphNode): AssetGraphNode => {
    const existing = nodes.get(node.key)
    if (!existing) {
      nodes.set(node.key, node)
      return node
    }
    // 同一个服务可能先由端口结果创建、后被 Web 结果补全，空字段按需合并。
    for (const field of Object.keys(node) as (keyof AssetGraphNode)[]) {
      const value = node[field]
      const incomingEmpty =
        value === undefined ||
        value === '' ||
        value === 0 ||
        (Array.isArray(value) && value.length === 0)
      if (incomingEmpty) continue
      const current = existing[field]
      const currentEmpty =
        current === undefined ||
        current === '' ||
        current === 0 ||
        (Array.isArray(current) && current.length === 0)
      if (currentEmpty) {
        ;(existing as unknown as Record<string, unknown>)[field] = value
      }
    }
    return existing
  }

  const addEdge = (src: string, dst: string, rel: AssetGraphRel) => {
    if (!src || !dst || src === dst) return
    const key = `${src}\u0000${rel}\u0000${dst}`
    if (edgeSeen.has(key)) return
    edgeSeen.add(key)
    edges.push({ src, dst, rel })
  }

  const projectKey = `p:task:${taskId}`
  addNode({ key: projectKey, kind: 'project', label: taskName || '本次任务' })

  const resolveIP = (parent: string, rawIP: string) => {
    const ip = normalizeHost(rawIP)
    if (!ip || !isIP(ip)) return
    const ipKey = `i:${ip}`
    addNode({ key: ipKey, kind: 'ip', label: ip, host: ip, ip })
    addEdge(parent, ipKey, 'resolves')
  }

  // 为 host 补齐根域名 / 子域名 / IP 层，返回挂服务的父节点。
  const provisionHost = (rawHost: string, rawIP = ''): { host: string; parent: string } => {
    const host = normalizeHost(rawHost)
    if (!host) return { host: '', parent: projectKey }

    if (isIP(host)) {
      const ipKey = `i:${host}`
      addNode({ key: ipKey, kind: 'ip', label: host, host, ip: host })
      addEdge(projectKey, ipKey, 'owns')
      return { host, parent: ipKey }
    }

    const root = rootDomain(host)
    const rootKey = `d:${root}`
    addNode({ key: rootKey, kind: 'root_domain', label: root, host: root })
    addEdge(projectKey, rootKey, 'owns')

    let parent = rootKey
    if (host !== root) {
      const subKey = `h:${host}`
      addNode({ key: subKey, kind: 'subdomain', label: host, host })
      addEdge(rootKey, subKey, 'contains')
      parent = subKey
    }

    const ip = rawIP ? normalizeHost(rawIP) : ''
    if (ip && isIP(ip)) resolveIP(parent, ip)
    return { host, parent }
  }

  const addService = (host: string, port: number) => {
    const key = `s:${host}:${port}`
    addNode({ key, kind: 'service', label: `${host}:${port}`, host, port })
    return key
  }

  const addEndpointAndRoute = (
    serviceKey: string,
    host: string,
    port: number,
    scheme: string,
    path: string,
    method: string,
    status: number,
  ) => {
    const state = status > 0 ? 'reachable' : undefined
    const endpointKey = `e:${scheme}:${host}:${port}`
    addNode({
      key: endpointKey,
      kind: 'endpoint',
      label: `${scheme}://${host}:${port}`,
      host,
      port,
      protocol: scheme,
      status_code: status || undefined,
      state,
    })
    addEdge(serviceKey, endpointKey, 'routes')

    const routePath = path || '/'
    if (routePath === '/') return
    const verb = (method || 'GET').toUpperCase()
    const routeKey = `rt:${host}:${port}:${verb}:${routePath}`
    addNode({
      key: routeKey,
      kind: 'route',
      label: `${verb} ${routePath}`,
      host,
      port,
      method: verb,
      path: routePath,
      status_code: status || undefined,
      state,
    })
    addEdge(serviceKey, routeKey, 'routes')
  }

  // 1. 子域名：domain/subdomain + 解析到的 IP
  for (const item of subdomains) {
    const host = normalizeHost(
      text(item.subdomain) || text(item.fullDomain) || text(item.domain) || text(item.host),
    )
    if (!host) continue
    const ips = strings(item.ips)
    const singleIP = text(item.ip)
    if (singleIP && !ips.includes(singleIP)) ips.push(singleIP)
    const { parent } = provisionHost(host, ips[0] ?? '')
    if (!isIP(host)) ips.forEach((ip) => resolveIP(parent, ip))
  }

  // 2. 端口：IP/host → 服务
  for (const item of ports) {
    const host = normalizeHost(text(item.host) || text(item.ip))
    const port = num(item.port)
    if (!host || port <= 0) continue
    const ip = text(item.ip)
    const { parent } = provisionHost(host, ip)
    const serviceKey = addService(host, port)
    const serviceName = [text(item.service), text(item.version)].filter(Boolean).join(' ')
    addNode({
      key: serviceKey,
      kind: 'service',
      label: `${host}:${port}`,
      host,
      port,
      protocol: text(item.protocol),
      ip: ip && isIP(normalizeHost(ip)) ? normalizeHost(ip) : undefined,
      title: serviceName || undefined,
      state: text(item.state).toLowerCase() === 'closed' ? 'lost' : 'reachable',
    })
    addEdge(parent, serviceKey, 'exposes')
  }

  // 3. Web 服务：host:port → 服务，URL 里的入口单独建节点
  for (const item of services) {
    const rawURL = text(item.url)
    const parsed = rawURL ? parseURL(rawURL) : null
    const host = normalizeHost(text(item.host)) || parsed?.host || ''
    if (!host) continue
    const scheme = parsed?.scheme || ''
    const port = num(item.port) || parsed?.port || (scheme === 'https' ? 443 : 80)
    const ip = normalizeHost(text(item.ip))
    const { parent } = provisionHost(host, ip)
    const status = num(item.status_code) || num(item.statusCode)
    const serviceKey = addService(host, port)
    addNode({
      key: serviceKey,
      kind: 'service',
      label: `${host}:${port}`,
      host,
      port,
      protocol: scheme,
      ip: ip && isIP(ip) ? ip : undefined,
      title: text(item.title) || undefined,
      status_code: status || undefined,
      tech: techList(item),
      state: status > 0 ? 'reachable' : undefined,
    })
    addEdge(parent, serviceKey, 'exposes')
    if (parsed) {
      addEndpointAndRoute(serviceKey, host, port, parsed.scheme, parsed.path, 'GET', status)
    }
  }

  // 4. URL 结果：服务 → 入口 → 路由
  for (const item of urls) {
    const parsed = parseURL(text(item.url))
    if (!parsed) continue
    const { host, scheme, port, path } = parsed
    const ip = normalizeHost(text(item.ip))
    const { parent } = provisionHost(host, ip)
    const status = num(item.status_code) || num(item.statusCode)
    const serviceKey = addService(host, port)
    addNode({
      key: serviceKey,
      kind: 'service',
      label: `${host}:${port}`,
      host,
      port,
      protocol: scheme,
      ip: ip && isIP(ip) ? ip : undefined,
      status_code: status || undefined,
      state: status > 0 ? 'reachable' : undefined,
    })
    addEdge(parent, serviceKey, 'exposes')
    addEndpointAndRoute(serviceKey, host, port, scheme, path, text(item.method) || 'GET', status)
  }

  return { nodes: [...nodes.values()], edges, truncated: false, limit: PAGE_SIZE }
}

export default function TaskTopologyView({ taskId, taskName }: TaskTopologyViewProps) {
  const queryClient = useQueryClient()

  const queryKey = (type: ResultType) => ['task-topology', taskId, type]

  // 结果页签在扫描过程中会持续增长，和项目级星图一样每 30 秒刷新。
  const subdomainsQuery = useQuery({
    queryKey: queryKey('subdomain'),
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'subdomain', pageSize: PAGE_SIZE }),
    enabled: !!taskId,
    refetchInterval: 30000,
  })
  const portsQuery = useQuery({
    queryKey: queryKey('port'),
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'port', pageSize: PAGE_SIZE }),
    enabled: !!taskId,
    refetchInterval: 30000,
  })
  const servicesQuery = useQuery({
    queryKey: queryKey('service'),
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'service', pageSize: PAGE_SIZE }),
    enabled: !!taskId,
    refetchInterval: 30000,
  })
  const urlsQuery = useQuery({
    queryKey: queryKey('url'),
    queryFn: () => resultApi.getTaskResults(taskId, { type: 'url', pageSize: PAGE_SIZE }),
    enabled: !!taskId,
    refetchInterval: 30000,
  })

  const subdomains = subdomainsQuery.data?.data.list ?? EMPTY
  const ports = portsQuery.data?.data.list ?? EMPTY
  const services = servicesQuery.data?.data.list ?? EMPTY
  const urls = urlsQuery.data?.data.list ?? EMPTY

  const totals = [
    subdomainsQuery.data?.data.total ?? 0,
    portsQuery.data?.data.total ?? 0,
    servicesQuery.data?.data.total ?? 0,
    urlsQuery.data?.data.total ?? 0,
  ]
  const truncated = totals.some((n) => n > PAGE_SIZE)

  const graph = useMemo(
    () => buildTaskGraph(taskId, taskName, subdomains, ports, services, urls),
    [taskId, taskName, subdomains, ports, services, urls],
  )

  const isLoading =
    subdomainsQuery.isLoading ||
    portsQuery.isLoading ||
    servicesQuery.isLoading ||
    urlsQuery.isLoading
  const isFetching =
    subdomainsQuery.isFetching ||
    portsQuery.isFetching ||
    servicesQuery.isFetching ||
    urlsQuery.isFetching

  const hasAny = subdomains.length + ports.length + services.length + urls.length > 0

  const graphData = useMemo<AssetGraphData>(
    () =>
      hasAny
        ? { ...graph, truncated }
        : { ...graph, nodes: [], edges: [], truncated: false },
    [graph, hasAny, truncated],
  )

  return (
    <div className="flex h-full flex-col gap-3 overflow-hidden p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm">
          任务 → 根域名 → 子域名 → IP → 服务 → 入口，左到右分层。
        </p>
        <Button
          size="small"
          onClick={() => queryClient.invalidateQueries({ queryKey: ['task-topology', taskId] })}
          disabled={isFetching}
          icon={<RefreshCw className={cn('h-4 w-4', isFetching && 'animate-spin')} />}
        >
          刷新
        </Button>
      </div>

      <AssetGraphCanvas
        className="min-h-[30rem] flex-1"
        data={isLoading ? null : graphData}
        loading={isLoading}
        rootLabel="任务"
        emptyTitle="暂无资产"
        emptyHint="本次任务还没有子域名、端口、服务或 URL 结果"
        truncatedText={`结果超过 ${PAGE_SIZE} 条，仅展示前 ${PAGE_SIZE} 条`}
        note="星图展示本次任务发现的资产层级关系，不包含漏洞信息。要看漏洞，去「漏洞」标签页。"
      />
    </div>
  )
}

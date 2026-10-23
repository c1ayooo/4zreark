import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { nodeApi, ScannerNode, NodeUpdateInput } from '@/api/nodes'
import { Button, Card, Form, Input, InputNumber, Modal, Progress, Select, Switch, Tag } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { useConfirm } from '@/components/common/confirm-provider'
import { StaggerItem } from '@/components/common/PageTransition'
import { cn, getStatusColor } from '@/lib/utils'
import { RefreshCw, HardDrive, Cpu, Database, Trash2, Settings, Plus, Copy, KeyRound, Rocket, Star } from 'lucide-react'

const STATUS_LABELS: Record<string, string> = {
  online: '在线',
  offline: '离线',
  busy: '忙碌',
  disabled: '已停用',
  error: '错误',
}

const TYPE_LABELS: Record<string, string> = {
  master: '主节点',
  worker: '工作节点',
  general: '通用节点',
  special: '专项节点',
  internal: '内网节点',
  local: '本地节点',
}

interface ConfigForm {
  name: string
  maxTasks: number
  tags: string
  enabled: boolean
}

interface EnrollForm {
  name: string
  maxTasks: number
  capabilities: string
  tags: string
}

interface DeployForm {
  host: string
  port: number
  os: 'linux' | 'windows'
  authMode: 'password' | 'key'
  username: string
  password: string
  privateKey: string
  keyPassphrase: string
  name: string
  maxTasks: number
  capabilities: string
  tags: string
  platformUrl: string
  proxy: string
  dir: string
  reverseTunnel: boolean
  relayPort: number
  tunnelPort: number
  platformPort: number
}

const splitList = (value: string) =>
  value.split(',').map((s) => s.trim()).filter(Boolean)

export default function NodesPage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<ScannerNode | null>(null)
  const [form, setForm] = useState<ConfigForm>({ name: '', maxTasks: 0, tags: '', enabled: true })
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [enrollForm, setEnrollForm] = useState<EnrollForm>({
    name: '',
    maxTasks: 5,
    capabilities: 'subdomain, port_scan, fingerprint, vuln_scan, crawler, dir_scan, sensitive',
    tags: '',
  })
  const [tokenInfo, setTokenInfo] = useState<{ title: string; token: string; hint: string } | null>(null)
  const [deployOpen, setDeployOpen] = useState(false)
  const [deployResult, setDeployResult] = useState<{ title: string; output: string } | null>(null)
  // SSH 一键部署表单：antd Form 托管，字段名与 initialValues 与原 useState 版本一致
  const [deployForm] = Form.useForm<DeployForm>()
  const deployInitialValues: DeployForm = {
    host: '',
    port: 22,
    os: 'linux',
    authMode: 'password',
    username: 'root',
    password: '',
    privateKey: '',
    keyPassphrase: '',
    name: '',
    maxTasks: 5,
    capabilities: 'subdomain, port_scan, fingerprint, vuln_scan, crawler, dir_scan, sensitive',
    tags: '',
    platformUrl: typeof window !== 'undefined' ? window.location.origin : '',
    proxy: '',
    dir: '/opt/4zreark-worker',
    reverseTunnel: true,
    relayPort: 18421,
    tunnelPort: 18080,
    platformPort: typeof window !== 'undefined'
      ? (Number(window.location.port) || (window.location.protocol === 'https:' ? 443 : 80))
      : 8080,
  }

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['nodes'],
    queryFn: () => nodeApi.getNodes({ pageSize: 100 }),
    refetchInterval: 10000,
  })

  const { data: statsData } = useQuery({
    queryKey: ['node-stats'],
    queryFn: () => nodeApi.getNodeStats(),
    refetchInterval: 10000,
  })

  // 默认扫描节点：任务没显式指定节点时用它
  const { data: defaultNode } = useQuery({
    queryKey: ['default-scan-node'],
    queryFn: () => nodeApi.getDefaultNode(),
    refetchInterval: 10000,
  })
  const defaultNodeId = defaultNode?.data?.node_id ?? ''

  const setDefaultMutation = useMutation({
    mutationFn: (nodeId: string) => nodeApi.setDefaultNode(nodeId),
    onSuccess: (_res, nodeId) => {
      toast({
        title: nodeId ? '默认扫描节点已更新' : '已清除默认扫描节点',
        description: nodeId ? '新任务未指定节点时会走该节点' : '新任务会由任意在线节点领取',
      })
      queryClient.invalidateQueries({ queryKey: ['default-scan-node'] })
    },
    onError: (err: unknown) => {
      const message =
        err && typeof err === 'object' && 'message' in err
          ? String((err as { message: unknown }).message)
          : '请稍后重试'
      toast({ title: '设置默认节点失败', description: message, variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: nodeApi.deleteNode,
    onSuccess: () => {
      toast({ title: '节点已删除' })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
      queryClient.invalidateQueries({ queryKey: ['node-stats'] })
    },
    onError: () => {
      toast({ title: '删除节点失败', variant: 'destructive' })
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: NodeUpdateInput }) => nodeApi.updateNode(id, data),
    onSuccess: () => {
      toast({ title: '节点配置已更新' })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
      queryClient.invalidateQueries({ queryKey: ['node-stats'] })
      setEditing(null)
    },
    onError: () => {
      toast({ title: '更新节点配置失败', variant: 'destructive' })
    },
  })

  const enrollMutation = useMutation({
    mutationFn: nodeApi.enrollNode,
    onSuccess: (res) => {
      setEnrollOpen(false)
      setTokenInfo({
        title: '节点密钥（只显示一次）',
        token: res.data.token,
        hint: `节点 ID: ${res.data.node_id}`,
      })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
      queryClient.invalidateQueries({ queryKey: ['node-stats'] })
    },
    onError: () => toast({ title: '创建节点失败', variant: 'destructive' }),
  })

  const rotateMutation = useMutation({
    mutationFn: nodeApi.rotateNodeToken,
    onSuccess: (res) => {
      setTokenInfo({
        title: '新节点密钥（只显示一次）',
        token: res.data.token,
        hint: '旧密钥已失效，在线连接会被断开，节点需要使用新密钥重连。',
      })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
    onError: () => toast({ title: '重置密钥失败', variant: 'destructive' }),
  })

  const revokeMutation = useMutation({
    mutationFn: nodeApi.revokeNodeToken,
    onSuccess: () => {
      toast({ title: '节点密钥已吊销，节点无法再连接平台' })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
      queryClient.invalidateQueries({ queryKey: ['node-stats'] })
      setEditing(null)
    },
    onError: () => toast({ title: '吊销密钥失败', variant: 'destructive' }),
  })

  const deployMutation = useMutation({
    mutationFn: nodeApi.deployNode,
    onSuccess: (res) => {
      setDeployOpen(false)
      setDeployResult({
        title: `部署完成 · ${res.data.name}（${res.data.host}）`,
        output: res.data.output || 'worker 已启动，等待节点上线。',
      })
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
      queryClient.invalidateQueries({ queryKey: ['node-stats'] })
      toast({ title: '节点已部署，等待连接平台' })
    },
    onError: (err: unknown) => {
      const message = err && typeof err === 'object' && 'message' in err
        ? String((err as { message: unknown }).message)
        : String(err)
      setDeployOpen(false)
      setDeployResult({ title: '部署失败', output: message })
    },
  })

  const submitDeploy = (deployValues: DeployForm) => {
    if (!deployValues.host.trim() || !deployValues.username.trim()) {
      toast({ title: '请填写 SSH 主机和用户名', variant: 'destructive' })
      return
    }
    if (deployValues.authMode === 'password' && !deployValues.password) {
      toast({ title: '请填写 SSH 密码', variant: 'destructive' })
      return
    }
    if (deployValues.authMode === 'key' && !deployValues.privateKey.trim()) {
      toast({ title: '请粘贴 SSH 私钥', variant: 'destructive' })
      return
    }
    deployMutation.mutate({
      host: deployValues.host.trim(),
      port: Number(deployValues.port) || 22,
      os: deployValues.os,
      username: deployValues.username.trim(),
      password: deployValues.authMode === 'password' ? deployValues.password : undefined,
      private_key: deployValues.authMode === 'key' ? deployValues.privateKey : undefined,
      key_passphrase: deployValues.authMode === 'key' ? deployValues.keyPassphrase : undefined,
      name: deployValues.name.trim() || deployValues.host.trim(),
      max_tasks: Number(deployValues.maxTasks) || 5,
      capabilities: splitList(deployValues.capabilities),
      tags: splitList(deployValues.tags),
      platform_url: deployValues.platformUrl.trim(),
      proxy: deployValues.proxy.trim(),
      dir: deployValues.dir.trim() || (deployValues.os === 'windows' ? 'C:\\4zreark-worker' : '/opt/4zreark-worker'),
      reverse_tunnel: deployValues.reverseTunnel,
      relay_port: Number(deployValues.relayPort) || 18421,
      tunnel_port: Number(deployValues.tunnelPort) || 18080,
      platform_port: Number(deployValues.platformPort) || 8080,
    })
  }

  const submitEnroll = () => {
    if (!enrollForm.name.trim()) {
      toast({ title: '请填写节点名称', variant: 'destructive' })
      return
    }
    enrollMutation.mutate({
      name: enrollForm.name.trim(),
      max_tasks: Number(enrollForm.maxTasks) || 5,
      capabilities: splitList(enrollForm.capabilities),
      tags: splitList(enrollForm.tags),
    })
  }

  const copyToken = async () => {
    if (!tokenInfo) return
    try {
      await navigator.clipboard.writeText(tokenInfo.token)
      toast({ title: '密钥已复制' })
    } catch {
      toast({ title: '复制失败，请手动选择复制', variant: 'destructive' })
    }
  }

  const nodes = data?.data?.list || []
  const stats = statsData?.data
  const activeCount = useMemo(
    () => (stats ? stats.online + stats.busy : 0),
    [stats]
  )

  const openConfig = (node: ScannerNode) => {
    setEditing(node)
    setForm({
      name: node.name,
      maxTasks: node.maxConcurrency,
      tags: node.tags.join(', '),
      enabled: node.status !== 'disabled',
    })
  }

  const saveConfig = () => {
    if (!editing) return
    updateMutation.mutate({
      id: editing.id,
      data: {
        name: form.name.trim() || editing.name,
        max_tasks: Number(form.maxTasks) || 0,
        tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
        status: form.enabled ? 'online' : 'disabled',
      },
    })
  }

  // 删除节点：危险操作，先确认（替代原 AlertDialog）
  const handleDeleteNode = async (node: ScannerNode) => {
    const ok = await confirm({
      title: '确认删除节点？',
      description: `确定要删除节点 "${node.name}" 吗？节点进程还活着时，下一次心跳会重新注册它；要彻底下线请先停掉对应进程。`,
      confirmText: '删除',
      cancelText: '取消',
      destructive: true,
    })
    if (ok) deleteMutation.mutate(node.id)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold">节点管理</h1>
          <p className="text-sm text-muted-foreground mt-1">
            worker 用平台签发的密钥连接，不保存数据库账号；密钥可随时重置或吊销。
          </p>
        </div>
        <div className="flex gap-2">
          <Button size="small" onClick={() => setDeployOpen(true)}>
            <Rocket className="h-4 w-4 mr-2" />
            一键部署
          </Button>
          <Button type="primary" size="small" onClick={() => setEnrollOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加节点
          </Button>
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          <Card classNames={{ body: 'flex items-center gap-2 p-3' }}>
            <HardDrive className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-lg font-semibold leading-tight">{stats.total}</p>
              <p className="text-[11px] text-muted-foreground">总节点</p>
            </div>
          </Card>
          <Card classNames={{ body: 'flex items-center gap-2 p-3' }}>
            <div className="flex h-5 w-5 items-center justify-center rounded-full bg-green-500 text-[10px] font-bold text-white">
              {activeCount}
            </div>
            <div>
              <p className="text-lg font-semibold leading-tight text-green-500">{activeCount}</p>
              <p className="text-[11px] text-muted-foreground">
                在线{stats.busy > 0 ? `（${stats.busy} 忙碌）` : ''}
              </p>
            </div>
          </Card>
          <Card classNames={{ body: 'flex items-center gap-2 p-3' }}>
            <Cpu className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-lg font-semibold leading-tight">{(stats.averageCpu ?? 0).toFixed(1)}%</p>
              <p className="text-[11px] text-muted-foreground">平均CPU</p>
            </div>
          </Card>
          <Card classNames={{ body: 'flex items-center gap-2 p-3' }}>
            <Database className="h-5 w-5 text-purple-500" />
            <div>
              <p className="text-lg font-semibold leading-tight">{(stats.averageMemory ?? 0).toFixed(1)}%</p>
              <p className="text-[11px] text-muted-foreground">平均内存</p>
            </div>
          </Card>
        </div>
      )}

      {/* Node Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
        {nodes.length === 0 ? (
          <div className="col-span-full text-center py-8 text-muted-foreground">
            暂无节点。启动一个 `role: worker` 的扫描端后会自动出现在这里。
          </div>
        ) : (
          nodes.map((node, index) => (
            <StaggerItem key={node.id} index={index}>
              <Card classNames={{ body: 'space-y-2 p-3' }}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="truncate text-sm font-semibold" title={node.capabilities.join(', ')}>
                        {node.name}
                      </p>
                      <Tag className={cn(getStatusColor(node.status), 'border-transparent px-1.5 py-0 text-[10px]')}>
                        {STATUS_LABELS[node.status] || node.status}
                      </Tag>
                    </div>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">
                      {node.ipAddress || '—'}{node.port ? `:${node.port}` : ''} · {TYPE_LABELS[node.type] || node.type}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 sm:gap-0.5">
                    <Button
                      type="text"
                      className={cn('h-11 w-11 p-0 sm:h-6 sm:w-6', defaultNodeId === node.nodeId && 'text-primary')}
                      title={defaultNodeId === node.nodeId ? '当前默认扫描节点' : '设为默认扫描节点'}
                      disabled={setDefaultMutation.isPending || defaultNodeId === node.nodeId}
                      onClick={() => setDefaultMutation.mutate(node.nodeId)}
                      icon={<Star className="h-3.5 w-3.5" />}
                    />
                    <Button
                      type="text"
                      className="h-11 w-11 p-0 sm:h-6 sm:w-6"
                      title="配置"
                      onClick={() => openConfig(node)}
                      icon={<Settings className="h-3.5 w-3.5" />}
                    />
                    <Button
                      type="text"
                      className="h-11 w-11 p-0 text-destructive sm:h-6 sm:w-6"
                      title="删除"
                      disabled={node.currentTasks > 0}
                      onClick={() => handleDeleteNode(node)}
                      icon={<Trash2 className="h-3.5 w-3.5" />}
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>
                    任务 <span className="font-medium text-foreground">{node.currentTasks}/{node.maxConcurrency}</span>
                  </span>
                  <span>CPU {node.cpuUsage.toFixed(0)}% · 内存 {node.memoryUsage.toFixed(0)}%</span>
                </div>
                <div className="flex gap-1">
                  <Progress percent={node.cpuUsage} showInfo={false} strokeWidth={4} className="m-0 flex-1" />
                  <Progress percent={node.memoryUsage} showInfo={false} strokeWidth={4} className="m-0 flex-1" />
                </div>

                <div className="flex items-center justify-between gap-2 text-[10px] text-muted-foreground">
                  <span className="truncate">
                    v{node.version || 'dev'} · 心跳 {node.lastHeartbeat ? new Date(node.lastHeartbeat).toLocaleTimeString('zh-CN') : '—'}
                  </span>
                  {node.tags.length > 0 && (
                    <div className="flex shrink-0 gap-1">
                      {node.tags.slice(0, 2).map((tag) => (
                        <Tag key={tag} className="border-transparent bg-blue-500/10 px-1.5 py-0 text-[10px] text-blue-500 hover:bg-blue-500/20">
                          {tag}
                        </Tag>
                      ))}
                      {node.tags.length > 2 && (
                        <span className="text-[10px] text-muted-foreground">+{node.tags.length - 2}</span>
                      )}
                    </div>
                  )}
                </div>
              </Card>
            </StaggerItem>
          ))
        )}
      </div>

      {/* 节点配置 */}
      <Modal
        open={!!editing}
        onCancel={() => setEditing(null)}
        title={`节点配置 · ${editing?.name}`}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setEditing(null)}>取消</Button>
            <Button type="primary" onClick={saveConfig} disabled={updateMutation.isPending}>
              保存
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">
          启用/停用与并发上限即时生效；worker 只需要平台地址和节点密钥，不需要数据库账号。
        </p>
        <div className="space-y-4 mt-4">
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="node-name">节点名称</label>
            <Input
              id="node-name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="node-max-tasks">单节点并发</label>
            <Input
              id="node-max-tasks"
              type="number"
              min={1}
              value={form.maxTasks}
              onChange={(e) => setForm((f) => ({ ...f, maxTasks: Number(e.target.value) }))}
            />
            <p className="text-xs text-muted-foreground">
              调低约 1 个心跳周期生效，不会中断正在执行的任务；调高不能超过节点启动时的
              并发容量（需重启）。节点重启后回到启动配置。
            </p>
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="node-tags">标签</label>
            <Input
              id="node-tags"
              placeholder="overseas, high-performance"
              value={form.tags}
              onChange={(e) => setForm((f) => ({ ...f, tags: e.target.value }))}
            />
            <p className="text-xs text-muted-foreground">多个标签用英文逗号分隔。</p>
          </div>
          <div className="flex items-center justify-between rounded-md border p-3">
            <div>
              <label className="text-sm font-medium">启用扫描</label>
              <p className="text-xs text-muted-foreground mt-1">
                关闭后该节点不再领取新任务，已在执行的任务会继续完成。
              </p>
            </div>
            <Switch
              checked={form.enabled}
              onChange={(checked) => setForm((f) => ({ ...f, enabled: checked }))}
            />
          </div>
          <div className="space-y-2 rounded-md border p-3">
            <label className="text-sm font-medium">节点密钥</label>
            <p className="text-xs text-muted-foreground">
              密钥只保存在 worker 侧，平台只存哈希。重置会立即断开旧连接；吊销后节点无法再连接平台。
            </p>
            <div className="flex flex-wrap gap-2">
              <Button
                size="small"
                disabled={!editing || rotateMutation.isPending}
                onClick={() => editing && rotateMutation.mutate(editing.id)}
              >
                <KeyRound className="h-4 w-4 mr-1" />
                重置密钥
              </Button>
              <Button
                size="small"
                danger
                disabled={!editing || revokeMutation.isPending}
                onClick={() => editing && revokeMutation.mutate(editing.id)}
              >
                <Trash2 className="h-4 w-4 mr-1" />
                吊销密钥
              </Button>
            </div>
          </div>
        </div>
      </Modal>

      {/* 添加节点 */}
      <Modal
        open={enrollOpen}
        onCancel={() => setEnrollOpen(false)}
        title="添加扫描节点"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setEnrollOpen(false)}>取消</Button>
            <Button type="primary" onClick={submitEnroll} disabled={enrollMutation.isPending}>
              创建并生成密钥
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">
          平台会生成节点 ID 和一次性密钥。worker 配置里只填平台地址和密钥，不需要数据库账号。
        </p>
        <div className="space-y-4 mt-4">
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="enroll-name">节点名称</label>
            <Input
              id="enroll-name"
              placeholder="worker-hk-1"
              value={enrollForm.name}
              onChange={(e) => setEnrollForm((f) => ({ ...f, name: e.target.value }))}
            />
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="enroll-max">单节点并发</label>
            <Input
              id="enroll-max"
              type="number"
              min={1}
              value={enrollForm.maxTasks}
              onChange={(e) => setEnrollForm((f) => ({ ...f, maxTasks: Number(e.target.value) }))}
            />
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="enroll-caps">能力</label>
            <Input
              id="enroll-caps"
              value={enrollForm.capabilities}
              onChange={(e) => setEnrollForm((f) => ({ ...f, capabilities: e.target.value }))}
            />
            <p className="text-xs text-muted-foreground">英文逗号分隔；留空表示全部能力。</p>
          </div>
          <div className="grid gap-2">
            <label className="text-sm font-medium" htmlFor="enroll-tags">标签</label>
            <Input
              id="enroll-tags"
              placeholder="overseas, high-performance"
              value={enrollForm.tags}
              onChange={(e) => setEnrollForm((f) => ({ ...f, tags: e.target.value }))}
            />
          </div>
        </div>
      </Modal>

      {/* 密钥展示（只显示一次） */}
      <Modal
        open={!!tokenInfo}
        onCancel={() => setTokenInfo(null)}
        title={tokenInfo?.title}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={copyToken}>
              <Copy className="h-4 w-4 mr-1" />
              复制密钥
            </Button>
            <Button type="primary" onClick={() => setTokenInfo(null)}>我已保存</Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">
          密钥只在此刻显示一次。泄露后可在节点配置里重置或吊销，旧密钥会立即失效。
        </p>
        {tokenInfo?.hint && (
          <p className="text-xs text-muted-foreground font-mono mt-3">{tokenInfo.hint}</p>
        )}
        <code className="block break-all rounded-md bg-muted p-3 text-sm mt-2">
          {tokenInfo?.token}
        </code>
        <div className="rounded-md border p-3 text-xs text-muted-foreground space-y-1 mt-3">
          <p>worker 侧配置：</p>
          <pre className="whitespace-pre-wrap font-mono">{`node:
  role: worker
  platform_url: "http://<平台地址>:8080"
  token: "${tokenInfo?.token ?? ''}"
  max_tasks: 5`}</pre>
        </div>
      </Modal>

      {/* SSH 一键部署 */}
      <Modal
        open={deployOpen}
        onCancel={() => setDeployOpen(false)}
        title="SSH 一键部署扫描节点"
        width={768}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setDeployOpen(false)}>取消</Button>
            <Button
              type="primary"
              onClick={() => deployForm.submit()}
              disabled={deployMutation.isPending}
            >
              {deployMutation.isPending ? '部署中…' : '开始部署'}
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground mb-4">
          平台会通过 SSH（密码或私钥）上传 worker 二进制和只含节点密钥的配置并启动。
          支持 Linux amd64 与 Windows；SSH 凭据只在本请求内使用，不落库、不写日志。
        </p>
        {/* getFieldsValue(true) 取整个表单 store：反连关闭等被卸载字段的值仍与旧 useState 版本一致 */}
        <Form
          form={deployForm}
          initialValues={deployInitialValues}
          onFinish={() => submitDeploy(deployForm.getFieldsValue(true) as DeployForm)}
        >
          <div className="grid gap-3 sm:grid-cols-2">
            {/* 无界面字段：仅随表单存储，保证提交时带上 platform_port */}
            <Form.Item name="platformPort" hidden className="mb-0">
              <Input />
            </Form.Item>
            <div className="grid gap-2">
              <label className="text-sm font-medium">目标系统</label>
              <Form.Item name="os" noStyle>
                <Select
                  options={[
                    { value: 'linux', label: 'Linux amd64' },
                    { value: 'windows', label: 'Windows amd64' },
                  ]}
                  onChange={(v) => {
                    const os = v as 'linux' | 'windows'
                    const dir = deployForm.getFieldValue('dir') as string
                    deployForm.setFieldsValue({
                      username: os === 'windows' ? 'Administrator' : 'root',
                      reverseTunnel: os === 'windows' ? false : deployForm.getFieldValue('reverseTunnel'),
                      dir: dir === '/opt/4zreark-worker' || dir === 'C:\\4zreark-worker'
                        ? (os === 'windows' ? 'C:\\4zreark-worker' : '/opt/4zreark-worker')
                        : dir,
                    })
                  }}
                />
              </Form.Item>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium">SSH 认证方式</label>
              <Form.Item name="authMode" noStyle>
                <Select
                  options={[
                    { value: 'password', label: '密码' },
                    { value: 'key', label: '私钥' },
                  ]}
                />
              </Form.Item>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="deploy-host">SSH 主机</label>
              <Form.Item name="host" noStyle>
                <Input id="deploy-host" placeholder="1.2.3.4 或 node.example.com" />
              </Form.Item>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="deploy-port">SSH 端口</label>
              <Form.Item name="port" noStyle>
                <InputNumber id="deploy-port" className="w-full" />
              </Form.Item>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="deploy-user">SSH 用户名</label>
              <Form.Item name="username" noStyle>
                <Input id="deploy-user" placeholder="root / Administrator" />
              </Form.Item>
            </div>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="deploy-name">节点名称</label>
              <Form.Item name="name" noStyle>
                <Input id="deploy-name" placeholder="留空则使用 SSH 主机名" />
              </Form.Item>
            </div>
            {/* 认证方式切换：密码 / 私钥 二选一 */}
            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.authMode !== cur.authMode}>
              {({ getFieldValue }) =>
                getFieldValue('authMode') === 'password' ? (
                  <div className="grid gap-2 sm:col-span-2">
                    <label className="text-sm font-medium" htmlFor="deploy-pass">SSH 密码</label>
                    <Form.Item name="password" noStyle>
                      <Input id="deploy-pass" type="password" placeholder="仅本次请求使用" />
                    </Form.Item>
                  </div>
                ) : (
                  <>
                    <div className="grid gap-2 sm:col-span-2">
                      <label className="text-sm font-medium" htmlFor="deploy-key">SSH 私钥</label>
                      <Form.Item name="privateKey" noStyle>
                        <Input.TextArea
                          id="deploy-key"
                          className="min-h-[110px] font-mono text-xs"
                          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                        />
                      </Form.Item>
                    </div>
                    <div className="grid gap-2 sm:col-span-2">
                      <label className="text-sm font-medium" htmlFor="deploy-key-pass">私钥口令（可选）</label>
                      <Form.Item name="keyPassphrase" noStyle>
                        <Input id="deploy-key-pass" type="password" />
                      </Form.Item>
                    </div>
                  </>
                )
              }
            </Form.Item>
            <div className="grid gap-2">
              <label className="text-sm font-medium" htmlFor="deploy-max">单节点并发</label>
              <Form.Item name="maxTasks" noStyle>
                <InputNumber id="deploy-max" min={1} className="w-full" />
              </Form.Item>
            </div>
            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.reverseTunnel !== cur.reverseTunnel}>
              {({ getFieldValue }) => (
                <div className="grid gap-2 sm:col-span-2">
                  <label className="text-sm font-medium" htmlFor="deploy-platform">平台地址（用于推导节点网关主机）</label>
                  <Form.Item name="platformUrl" noStyle>
                    <Input
                      id="deploy-platform"
                      placeholder="https://master.example.com"
                      disabled={getFieldValue('reverseTunnel')}
                    />
                  </Form.Item>
                  <p className="text-xs text-muted-foreground">
                    {getFieldValue('reverseTunnel')
                      ? 'rem 反连开启时忽略；worker 会走 https://127.0.0.1:<隧道端口> 到独立 TLS 节点网关。'
                      : 'worker 会连接 https://<该主机>:9443 的独立 TLS 节点网关，不再使用 Web 端口 8080。'}
                  </p>
                </div>
              )}
            </Form.Item>
            <div className="grid gap-2 sm:col-span-2">
              <label className="text-sm font-medium" htmlFor="deploy-proxy">代理（可选）</label>
              <Form.Item name="proxy" noStyle>
                <Input id="deploy-proxy" placeholder="socks5://user:pass@relay:1080 或 http://relay:8080" />
              </Form.Item>
              <p className="text-xs text-muted-foreground">
                目标机不能直连平台时，可填 SOCKS5/HTTP 代理；代理服务器需要能访问平台。
              </p>
            </div>
            <div className="grid gap-3 rounded-md border p-3 sm:col-span-2">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium">自动 rem 反连（推荐）</label>
                  <p className="text-xs text-muted-foreground mt-1">
                    默认开启：平台自动在目标机启动 rem 服务端、在本机启动反向转发客户端，
                    worker 通过 127.0.0.1 隧道连平台。只需填写上面的 SSH 主机/用户名/密码（或私钥）。
                    仅支持 Linux 目标机。
                  </p>
                </div>
                <Form.Item name="reverseTunnel" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
              </div>
              <Form.Item noStyle shouldUpdate={(prev, cur) => prev.reverseTunnel !== cur.reverseTunnel}>
                {({ getFieldValue }) =>
                  getFieldValue('reverseTunnel') ? (
                    <div className="grid gap-3 sm:grid-cols-2">
                      <div className="grid gap-2">
                        <label className="text-sm font-medium" htmlFor="rem-relay-port">relay 端口（目标机公网）</label>
                        <Form.Item name="relayPort" noStyle>
                          <InputNumber id="rem-relay-port" className="w-full" />
                        </Form.Item>
                      </div>
                      <div className="grid gap-2">
                        <label className="text-sm font-medium" htmlFor="rem-tunnel-port">隧道端口（目标机回环）</label>
                        <Form.Item name="tunnelPort" noStyle>
                          <InputNumber id="rem-tunnel-port" className="w-full" />
                        </Form.Item>
                      </div>
                      <p className="text-xs text-muted-foreground sm:col-span-2">
                        目标机没有 rem 时平台自动上传（约 3MB，由工具运行时管理）。relay 端口需允许平台访问；
                        隧道端口只绑定 127.0.0.1，并转发到节点网关 TLS 端口 9443（不是 Web 8080）。
                      </p>
                    </div>
                  ) : null
                }
              </Form.Item>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <label className="text-sm font-medium" htmlFor="deploy-dir">安装目录</label>
              <Form.Item name="dir" noStyle>
                <Input id="deploy-dir" />
              </Form.Item>
              <p className="text-xs text-muted-foreground">
                Windows 示例：C:\4zreark-worker；Linux 示例：/opt/4zreark-worker。
              </p>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <label className="text-sm font-medium" htmlFor="deploy-caps">能力</label>
              <Form.Item name="capabilities" noStyle>
                <Input id="deploy-caps" />
              </Form.Item>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <label className="text-sm font-medium" htmlFor="deploy-tags">标签</label>
              <Form.Item name="tags" noStyle>
                <Input id="deploy-tags" placeholder="overseas, high-performance" />
              </Form.Item>
            </div>
          </div>
        </Form>
        <p className="text-xs text-muted-foreground mt-3">
          注意：默认不校验 SSH host key；Windows 需要先把 worker-windows-amd64.exe 放到 server 同目录
          或配置 node.windows_binary。目标机需要已有扫描工具/字典（一键部署只传二进制和节点配置）。
        </p>
      </Modal>

      {/* 部署结果 */}
      <Modal
        open={!!deployResult}
        onCancel={() => setDeployResult(null)}
        title={deployResult?.title}
        width={768}
        footer={
          <div className="flex justify-end gap-2">
            <Button type="primary" onClick={() => setDeployResult(null)}>关闭</Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground mb-3">安装目录和启动日志见下方。</p>
        <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">
          {deployResult?.output}
        </pre>
      </Modal>
    </div>
  )
}

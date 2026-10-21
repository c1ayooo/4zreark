import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { nodeApi, ScannerNode, NodeUpdateInput } from '@/api/nodes'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { cn, getStatusColor } from '@/lib/utils'
import { RefreshCw, HardDrive, Cpu, Database, Trash2, Settings, Plus, Copy, KeyRound, Rocket, Star } from 'lucide-react'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

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
  gostReverse: boolean
  gostRelayPort: number
  gostTunnelPort: number
  gostUser: string
  gostPass: string
  platformPort: number
}

const splitList = (value: string) =>
  value.split(',').map((s) => s.trim()).filter(Boolean)

export default function NodesPage() {
  const { toast } = useToast()
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
  const [deployForm, setDeployForm] = useState<DeployForm>({
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
    gostReverse: true,
    gostRelayPort: 18421,
    gostTunnelPort: 18080,
    gostUser: '',
    gostPass: '',
    platformPort: typeof window !== 'undefined'
      ? (Number(window.location.port) || (window.location.protocol === 'https:' ? 443 : 80))
      : 8080,
  })

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

  const submitDeploy = () => {
    if (!deployForm.host.trim() || !deployForm.username.trim()) {
      toast({ title: '请填写 SSH 主机和用户名', variant: 'destructive' })
      return
    }
    if (deployForm.authMode === 'password' && !deployForm.password) {
      toast({ title: '请填写 SSH 密码', variant: 'destructive' })
      return
    }
    if (deployForm.authMode === 'key' && !deployForm.privateKey.trim()) {
      toast({ title: '请粘贴 SSH 私钥', variant: 'destructive' })
      return
    }
    deployMutation.mutate({
      host: deployForm.host.trim(),
      port: Number(deployForm.port) || 22,
      os: deployForm.os,
      username: deployForm.username.trim(),
      password: deployForm.authMode === 'password' ? deployForm.password : undefined,
      private_key: deployForm.authMode === 'key' ? deployForm.privateKey : undefined,
      key_passphrase: deployForm.authMode === 'key' ? deployForm.keyPassphrase : undefined,
      name: deployForm.name.trim() || deployForm.host.trim(),
      max_tasks: Number(deployForm.maxTasks) || 5,
      capabilities: splitList(deployForm.capabilities),
      tags: splitList(deployForm.tags),
      platform_url: deployForm.platformUrl.trim(),
      proxy: deployForm.proxy.trim(),
      dir: deployForm.dir.trim() || (deployForm.os === 'windows' ? 'C:\\4zreark-worker' : '/opt/4zreark-worker'),
      gost_reverse: deployForm.gostReverse,
      gost_relay_port: Number(deployForm.gostRelayPort) || 18421,
      gost_tunnel_port: Number(deployForm.gostTunnelPort) || 18080,
      gost_user: deployForm.gostUser.trim(),
      gost_pass: deployForm.gostPass,
      platform_port: Number(deployForm.platformPort) || 8080,
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
          <Button size="sm" variant="outline" onClick={() => setDeployOpen(true)}>
            <Rocket className="h-4 w-4 mr-2" />
            一键部署
          </Button>
          <Button size="sm" onClick={() => setEnrollOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加节点
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
        </div>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
          <Card>
            <CardContent className="flex items-center gap-2 p-3">
              <HardDrive className="h-5 w-5 text-muted-foreground" />
              <div>
                <p className="text-lg font-semibold leading-tight">{stats.total}</p>
                <p className="text-[11px] text-muted-foreground">总节点</p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="flex items-center gap-2 p-3">
              <div className="flex h-5 w-5 items-center justify-center rounded-full bg-green-500 text-[10px] font-bold text-white">
                {activeCount}
              </div>
              <div>
                <p className="text-lg font-semibold leading-tight text-green-500">{activeCount}</p>
                <p className="text-[11px] text-muted-foreground">
                  在线{stats.busy > 0 ? `（${stats.busy} 忙碌）` : ''}
                </p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="flex items-center gap-2 p-3">
              <Cpu className="h-5 w-5 text-blue-500" />
              <div>
                <p className="text-lg font-semibold leading-tight">{(stats.averageCpu ?? 0).toFixed(1)}%</p>
                <p className="text-[11px] text-muted-foreground">平均CPU</p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="flex items-center gap-2 p-3">
              <Database className="h-5 w-5 text-purple-500" />
              <div>
                <p className="text-lg font-semibold leading-tight">{(stats.averageMemory ?? 0).toFixed(1)}%</p>
                <p className="text-[11px] text-muted-foreground">平均内存</p>
              </div>
            </CardContent>
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
          nodes.map((node) => (
            <Card key={node.id}>
              <CardContent className="space-y-2 p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <p className="truncate text-sm font-semibold" title={node.capabilities.join(', ')}>
                        {node.name}
                      </p>
                      <Badge className={cn(getStatusColor(node.status), 'px-1.5 py-0 text-[10px]')}>
                        {STATUS_LABELS[node.status] || node.status}
                      </Badge>
                    </div>
                    <p className="truncate font-mono text-[11px] text-muted-foreground">
                      {node.ipAddress || '—'}{node.port ? `:${node.port}` : ''} · {TYPE_LABELS[node.type] || node.type}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2 sm:gap-0.5">
                    <Button
                      variant="ghost"
                      size="icon"
                      className={cn('h-11 w-11 sm:h-6 sm:w-6', defaultNodeId === node.nodeId && 'text-primary')}
                      title={defaultNodeId === node.nodeId ? '当前默认扫描节点' : '设为默认扫描节点'}
                      disabled={setDefaultMutation.isPending || defaultNodeId === node.nodeId}
                      onClick={() => setDefaultMutation.mutate(node.nodeId)}
                    >
                      <Star className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-11 w-11 sm:h-6 sm:w-6"
                      title="配置"
                      onClick={() => openConfig(node)}
                    >
                      <Settings className="h-3.5 w-3.5" />
                    </Button>
                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-11 w-11 text-destructive hover:text-destructive sm:h-6 sm:w-6"
                          title="删除"
                          disabled={node.currentTasks > 0}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent>
                        <AlertDialogHeader>
                          <AlertDialogTitle>确认删除节点？</AlertDialogTitle>
                          <AlertDialogDescription>
                            确定要删除节点 "{node.name}" 吗？节点进程还活着时，下一次心跳会重新注册它；
                            要彻底下线请先停掉对应进程。
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel>取消</AlertDialogCancel>
                          <AlertDialogAction
                            onClick={() => deleteMutation.mutate(node.id)}
                            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                          >
                            删除
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>
                    任务 <span className="font-medium text-foreground">{node.currentTasks}/{node.maxConcurrency}</span>
                  </span>
                  <span>CPU {node.cpuUsage.toFixed(0)}% · 内存 {node.memoryUsage.toFixed(0)}%</span>
                </div>
                <div className="flex gap-1">
                  <Progress value={node.cpuUsage} className="h-1 flex-1" />
                  <Progress value={node.memoryUsage} className="h-1 flex-1" />
                </div>

                <div className="flex items-center justify-between gap-2 text-[10px] text-muted-foreground">
                  <span className="truncate">
                    v{node.version || 'dev'} · 心跳 {node.lastHeartbeat ? new Date(node.lastHeartbeat).toLocaleTimeString('zh-CN') : '—'}
                  </span>
                  {node.tags.length > 0 && (
                    <div className="flex shrink-0 gap-1">
                      {node.tags.slice(0, 2).map((tag) => (
                        <Badge key={tag} className="bg-blue-500/10 px-1.5 py-0 text-[10px] text-blue-500 hover:bg-blue-500/20">
                          {tag}
                        </Badge>
                      ))}
                      {node.tags.length > 2 && (
                        <span className="text-[10px] text-muted-foreground">+{node.tags.length - 2}</span>
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {/* 节点配置 */}
      <Dialog open={!!editing} onOpenChange={(open) => !open && setEditing(null)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>节点配置 · {editing?.name}</DialogTitle>
            <DialogDescription>
              启用/停用与并发上限即时生效；worker 只需要平台地址和节点密钥，不需要数据库账号。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="node-name">节点名称</Label>
              <Input
                id="node-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="node-max-tasks">单节点并发</Label>
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
              <Label htmlFor="node-tags">标签</Label>
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
                <Label>启用扫描</Label>
                <p className="text-xs text-muted-foreground mt-1">
                  关闭后该节点不再领取新任务，已在执行的任务会继续完成。
                </p>
              </div>
              <Switch
                checked={form.enabled}
                onCheckedChange={(checked) => setForm((f) => ({ ...f, enabled: checked }))}
              />
            </div>
            <div className="space-y-2 rounded-md border p-3">
              <Label>节点密钥</Label>
              <p className="text-xs text-muted-foreground">
                密钥只保存在 worker 侧，平台只存哈希。重置会立即断开旧连接；吊销后节点无法再连接平台。
              </p>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!editing || rotateMutation.isPending}
                  onClick={() => editing && rotateMutation.mutate(editing.id)}
                >
                  <KeyRound className="h-4 w-4 mr-1" />
                  重置密钥
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  disabled={!editing || revokeMutation.isPending}
                  onClick={() => editing && revokeMutation.mutate(editing.id)}
                >
                  <Trash2 className="h-4 w-4 mr-1" />
                  吊销密钥
                </Button>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)}>
              取消
            </Button>
            <Button onClick={saveConfig} disabled={updateMutation.isPending}>
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 添加节点 */}
      <Dialog open={enrollOpen} onOpenChange={setEnrollOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>添加扫描节点</DialogTitle>
            <DialogDescription>
              平台会生成节点 ID 和一次性密钥。worker 配置里只填平台地址和密钥，不需要数据库账号。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="grid gap-2">
              <Label htmlFor="enroll-name">节点名称</Label>
              <Input
                id="enroll-name"
                placeholder="worker-hk-1"
                value={enrollForm.name}
                onChange={(e) => setEnrollForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="enroll-max">单节点并发</Label>
              <Input
                id="enroll-max"
                type="number"
                min={1}
                value={enrollForm.maxTasks}
                onChange={(e) => setEnrollForm((f) => ({ ...f, maxTasks: Number(e.target.value) }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="enroll-caps">能力</Label>
              <Input
                id="enroll-caps"
                value={enrollForm.capabilities}
                onChange={(e) => setEnrollForm((f) => ({ ...f, capabilities: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">英文逗号分隔；留空表示全部能力。</p>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="enroll-tags">标签</Label>
              <Input
                id="enroll-tags"
                placeholder="overseas, high-performance"
                value={enrollForm.tags}
                onChange={(e) => setEnrollForm((f) => ({ ...f, tags: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEnrollOpen(false)}>
              取消
            </Button>
            <Button onClick={submitEnroll} disabled={enrollMutation.isPending}>
              创建并生成密钥
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 密钥展示（只显示一次） */}
      <Dialog open={!!tokenInfo} onOpenChange={(open) => !open && setTokenInfo(null)}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{tokenInfo?.title}</DialogTitle>
            <DialogDescription>
              密钥只在此刻显示一次。泄露后可在节点配置里重置或吊销，旧密钥会立即失效。
            </DialogDescription>
          </DialogHeader>
          {tokenInfo?.hint && (
            <p className="text-xs text-muted-foreground font-mono">{tokenInfo.hint}</p>
          )}
          <code className="block break-all rounded-md bg-muted p-3 text-sm">
            {tokenInfo?.token}
          </code>
          <div className="rounded-md border p-3 text-xs text-muted-foreground space-y-1">
            <p>worker 侧配置：</p>
            <pre className="whitespace-pre-wrap font-mono">{`node:
  role: worker
  platform_url: "http://<平台地址>:8080"
  token: "${tokenInfo?.token ?? ''}"
  max_tasks: 5`}</pre>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={copyToken}>
              <Copy className="h-4 w-4 mr-1" />
              复制密钥
            </Button>
            <Button onClick={() => setTokenInfo(null)}>我已保存</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* SSH 一键部署 */}
      <Dialog open={deployOpen} onOpenChange={setDeployOpen}>
        <DialogContent className="max-h-[90vh] w-[calc(100vw-2rem)] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>SSH 一键部署扫描节点</DialogTitle>
            <DialogDescription>
              平台会通过 SSH（密码或私钥）上传 worker 二进制和只含节点密钥的配置并启动。
              支持 Linux amd64 与 Windows；SSH 凭据只在本请求内使用，不落库、不写日志。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label>目标系统</Label>
              <Select
                value={deployForm.os}
                onValueChange={(v) => setDeployForm((f) => ({
                  ...f,
                  os: v as 'linux' | 'windows',
                  username: v === 'windows' ? 'Administrator' : 'root',
                  gostReverse: v === 'windows' ? false : f.gostReverse,
                  dir: f.dir === '/opt/4zreark-worker' || f.dir === 'C:\\4zreark-worker'
                    ? (v === 'windows' ? 'C:\\4zreark-worker' : '/opt/4zreark-worker')
                    : f.dir,
                }))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="linux">Linux amd64</SelectItem>
                  <SelectItem value="windows">Windows amd64</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label>SSH 认证方式</Label>
              <Select
                value={deployForm.authMode}
                onValueChange={(v) => setDeployForm((f) => ({ ...f, authMode: v as 'password' | 'key' }))}
              >
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="password">密码</SelectItem>
                  <SelectItem value="key">私钥</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="deploy-host">SSH 主机</Label>
              <Input
                id="deploy-host"
                placeholder="1.2.3.4 或 node.example.com"
                value={deployForm.host}
                onChange={(e) => setDeployForm((f) => ({ ...f, host: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="deploy-port">SSH 端口</Label>
              <Input
                id="deploy-port"
                type="number"
                value={deployForm.port}
                onChange={(e) => setDeployForm((f) => ({ ...f, port: Number(e.target.value) }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="deploy-user">SSH 用户名</Label>
              <Input
                id="deploy-user"
                placeholder="root / Administrator"
                value={deployForm.username}
                onChange={(e) => setDeployForm((f) => ({ ...f, username: e.target.value }))}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="deploy-name">节点名称</Label>
              <Input
                id="deploy-name"
                placeholder="留空则使用 SSH 主机名"
                value={deployForm.name}
                onChange={(e) => setDeployForm((f) => ({ ...f, name: e.target.value }))}
              />
            </div>
            {deployForm.authMode === 'password' ? (
              <div className="grid gap-2 sm:col-span-2">
                <Label htmlFor="deploy-pass">SSH 密码</Label>
                <Input
                  id="deploy-pass"
                  type="password"
                  placeholder="仅本次请求使用"
                  value={deployForm.password}
                  onChange={(e) => setDeployForm((f) => ({ ...f, password: e.target.value }))}
                />
              </div>
            ) : (
              <>
                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="deploy-key">SSH 私钥</Label>
                  <Textarea
                    id="deploy-key"
                    className="min-h-[110px] font-mono text-xs"
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                    value={deployForm.privateKey}
                    onChange={(e) => setDeployForm((f) => ({ ...f, privateKey: e.target.value }))}
                  />
                </div>
                <div className="grid gap-2 sm:col-span-2">
                  <Label htmlFor="deploy-key-pass">私钥口令（可选）</Label>
                  <Input
                    id="deploy-key-pass"
                    type="password"
                    value={deployForm.keyPassphrase}
                    onChange={(e) => setDeployForm((f) => ({ ...f, keyPassphrase: e.target.value }))}
                  />
                </div>
              </>
            )}
            <div className="grid gap-2">
              <Label htmlFor="deploy-max">单节点并发</Label>
              <Input
                id="deploy-max"
                type="number"
                min={1}
                value={deployForm.maxTasks}
                onChange={(e) => setDeployForm((f) => ({ ...f, maxTasks: Number(e.target.value) }))}
              />
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="deploy-platform">平台地址（用于推导节点网关主机）</Label>
              <Input
                id="deploy-platform"
                placeholder="https://master.example.com"
                value={deployForm.platformUrl}
                disabled={deployForm.gostReverse}
                onChange={(e) => setDeployForm((f) => ({ ...f, platformUrl: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                {deployForm.gostReverse
                  ? 'gost 反连开启时忽略；worker 会走 https://127.0.0.1:<隧道端口> 到独立 TLS 节点网关。'
                  : 'worker 会连接 https://<该主机>:9443 的独立 TLS 节点网关，不再使用 Web 端口 8080。'}
              </p>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="deploy-proxy">代理（可选）</Label>
              <Input
                id="deploy-proxy"
                placeholder="socks5://user:pass@relay:1080 或 http://relay:8080"
                value={deployForm.proxy}
                onChange={(e) => setDeployForm((f) => ({ ...f, proxy: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                目标机不能直连平台时，可填 gost 等提供的 SOCKS5/HTTP 代理；代理服务器需要能访问平台。
              </p>
            </div>
            <div className="grid gap-3 rounded-md border p-3 sm:col-span-2">
              <div className="flex items-center justify-between">
                <div>
                  <Label>自动 gost 反连（推荐）</Label>
                  <p className="text-xs text-muted-foreground mt-1">
                    默认开启：平台自动在目标机启动 gost relay、在本机启动 rtcp 客户端，
                    worker 通过 127.0.0.1 隧道连平台。只需填写上面的 SSH 主机/用户名/密码（或私钥）。
                    仅支持 Linux 目标机。
                  </p>
                </div>
                <Switch
                  checked={deployForm.gostReverse}
                  onCheckedChange={(checked) => setDeployForm((f) => ({ ...f, gostReverse: checked }))}
                />
              </div>
              {deployForm.gostReverse && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <div className="grid gap-2">
                    <Label htmlFor="gost-relay-port">relay 端口（目标机公网）</Label>
                    <Input
                      id="gost-relay-port"
                      type="number"
                      value={deployForm.gostRelayPort}
                      onChange={(e) => setDeployForm((f) => ({ ...f, gostRelayPort: Number(e.target.value) }))}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="gost-tunnel-port">隧道端口（目标机回环）</Label>
                    <Input
                      id="gost-tunnel-port"
                      type="number"
                      value={deployForm.gostTunnelPort}
                      onChange={(e) => setDeployForm((f) => ({ ...f, gostTunnelPort: Number(e.target.value) }))}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="gost-user">relay 认证（可选）</Label>
                    <Input
                      id="gost-user"
                      placeholder="留空自动生成"
                      value={deployForm.gostUser}
                      onChange={(e) => setDeployForm((f) => ({ ...f, gostUser: e.target.value }))}
                    />
                  </div>
                  <div className="grid gap-2 sm:col-span-2">
                    <Label htmlFor="gost-pass">relay 密码（可选）</Label>
                    <Input
                      id="gost-pass"
                      type="password"
                      placeholder="留空自动生成"
                      value={deployForm.gostPass}
                      onChange={(e) => setDeployForm((f) => ({ ...f, gostPass: e.target.value }))}
                    />
                  </div>
                  <p className="text-xs text-muted-foreground sm:col-span-2">
                    目标机需要已有 gost，或平台侧有 gost 二进制可自动上传。relay 端口需允许平台访问；
                    隧道端口只绑定 127.0.0.1，并转发到节点网关 TLS 端口 9443（不是 Web 8080）。
                  </p>
                </div>
              )}
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="deploy-dir">安装目录</Label>
              <Input
                id="deploy-dir"
                value={deployForm.dir}
                onChange={(e) => setDeployForm((f) => ({ ...f, dir: e.target.value }))}
              />
              <p className="text-xs text-muted-foreground">
                Windows 示例：C:\4zreark-worker；Linux 示例：/opt/4zreark-worker。
              </p>
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="deploy-caps">能力</Label>
              <Input
                id="deploy-caps"
                value={deployForm.capabilities}
                onChange={(e) => setDeployForm((f) => ({ ...f, capabilities: e.target.value }))}
              />
            </div>
            <div className="grid gap-2 sm:col-span-2">
              <Label htmlFor="deploy-tags">标签</Label>
              <Input
                id="deploy-tags"
                placeholder="overseas, high-performance"
                value={deployForm.tags}
                onChange={(e) => setDeployForm((f) => ({ ...f, tags: e.target.value }))}
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            注意：默认不校验 SSH host key；Windows 需要先把 worker-windows-amd64.exe 放到 server 同目录
            或配置 node.windows_binary。目标机需要已有扫描工具/字典（一键部署只传二进制和节点配置）。
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeployOpen(false)}>
              取消
            </Button>
            <Button onClick={submitDeploy} disabled={deployMutation.isPending}>
              {deployMutation.isPending ? '部署中…' : '开始部署'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 部署结果 */}
      <Dialog open={!!deployResult} onOpenChange={(open) => !open && setDeployResult(null)}>
        <DialogContent className="max-h-[90vh] w-[calc(100vw-2rem)] max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{deployResult?.title}</DialogTitle>
            <DialogDescription>安装目录和启动日志见下方。</DialogDescription>
          </DialogHeader>
          <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">
            {deployResult?.output}
          </pre>
          <DialogFooter>
            <Button onClick={() => setDeployResult(null)}>关闭</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

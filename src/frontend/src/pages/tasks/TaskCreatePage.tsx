import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { taskApi, TaskConfig } from '@/api/tasks'
import { assetApi } from '@/api/assets'
import { dictionaryApi } from '@/api/sources'
import { nodeApi } from '@/api/nodes'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { X, Plus, Play } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

const scanTypes = [
  { id: 'port_scan', label: '端口扫描', description: '扫描开放端口' },
  { id: 'service_detect', label: '服务识别', description: '真实协议握手识别服务类型和版本' },
  { id: 'exposure_scan', label: '暴露面探测', description: '无凭据探测 Redis/ES/FTP 等匿名暴露' },
  { id: 'clue_hunt', label: '存量线索', description: 'Wayback 遗留端点 / CDN 源站 / 云资源 / SaaS' },
  { id: 'vuln_scan', label: '漏洞扫描', description: '检测已知漏洞' },
  { id: 'fingerprint', label: '指纹识别', description: '识别目标指纹' },
  { id: 'subdomain', label: '子域名枚举', description: '发现子域名' },
  { id: 'takeover', label: '子域名接管', description: '检测子域名接管漏洞' },
  { id: 'crawler', label: 'Web爬虫', description: '爬取网站URL和接口' },
  { id: 'dir_scan', label: '目录扫描', description: '扫描敏感目录' },
]

// 检测目标类型
function detectTargetType(target: string): string {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) return 'ip'
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) return 'cidr'
  if (/^https?:\/\//.test(target)) return 'url'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(target)) return 'domain'
  return 'unknown'
}

interface TaskCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** 从项目详情进入时预选归属项目 */
  initialProjectId?: number
}

export function TaskCreateDialog({ open, onOpenChange, initialProjectId }: TaskCreateDialogProps) {
  const navigate = useNavigate()
  const { toast } = useToast()

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    config: {
      scanTypes: ['subdomain', 'port_scan', 'fingerprint'],
      port_scan_mode: 'quick',
      timeout: 30,
      concurrent: 10,
    } as TaskConfig,
  })

  const [directTargets, setDirectTargets] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState('')
  // 归属项目：扫描结果自动并入该项目的资产（sites/raw_records）
  const [projectId, setProjectId] = useState(initialProjectId ?? 0)
  // 扫描节点：空 = 跟随默认节点（后端解析），填 node_id = 指定节点
  const [nodeId, setNodeId] = useState('')

  const { data: projectsRes } = useQuery({
    queryKey: ['projects'],
    queryFn: () => assetApi.projects(),
  })
  const projects = projectsRes?.data ?? []

  const subDicts = useQuery({
    queryKey: ['task-dicts', 'subdomain'],
    queryFn: () => dictionaryApi.list({ type: 'subdomain', page: 1, page_size: 100 }),
  })
  const dirDicts = useQuery({
    queryKey: ['task-dicts', 'directory'],
    queryFn: () => dictionaryApi.list({ type: 'directory', page: 1, page_size: 100 }),
  })
  const subDictList = subDicts.data?.data ?? []
  const dirDictList = dirDicts.data?.data ?? []
  const nodes = useQuery({
    queryKey: ['scan-nodes-options'],
    queryFn: () => nodeApi.getNodes({ page: 1, pageSize: 100 }),
  })
  const defaultNode = useQuery({
    queryKey: ['default-scan-node'],
    queryFn: () => nodeApi.getDefaultNode(),
  })
  const nodeOptions = nodes.data?.data.list ?? []

  const createMutation = useMutation({
    mutationFn: taskApi.createTask,
    onSuccess: () => {
      toast({ title: '任务创建成功' })
      onOpenChange(false)
      navigate('/tasks')
    },
    onError: (error: Error) => {
      toast({ title: '创建失败', description: error.message, variant: 'destructive' })
    },
  })

  const getTaskType = (scanTypes: string[]): string => {
    if (scanTypes.length === 0) return 'port_scan'
    if (scanTypes.length === 1) return scanTypes[0]
    return 'custom'
  }

  const addDirectTargets = () => {
    if (!targetInput.trim()) return
    const newTargets = targetInput.split(/[\n,\s]+/).map(t => t.trim()).filter(t => t.length > 0)
    const uniqueTargets = [...new Set([...directTargets, ...newTargets])]
    setDirectTargets(uniqueTargets)
    setTargetInput('')
  }

  const handleSubmit = () => {
    if (!formData.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'destructive' })
      return
    }
    if (!projectId) {
      toast({ title: '请选择归属项目', description: '扫描结果会并入该项目的资产', variant: 'destructive' })
      return
    }
    if (directTargets.length === 0) {
      toast({ title: '请输入至少一个扫描目标', variant: 'destructive' })
      return
    }
    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' })
      return
    }
    // 服务识别 / 暴露面探测是独立任务类型，暂不支持与其他扫描阶段组合
    const exclusive = ['service_detect', 'exposure_scan', 'clue_hunt']
    const selected = formData.config.scanTypes || []
    if (selected.some((t) => exclusive.includes(t)) && selected.length > 1) {
      toast({
        title: '服务识别 / 暴露面探测 / 存量线索需单独创建任务',
        description: '这些任务不含端口扫描、爬虫等阶段，请只勾选其中一项',
        variant: 'destructive',
      })
      return
    }

    const types = [...new Set(directTargets.map(detectTargetType))]
    const targetType = types.length === 1 ? types[0] : 'mixed'
    const taskType = getTaskType(formData.config.scanTypes || [])

    createMutation.mutate({
      name: formData.name,
      projectId,
      type: taskType,
      targets: directTargets,
      targetType: targetType,
      description: formData.description,
      config: formData.config,
      nodeId: nodeId || undefined,
    })
  }

  const toggleScanType = (scanTypeId: string) => {
    const current = formData.config.scanTypes || []
    const newTypes = current.includes(scanTypeId)
      ? current.filter((t) => t !== scanTypeId)
      : [...current, scanTypeId]
    setFormData({
      ...formData,
      config: { ...formData.config, scanTypes: newTypes },
    })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>创建扫描任务</DialogTitle>
        </DialogHeader>

        <div className="space-y-5 py-2">
          {/* 任务名称 */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>任务名称 *</Label>
              <Input
                placeholder="输入任务名称"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>任务描述</Label>
              <Input
                placeholder="可选"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>
          </div>

          {/* 归属项目：扫描结果自动并入该项目资产 */}
          <div className="space-y-2">
            <Label>归属项目 *</Label>
            <Select
              value={projectId ? String(projectId) : ''}
              onValueChange={(v) => setProjectId(Number(v))}
            >
              <SelectTrigger>
                <SelectValue placeholder="选择项目" />
              </SelectTrigger>
              <SelectContent>
                {projects.map((p) => (
                  <SelectItem key={p.id} value={String(p.id)}>
                    {p.name}（{p.code}）
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              扫描发现的子域、服务会自动归并到该项目的资产里
            </p>
          </div>

          {/* 扫描节点：不选 = 使用系统默认节点 */}
          <div className="space-y-2">
            <Label>扫描节点</Label>
            <Select
              value={nodeId || 'default'}
              onValueChange={(v) => setNodeId(v === 'default' ? '' : v)}
            >
              <SelectTrigger>
                <SelectValue placeholder="默认节点" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="default">
                  默认节点
                  {defaultNode.data?.data?.node
                    ? `（${defaultNode.data.data.node.name}）`
                    : defaultNode.data?.data?.node_id
                      ? `（${defaultNode.data.data.node_id}）`
                      : '（未设置，任意在线节点）'}
                </SelectItem>
                {nodeOptions.map((n) => (
                  <SelectItem
                    key={n.id}
                    value={n.nodeId}
                    disabled={n.status === 'disabled' || n.status === 'offline'}
                  >
                    {n.name}（{n.nodeId}，{n.status}）
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-muted-foreground text-xs">
              默认节点在「节点管理」设置；也可在创建任务时临时指定节点。
            </p>
          </div>

          {/* 扫描目标 */}
          <div className="space-y-2">
            <Label>扫描目标 *</Label>
            <div className="flex gap-3">
              <Textarea
                placeholder="输入目标，每行一个或用逗号分隔&#10;支持：IP / 域名 / URL / CIDR&#10;示例：&#10;192.168.1.1&#10;example.com"
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                rows={4}
                className="flex-1"
              />
              <div className="w-48 border rounded-lg p-2">
                <div className="text-xs text-muted-foreground mb-2">
                  目标列表
                </div>
                {directTargets.length === 0 ? (
                  <div className="text-xs text-muted-foreground text-center py-4">暂无目标</div>
                ) : (
                  <div className="space-y-1 max-h-24 overflow-auto">
                    {directTargets.map((target, i) => (
                      <div key={i} className="flex items-center justify-between text-xs bg-muted px-2 py-1 rounded">
                        <span className="truncate">{target}</span>
                        <X className="h-3 w-3 cursor-pointer shrink-0 ml-1" onClick={() => setDirectTargets(directTargets.filter(t => t !== target))} />
                      </div>
                    ))}
                  </div>
                )}
                <div className="text-xs text-muted-foreground text-right mt-2">
                  共 {directTargets.length} 个目标
                </div>
              </div>
            </div>
            <Button type="button" onClick={addDirectTargets} size="sm" variant="outline">
              <Plus className="h-4 w-4 mr-1" />
              添加到列表
            </Button>
          </div>

          {/* 扫描类型 */}
          <div className="space-y-2">
            <Label>扫描类型 *</Label>
            <div className="grid grid-cols-4 gap-2">
              {scanTypes.map((type) => (
                <div
                  key={type.id}
                  className={`relative p-2 border rounded-lg cursor-pointer transition-all text-center ${
                    formData.config.scanTypes?.includes(type.id)
                      ? 'border-primary bg-primary/5 ring-1 ring-primary'
                      : 'hover:bg-muted'
                  }`}
                  onClick={() => toggleScanType(type.id)}
                >
                  <div className="font-medium text-sm">{type.label}</div>
                  <div className="text-xs text-muted-foreground">{type.description}</div>
                  {formData.config.scanTypes?.includes(type.id) && (
                    <div className="absolute -top-1 -right-1 w-3 h-3 bg-primary rounded-full" />
                  )}
                </div>
              ))}
            </div>
          </div>

          <p className="text-muted-foreground text-xs">
            资产入库跟随勾选：端口扫描→端口入口；爬虫/目录→URL；指纹/服务识别→技术栈与图标。
          </p>

          {/* 任务级字典：子域 / 目录分别选，空 = 内置词表 */}
          {formData.config.scanTypes?.includes('subdomain') && (
            <div className="space-y-2">
              <Label>子域字典</Label>
              <Select
                value={formData.config.subdomain_dict_id || 'builtin'}
                onValueChange={(v) =>
                  setFormData({
                    ...formData,
                    config: { ...formData.config, subdomain_dict_id: v === 'builtin' ? '' : v },
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="内置词表" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="builtin">内置词表</SelectItem>
                  {subDictList.map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.name}（{d.line_count} 条）
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          {/* 第三方测绘引擎：仅子域名枚举相关；只勾选了已配置 key 的引擎才会真正生效 */}
          {formData.config.scanTypes?.includes('subdomain') && (
            <div className="space-y-2">
              <Label>测绘引擎（子域名收集）</Label>
              <div className="flex flex-wrap gap-3">
                {['fofa', 'hunter', 'quake', 'zoomeye', 'shodan'].map((engine) => {
                  const selected = formData.config.thirdparty_sources ?? []
                  const checked = selected.includes(engine)
                  return (
                    <label key={engine} className="flex items-center gap-1.5 text-sm">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={(e) => {
                          const next = e.target.checked
                            ? [...selected, engine]
                            : selected.filter((x) => x !== engine)
                          setFormData({
                            ...formData,
                            config: { ...formData.config, thirdparty_sources: next },
                          })
                        }}
                      />
                      {engine.toUpperCase()}
                    </label>
                  )
                })}
              </div>
              <p className="text-muted-foreground text-xs">
                不勾选 = 默认使用所有已配置 key 的引擎；引擎 key 在「数据源管理」配置，任务级 key 可在下方覆盖。
              </p>
              <div className="grid grid-cols-3 gap-4">
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">FOFA Key（可选）</Label>
                  <Input
                    value={formData.config.fofa_key || ''}
                    onChange={(e) =>
                      setFormData({ ...formData, config: { ...formData.config, fofa_key: e.target.value } })
                    }
                    placeholder="留空用数据源管理里的配置"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Hunter Key（可选）</Label>
                  <Input
                    value={formData.config.hunter_key || ''}
                    onChange={(e) =>
                      setFormData({ ...formData, config: { ...formData.config, hunter_key: e.target.value } })
                    }
                    placeholder="留空用数据源管理里的配置"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-muted-foreground">Quake Key（可选）</Label>
                  <Input
                    value={formData.config.quake_key || ''}
                    onChange={(e) =>
                      setFormData({ ...formData, config: { ...formData.config, quake_key: e.target.value } })
                    }
                    placeholder="留空用数据源管理里的配置"
                  />
                </div>
              </div>
            </div>
          )}
          {formData.config.scanTypes?.includes('dir_scan') && (
            <div className="space-y-2">
              <Label>目录字典</Label>
              <Select
                value={formData.config.dir_dict_id || 'builtin'}
                onValueChange={(v) =>
                  setFormData({
                    ...formData,
                    config: { ...formData.config, dir_dict_id: v === 'builtin' ? '' : v },
                  })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="spray 默认字典" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="builtin">spray 默认字典</SelectItem>
                  {dirDictList.map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.name}（{d.line_count} 条）
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {/* 扫描参数 - 简化版 */}
          <div className="space-y-2">
            <Label>扫描参数</Label>
            <div className="grid grid-cols-3 gap-4">
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">端口模式</Label>
                <Select
                  value={formData.config.port_scan_mode || 'quick'}
                  onValueChange={(value) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, port_scan_mode: value },
                    })
                  }
                >
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">快速扫描</SelectItem>
                    <SelectItem value="top1000">Top 1000</SelectItem>
                    <SelectItem value="full">全端口</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">超时 (秒)</Label>
                <Input
                  type="number"
                  className="h-9"
                  value={formData.config.timeout || 30}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, timeout: Number(e.target.value) },
                    })
                  }
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs text-muted-foreground">并发数</Label>
                <Input
                  type="number"
                  className="h-9"
                  value={formData.config.concurrent || 10}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, concurrent: Number(e.target.value) },
                    })
                  }
                />
              </div>
            </div>
          </div>
        </div>

        {/* 底部按钮 */}
        <div className="flex justify-end gap-3 pt-4 border-t">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={createMutation.isPending}>
            <Play className="h-4 w-4 mr-2" />
            创建任务
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// 保留原来的页面导出，但改用 Dialog
export default function TaskCreatePage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const initialProjectId = Number(searchParams.get('project_id')) || undefined

  return (
    <TaskCreateDialog
      open={true}
      initialProjectId={initialProjectId}
      onOpenChange={(open) => {
        if (!open) navigate('/tasks')
      }}
    />
  )
}

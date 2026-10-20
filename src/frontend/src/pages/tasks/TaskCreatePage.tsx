import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { taskApi, TaskConfig } from '@/api/tasks'
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
  { id: 'service_detect', label: '服务识别', description: '识别服务类型和版本' },
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
}

export function TaskCreateDialog({ open, onOpenChange }: TaskCreateDialogProps) {
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
    if (directTargets.length === 0) {
      toast({ title: '请输入至少一个扫描目标', variant: 'destructive' })
      return
    }
    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' })
      return
    }

    const types = [...new Set(directTargets.map(detectTargetType))]
    const targetType = types.length === 1 ? types[0] : 'mixed'
    const taskType = getTaskType(formData.config.scanTypes || [])

    createMutation.mutate({
      name: formData.name,
      type: taskType,
      targets: directTargets,
      targetType: targetType,
      description: formData.description,
      config: formData.config,
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
  
  return (
    <TaskCreateDialog 
      open={true} 
      onOpenChange={(open) => {
        if (!open) navigate('/tasks')
      }} 
    />
  )
}

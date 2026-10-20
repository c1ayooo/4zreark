import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { taskApi, TaskConfig } from '@/api/tasks'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import { Play, X } from 'lucide-react'
import { cn } from '@/lib/utils'

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

export default function TaskCreateDialog({ open, onOpenChange }: TaskCreateDialogProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    config: {
      scanTypes: ['port_scan'],
      port_scan_mode: 'quick',
      portRange: '1-65535',
      timeout: 30,
      concurrent: 10,
    } as TaskConfig,
  })

  // 直接输入的目标
  const [directTargets, setDirectTargets] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState('')

  // 创建任务
  const createMutation = useMutation({
    mutationFn: taskApi.createTask,
    onSuccess: () => {
      toast({ title: '任务创建成功' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      onOpenChange(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({ title: '创建失败', description: error.message, variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      config: {
        scanTypes: ['port_scan'],
        port_scan_mode: 'quick',
        portRange: '1-65535',
        timeout: 30,
        concurrent: 10,
      },
    })
    setDirectTargets([])
    setTargetInput('')
  }

  // 添加直接输入的目标
  const addDirectTargets = () => {
    if (!targetInput.trim()) return
    const newTargets = targetInput
      .split(/[\n,\s]+/)
      .map(t => t.trim())
      .filter(t => t.length > 0)
    const uniqueTargets = [...new Set([...directTargets, ...newTargets])]
    setDirectTargets(uniqueTargets)
    setTargetInput('')
  }

  const removeDirectTarget = (target: string) => {
    setDirectTargets(directTargets.filter(t => t !== target))
  }

  // 根据选择的扫描类型自动确定任务类型
  const getTaskType = (scanTypes: string[]): string => {
    if (scanTypes.length === 0) return 'port_scan'
    if (scanTypes.length === 1) {
      // 单一扫描类型直接返回对应类型
      return scanTypes[0]
    }
    // 多种扫描类型使用 custom 模式，后端根据 scanTypes 执行对应模块
    return 'custom'
  }

  const handleSubmit = (_startImmediately = false) => {
    if (!formData.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'destructive' })
      return
    }
    
    // 验证目标 - 只支持直接输入模式
    let targets: string[] = []
    let targetType: string = 'unknown'

    // 如果输入框有内容，自动添加到目标列表
    let finalTargets = [...directTargets]
    if (targetInput.trim()) {
      const newTargets = targetInput
        .split(/[\n,\s]+/)
        .map(t => t.trim())
        .filter(t => t.length > 0)
      finalTargets = [...new Set([...finalTargets, ...newTargets])]
    }
    
    if (finalTargets.length === 0) {
      toast({ title: '请输入至少一个扫描目标', variant: 'destructive' })
      return
    }
    targets = finalTargets
    const types = [...new Set(targets.map(detectTargetType))]
    targetType = types.length === 1 ? types[0] : 'mixed'

    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' })
      return
    }

    // 转换配置字段为后端格式 (snake_case)
    const configForBackend = {
      ...formData.config,
      scan_types: formData.config.scanTypes, // 后端使用 snake_case
    }

    // 根据选择的扫描类型自动确定任务类型
    const taskType = getTaskType(formData.config.scanTypes || [])

    createMutation.mutate({
      name: formData.name,
      type: taskType,
      targets: targets,
      targetType: targetType,
      description: formData.description,
      config: configForBackend,
    })
  }

  const toggleScanType = (scanTypeId: string) => {
    const current = formData.config.scanTypes || []
    if (current.includes(scanTypeId)) {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: current.filter((t) => t !== scanTypeId),
        },
      })
    } else {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: [...current, scanTypeId],
        },
      })
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl p-0">
        <DialogHeader className="px-5 pt-5 pb-3">
          <DialogTitle className="text-base font-semibold">创建扫描任务</DialogTitle>
        </DialogHeader>

        <div className="px-5 pb-5 space-y-4">
          {/* 任务名称 */}
          <div className="space-y-1.5">
            <Label className="text-sm">任务名称 <span className="text-destructive">*</span></Label>
            <Input
              placeholder="输入任务名称"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            />
          </div>

          {/* 扫描目标 */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <Label className="text-sm">扫描目标 <span className="text-destructive">*</span></Label>
              <span className="text-xs text-muted-foreground">{directTargets.length} 个目标</span>
            </div>
            <Textarea
              placeholder="输入目标，每行一个或用逗号/空格分隔&#10;支持：IP / 域名 / URL / CIDR"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              onBlur={addDirectTargets}
              className="min-h-[80px] font-mono text-sm resize-none"
            />
            {directTargets.length > 0 && (
              <div className="flex flex-wrap gap-1.5 max-h-[60px] overflow-auto p-2 bg-muted/50 rounded-md">
                {directTargets.map((target, i) => (
                  <Badge key={i} variant="secondary" className="text-xs font-mono gap-1 pr-1">
                    {target}
                    <X className="h-3 w-3 cursor-pointer hover:text-destructive" onClick={() => removeDirectTarget(target)} />
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {/* 扫描类型 - 简化为 checkbox 风格 */}
          <div className="space-y-1.5">
            <Label className="text-sm">扫描类型 <span className="text-destructive">*</span></Label>
            <div className="grid grid-cols-4 gap-1.5">
              {scanTypes.map((type) => (
                <div
                  key={type.id}
                  className={cn(
                    'px-2.5 py-1.5 border rounded cursor-pointer text-center text-xs transition-all',
                    formData.config.scanTypes?.includes(type.id)
                      ? 'border-primary bg-primary/10 text-primary font-medium'
                      : 'hover:bg-muted'
                  )}
                  onClick={() => toggleScanType(type.id)}
                >
                  {type.label}
                </div>
              ))}
            </div>
          </div>

          {/* 端口模式 - 仅当选择了端口扫描时显示 */}
          {formData.config.scanTypes?.includes('port_scan') && (
            <div className="flex items-center gap-3">
              <Label className="text-sm shrink-0">端口范围</Label>
              <Select
                value={formData.config.port_scan_mode || 'quick'}
                onValueChange={(value) =>
                  setFormData({
                    ...formData,
                    config: { ...formData.config, port_scan_mode: value },
                  })
                }
              >
                <SelectTrigger className="h-8 text-xs w-[120px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="quick">快速</SelectItem>
                  <SelectItem value="top1000">Top 1000</SelectItem>
                  <SelectItem value="full">全端口</SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}
        </div>

        {/* 底部操作 */}
        <div className="flex justify-end gap-2 px-5 py-3 border-t bg-muted/30">
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button size="sm" onClick={() => handleSubmit(true)} disabled={createMutation.isPending}>
            <Play className="h-3.5 w-3.5 mr-1" />
            创建任务
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

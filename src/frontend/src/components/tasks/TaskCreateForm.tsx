import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Select, Tag } from 'antd'
import { taskApi, templateApi, TaskConfig, TaskTemplate } from '@/api/tasks'
import TaskTemplatesDialog from '@/components/tasks/TaskTemplatesDialog'
import { assetApi } from '@/api/assets'
import { dictionaryApi } from '@/api/sources'
import { nodeApi } from '@/api/nodes'
import { useToast } from '@/components/ui/use-toast'
import { Play } from 'lucide-react'
import { cn } from '@/lib/utils'

// 扫描类型全集（含独立任务类型：服务识别 / 暴露面探测 / 存量线索）
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

// 页面入口（原 TaskCreatePage）默认配置：三模块组合 + 超时/并发
const PAGE_DEFAULT_CONFIG: TaskConfig = {
  scanTypes: ['subdomain', 'port_scan', 'fingerprint'],
  port_scan_mode: 'quick',
  timeout: 30,
  concurrent: 10,
}

// 对话框入口（原 TaskCreateDialog）默认配置：单模块 + 端口范围 + 扫描节奏
const DIALOG_DEFAULT_CONFIG: TaskConfig = {
  scanTypes: ['port_scan'],
  port_scan_mode: 'quick',
  portRange: '1-65535',
  timeout: 30,
  concurrent: 10,
  rate_per_sec: 20,
  target_delay_ms: 200,
}

// 检测目标类型
function detectTargetType(target: string): string {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) return 'ip'
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) return 'cidr'
  if (/^https?:\/\//.test(target)) return 'url'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(target)) return 'domain'
  return 'unknown'
}

export interface TaskCreateFormProps {
  /** 入口差异（保持两种入口的提交行为不变）：
   *  - dialog：config 额外补 snake_case 的 scan_types；提交时自动把输入框内未添加的目标并入
   *  - page：config 原样提交；提交时只认已添加到列表的目标 */
  variant?: 'dialog' | 'page'
  /** 预选归属项目：从项目详情 / URL project_id 进入时传入 */
  initialProjectId?: number
  /** 创建成功回调：外壳负责关闭对话框 / 跳转任务列表 */
  onCreated?: () => void
  /** 取消回调：外壳负责关闭对话框 / 返回任务列表 */
  onCancel?: () => void
  /** 暂停模板/字典等查询（对话框关闭时传 false） */
  queriesEnabled?: boolean
}

/**
 * 创建扫描任务的共享表单体：TaskCreateDialog（弹窗）与 TaskCreatePage（页面）共用，
 * 拥有全部 formData 状态、校验、提交与字段 UI（antd）。
 */
export default function TaskCreateForm({
  variant = 'dialog',
  initialProjectId,
  onCreated,
  onCancel,
  queriesEnabled = true,
}: TaskCreateFormProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [formData, setFormData] = useState(() => ({
    name: '',
    description: '',
    config: variant === 'page' ? PAGE_DEFAULT_CONFIG : DIALOG_DEFAULT_CONFIG,
  }))

  // 直接输入的目标
  const [directTargets, setDirectTargets] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState('')
  // 归属项目：扫描结果自动并入该项目的资产
  const [projectId, setProjectId] = useState(initialProjectId ?? 0)
  // 任务模板：套用模块组合与节奏
  const [templateId, setTemplateId] = useState('')
  const [templatesOpen, setTemplatesOpen] = useState(false)
  // 扫描节点：空 = 跟随默认节点（后端解析），填 node_id = 指定节点
  const [nodeId, setNodeId] = useState('')

  const templatesRes = useQuery({
    queryKey: ['task-templates'],
    queryFn: () => templateApi.list(),
    enabled: queriesEnabled,
  })
  const templates: TaskTemplate[] = templatesRes.data?.data ?? []

  const { data: projectsRes } = useQuery({
    queryKey: ['projects'],
    queryFn: () => assetApi.projects(),
  })
  const projects = projectsRes?.data ?? []

  const subDicts = useQuery({
    queryKey: ['task-dicts', 'subdomain'],
    queryFn: () => dictionaryApi.list({ type: 'subdomain', page: 1, page_size: 100 }),
    enabled: queriesEnabled,
  })
  const dirDicts = useQuery({
    queryKey: ['task-dicts', 'directory'],
    queryFn: () => dictionaryApi.list({ type: 'directory', page: 1, page_size: 100 }),
    enabled: queriesEnabled,
  })
  const subDictList = subDicts.data?.data ?? []
  const dirDictList = dirDicts.data?.data ?? []
  // 扫描节点选项 + 系统默认节点（不选 = 使用系统默认节点）
  const nodes = useQuery({
    queryKey: ['scan-nodes-options'],
    queryFn: () => nodeApi.getNodes({ page: 1, pageSize: 100 }),
    enabled: queriesEnabled,
  })
  const defaultNode = useQuery({
    queryKey: ['default-scan-node'],
    queryFn: () => nodeApi.getDefaultNode(),
    enabled: queriesEnabled,
  })
  const nodeOptions = nodes.data?.data.list ?? []
  const defaultNodeLabel = defaultNode.data?.data?.node
    ? `默认节点（${defaultNode.data.data.node.name}）`
    : defaultNode.data?.data?.node_id
      ? `默认节点（${defaultNode.data.data.node_id}）`
      : '默认节点（未设置，任意在线节点）'

  // 创建任务
  const createMutation = useMutation({
    mutationFn: taskApi.createTask,
    onSuccess: () => {
      toast({ title: '任务创建成功' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      onCreated?.()
      if (variant === 'dialog') resetForm()
    },
    onError: (error: Error) => {
      toast({ title: '创建失败', description: error.message, variant: 'destructive' })
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      config: variant === 'page' ? PAGE_DEFAULT_CONFIG : DIALOG_DEFAULT_CONFIG,
    })
    setDirectTargets([])
    setTemplateId('')
    setTargetInput('')
    setProjectId(initialProjectId ?? 0)
    setNodeId('')
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

  const handleSubmit = () => {
    if (!formData.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'destructive' })
      return
    }
    if (!projectId) {
      toast({
        title: '请选择归属项目',
        description: '扫描结果会并入该项目的资产',
        variant: 'destructive',
      })
      return
    }

    // 验证目标 - 只支持直接输入模式
    let targets: string[] = directTargets
    // 对话框旧行为：提交时把输入框内未添加的目标自动并入
    if (variant === 'dialog' && targetInput.trim()) {
      const newTargets = targetInput
        .split(/[\n,\s]+/)
        .map(t => t.trim())
        .filter(t => t.length > 0)
      targets = [...new Set([...targets, ...newTargets])]
    }

    if (targets.length === 0) {
      toast({ title: '请输入至少一个扫描目标', variant: 'destructive' })
      return
    }

    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' })
      return
    }

    // 服务识别 / 暴露面探测 / 存量线索是独立任务类型，暂不支持与其他扫描阶段组合
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

    const types = [...new Set(targets.map(detectTargetType))]
    const targetType = types.length === 1 ? types[0] : 'mixed'
    const taskType = getTaskType(formData.config.scanTypes || [])

    // 转换配置字段为后端格式：对话框旧行为会额外补 snake_case 的 scan_types，页面旧行为原样提交
    const configForBackend =
      variant === 'dialog'
        ? { ...formData.config, scan_types: formData.config.scanTypes }
        : formData.config

    createMutation.mutate({
      name: formData.name,
      projectId,
      type: taskType,
      targets: targets,
      targetType: targetType,
      description: formData.description,
      config: configForBackend,
      // 未选节点时不带 node_id（跟随系统默认节点）
      ...(nodeId ? { nodeId } : {}),
    })
  }

  // 套用模板：只覆盖「扫什么 + 扫多快」，名称/目标/项目保持用户已填的内容
  const applyTemplate = (t: TaskTemplate) => {
    const cfg = t.config || {}
    setTemplateId(t.id)
    setFormData((prev) => ({
      ...prev,
      config: {
        ...prev.config,
        scanTypes: cfg.scan_types || cfg.scanTypes || prev.config.scanTypes,
        rate_per_sec: cfg.rate_per_sec ?? prev.config.rate_per_sec,
        target_delay_ms: cfg.target_delay_ms ?? prev.config.target_delay_ms,
        port_scan_mode: cfg.port_scan_mode ?? prev.config.port_scan_mode,
      } as TaskConfig,
    }))
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
    <div className="space-y-4">
      {/* 模板：一键套用模块组合与节奏 */}
      <div className="flex items-end gap-2">
        <div className="flex-1 space-y-1.5">
          <label className="text-sm font-medium">从模板创建</label>
          <Select
            className="w-full"
            value={templateId || 'none'}
            onChange={(v) => {
              if (v === 'none') {
                setTemplateId('')
                return
              }
              const t = templates.find((item) => item.id === v)
              if (t) applyTemplate(t)
            }}
            placeholder="不使用模板"
            options={[
              { value: 'none', label: '不使用模板' },
              ...templates.map((t) => ({ value: t.id, label: t.name })),
            ]}
          />
        </div>
        <Button size="small" className="h-9" onClick={() => setTemplatesOpen(true)}>
          管理模板
        </Button>
      </div>

      {/* 任务名称 + 任务描述 */}
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <label className="text-sm font-medium">
            任务名称 <span className="text-destructive">*</span>
          </label>
          <Input
            placeholder="输入任务名称"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          />
        </div>
        <div className="space-y-1.5">
          <label className="text-sm font-medium">任务描述</label>
          <Input
            placeholder="可选"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
        </div>
      </div>

      {/* 归属项目：扫描结果自动并入该项目资产 */}
      <div className="space-y-1.5">
        <label className="text-sm font-medium">
          归属项目 <span className="text-destructive">*</span>
        </label>
        <Select
          className="w-full"
          value={projectId ? String(projectId) : undefined}
          onChange={(v) => setProjectId(Number(v))}
          placeholder="选择项目"
          options={projects.map((p) => ({ value: String(p.id), label: `${p.name}（${p.code}）` }))}
        />
        <p className="text-xs text-muted-foreground">
          扫描发现的子域、服务会自动归并到该项目的资产里
        </p>
      </div>

      {/* 扫描节点：不选 = 使用系统默认节点 */}
      <div className="space-y-1.5">
        <label className="text-sm font-medium">扫描节点</label>
        <Select
          className="w-full"
          value={nodeId || 'default'}
          onChange={(v) => setNodeId(v === 'default' ? '' : v)}
          placeholder="默认节点"
          options={[
            { value: 'default', label: defaultNodeLabel },
            ...nodeOptions.map((n) => ({
              value: n.nodeId,
              label: `${n.name}（${n.nodeId}，${n.status}）`,
              disabled: n.status === 'disabled' || n.status === 'offline',
            })),
          ]}
        />
        <p className="text-xs text-muted-foreground">
          默认节点在「节点管理」设置；也可在创建任务时临时指定节点。
        </p>
      </div>

      {/* 扫描目标 */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium">
            扫描目标 <span className="text-destructive">*</span>
          </label>
          <span className="text-xs text-muted-foreground">{directTargets.length} 个目标</span>
        </div>
        <Input.TextArea
          placeholder="输入目标，每行一个或用逗号/空格分隔&#10;支持：IP / 域名 / URL / CIDR"
          value={targetInput}
          onChange={(e) => setTargetInput(e.target.value)}
          onBlur={addDirectTargets}
          className="min-h-[80px] font-mono text-sm"
          style={{ resize: 'none' }}
        />
        {directTargets.length > 0 && (
          <div className="flex max-h-[60px] flex-wrap gap-1.5 overflow-auto rounded-md bg-muted/50 p-2">
            {directTargets.map((target, i) => (
              <Tag
                key={i}
                className="font-mono text-xs"
                closable
                onClose={() => removeDirectTarget(target)}
              >
                {target}
              </Tag>
            ))}
          </div>
        )}
      </div>

      {/* 扫描类型 - checkbox 风格调选，含独立任务类型 */}
      <div className="space-y-1.5">
        <label className="text-sm font-medium">
          扫描类型 <span className="text-destructive">*</span>
        </label>
        <div className="grid grid-cols-4 gap-1.5">
          {scanTypes.map((type) => (
            <div
              key={type.id}
              className={cn(
                'cursor-pointer rounded border px-2.5 py-1.5 text-center text-xs transition-all',
                formData.config.scanTypes?.includes(type.id)
                  ? 'border-primary bg-primary/10 font-medium text-primary'
                  : 'hover:bg-muted',
              )}
              onClick={() => toggleScanType(type.id)}
            >
              <div className="font-medium">{type.label}</div>
              <div className={cn('text-muted-foreground', formData.config.scanTypes?.includes(type.id) && 'text-primary/70')}>
                {type.description}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 扫描节奏：除漏洞扫描外全模块生效，默认值刻意保守 */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-sm font-medium">扫描节奏</label>
          <div className="flex gap-1">
            {[
              { label: '保守', rate: 5, delay: 1000 },
              { label: '标准', rate: 20, delay: 200 },
              { label: '快速', rate: 50, delay: 50 },
            ].map((preset) => (
              <Button
                key={preset.label}
                size="small"
                type={
                  (formData.config.rate_per_sec ?? 20) === preset.rate ? 'primary' : 'default'
                }
                className="h-7 px-2.5 text-xs"
                onClick={() =>
                  setFormData({
                    ...formData,
                    config: {
                      ...formData.config,
                      rate_per_sec: preset.rate,
                      target_delay_ms: preset.delay,
                    },
                  })
                }
              >
                {preset.label}
              </Button>
            ))}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">每秒请求上限</label>
            <Input
              type="number"
              min={1}
              max={200}
              value={formData.config.rate_per_sec ?? 20}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  config: {
                    ...formData.config,
                    rate_per_sec: Number(e.target.value) || 20,
                  },
                })
              }
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">单目标间隔（毫秒）</label>
            <Input
              type="number"
              min={0}
              max={5000}
              step={50}
              value={formData.config.target_delay_ms ?? 200}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  config: {
                    ...formData.config,
                    target_delay_ms: Number(e.target.value),
                  },
                })
              }
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          漏洞扫描不受限制；数值越小越快，越容易被目标封 IP。多目标并发时爬虫对单站额外按全局速率的一半限速。
        </p>
      </div>

      {/* 爬虫保护：每站页数/深度上限，防止深钻拖垮业务站 */}
      <div className="space-y-2">
        <label className="text-sm font-medium">爬虫保护</label>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">每站最多爬取页数</label>
            <Input
              type="number"
              min={0}
              max={5000}
              placeholder="100"
              value={formData.config.max_pages ?? ''}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  config: {
                    ...formData.config,
                    max_pages: e.target.value === '' ? undefined : Number(e.target.value),
                  },
                })
              }
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">爬取深度（层）</label>
            <Input
              type="number"
              min={0}
              max={10}
              placeholder="3"
              value={formData.config.max_depth ?? ''}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  config: {
                    ...formData.config,
                    max_depth: e.target.value === '' ? undefined : Number(e.target.value),
                  },
                })
              }
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          留空用默认（100 页 / 3 层）。引擎层生效：到达上限后爬虫停止发请求，不只是截断结果。
        </p>
      </div>

      {/* 扫描参数：端口模式 / 超时 / 并发 */}
      <div className="space-y-2">
        <label className="text-sm font-medium">扫描参数</label>
        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">端口模式</label>
            <Select
              className="w-full"
              value={formData.config.port_scan_mode || 'quick'}
              onChange={(value) =>
                setFormData({
                  ...formData,
                  config: { ...formData.config, port_scan_mode: value },
                })
              }
              options={[
                { value: 'quick', label: '快速扫描' },
                { value: 'top1000', label: 'Top 1000' },
                { value: 'full', label: '全端口' },
              ]}
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">超时 (秒)</label>
            <Input
              type="number"
              value={formData.config.timeout || 30}
              onChange={(e) =>
                setFormData({
                  ...formData,
                  config: { ...formData.config, timeout: Number(e.target.value) },
                })
              }
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground">并发数</label>
            <Input
              type="number"
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

      <p className="text-muted-foreground text-xs">
        资产入库跟随勾选：端口扫描→端口入口；爬虫/目录→URL；指纹/服务识别→技术栈与图标。
      </p>

      {/* 任务级字典：子域 / 目录分别选，空 = 内置词表 */}
      {formData.config.scanTypes?.includes('subdomain') && (
        <div className="flex items-center gap-3">
          <label className="shrink-0 text-sm font-medium">子域字典</label>
          <Select
            className="h-8 min-w-0 flex-1 text-xs"
            value={formData.config.subdomain_dict_id || 'builtin'}
            onChange={(v) =>
              setFormData({
                ...formData,
                config: { ...formData.config, subdomain_dict_id: v === 'builtin' ? '' : v },
              })
            }
            options={[
              { value: 'builtin', label: '内置词表' },
              ...subDictList.map((d) => ({ value: d.id, label: `${d.name}（${d.line_count} 条）` })),
            ]}
          />
        </div>
      )}
      {/* 第三方测绘引擎：仅子域名枚举相关；只勾选了已配置 key 的引擎才会真正生效 */}
      {formData.config.scanTypes?.includes('subdomain') && (
        <div className="space-y-2">
          <label className="text-sm font-medium">测绘引擎（子域名收集）</label>
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
              <label className="text-xs text-muted-foreground">FOFA Key（可选）</label>
              <Input
                value={formData.config.fofa_key || ''}
                onChange={(e) =>
                  setFormData({ ...formData, config: { ...formData.config, fofa_key: e.target.value } })
                }
                placeholder="留空用数据源管理里的配置"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Hunter Key（可选）</label>
              <Input
                value={formData.config.hunter_key || ''}
                onChange={(e) =>
                  setFormData({ ...formData, config: { ...formData.config, hunter_key: e.target.value } })
                }
                placeholder="留空用数据源管理里的配置"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs text-muted-foreground">Quake Key（可选）</label>
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
        <div className="flex items-center gap-3">
          <label className="shrink-0 text-sm font-medium">目录字典</label>
          <Select
            className="h-8 min-w-0 flex-1 text-xs"
            value={formData.config.dir_dict_id || 'builtin'}
            onChange={(v) =>
              setFormData({
                ...formData,
                config: { ...formData.config, dir_dict_id: v === 'builtin' ? '' : v },
              })
            }
            options={[
              { value: 'builtin', label: 'spray 默认字典' },
              ...dirDictList.map((d) => ({ value: d.id, label: `${d.name}（${d.line_count} 条）` })),
            ]}
          />
        </div>
      )}

      {/* 底部操作：取消 + 创建（取消行为由外壳决定） */}
      <div className="flex justify-end gap-2 border-t pt-4">
        {onCancel && (
          <Button onClick={onCancel}>取消</Button>
        )}
        <Button
          type="primary"
          icon={<Play className="h-3.5 w-3.5" />}
          loading={createMutation.isPending}
          onClick={handleSubmit}
        >
          创建任务
        </Button>
      </div>

      <TaskTemplatesDialog open={templatesOpen} onOpenChange={setTemplatesOpen} />
    </div>
  )
}

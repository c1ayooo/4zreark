import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Button, Input, Modal, Select } from 'antd'
import { Rocket } from 'lucide-react'

import { taskApi } from '@/api/tasks'
import { assetApi } from '@/api/assets'
import { useToast } from '@/components/ui/use-toast'

// 可对「已有资产」派的任务类型。子域枚举不在此列：资产已经归并过，再枚举一遍没有意义。
const SCAN_OPTIONS: { value: string; label: string; hint: string }[] = [
  { value: 'port_scan', label: '端口扫描', hint: '对每个 host 做端口发现' },
  { value: 'fingerprint', label: '指纹识别', hint: '识别框架、中间件、CMS' },
  { value: 'crawler', label: 'Web 爬虫', hint: '抓 URL、表单与接口' },
  { value: 'dir_scan', label: '目录扫描', hint: '按字典探测路径（请求量大）' },
  { value: 'vuln_scan', label: '漏洞扫描', hint: '按 PoC 验证已知漏洞' },
]

interface CreateTaskFromAssetsDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** 选中的资产 host 列表 */
  hosts: string[]
  /** 从项目资产页发起时带上项目，任务归属就确定了 */
  projectId?: string | number
}

// 资产页的 value 可能是 https://host:443 这种完整入口，派单只需要 host。
function normalizeHost(raw: string) {
  return raw
    .trim()
    .replace(/^[a-zA-Z][\w+.-]*:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
}

function defaultName(count: number) {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `资产复测-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}-${count}个资产`
}

// 从「已有资产」直接派任务：选资产 → 选扫描类型 → 起任务。
// 这是资产页与任务详情页共用的入口，避免用户只能靠脚本拼目标列表。
export default function CreateTaskFromAssetsDialog({
  open,
  onOpenChange,
  hosts,
  projectId,
}: CreateTaskFromAssetsDialogProps) {
  const navigate = useNavigate()
  const { toast } = useToast()
  const [name, setName] = useState('')
  const [pid, setPid] = useState<string>(projectId ? String(projectId) : '')
  const [scanTypes, setScanTypes] = useState<string[]>(['port_scan', 'fingerprint'])
  const [threads, setThreads] = useState('5')
  const [showAll, setShowAll] = useState(false)

  const projects = useQuery({
    queryKey: ['asset-projects'],
    queryFn: () => assetApi.projects(),
    enabled: open,
  })

  useEffect(() => {
    if (open) {
      setName(defaultName(hosts.length))
      setPid(projectId ? String(projectId) : '')
      setShowAll(false)
    }
  }, [open, hosts.length, projectId])

  const toggleType = (value: string) => {
    setScanTypes((prev) => (prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]))
  }

  const targets = useMemo(
    () => Array.from(new Set(hosts.map(normalizeHost).filter(Boolean))),
    [hosts]
  )
  const preview = useMemo(() => (showAll ? targets : targets.slice(0, 6)), [targets, showAll])

  const create = useMutation({
    mutationFn: () =>
      taskApi.createTask({
        name: name.trim() || defaultName(hosts.length),
        projectId: pid ? Number(pid) : undefined,
        type: scanTypes[0] || 'port_scan',
        targets,
        targetType: 'domain',
        description: `从资产列表选中 ${hosts.length} 个资产创建`,
        config: {
          scanTypes,
          concurrent: Number(threads) || 5,
          timeout: 10,
        },
      }),
    onSuccess: (res) => {
      const taskId = (res as any)?.data?.id
      toast({ title: '任务已创建', description: `目标 ${hosts.length} 个，正在等待派单` })
      onOpenChange(false)
      if (taskId) navigate(`/tasks/${taskId}`)
    },
    onError: (err: any) => {
      toast({ title: '创建失败', description: err?.message || String(err), variant: 'destructive' })
    },
  })

  const canSubmit = targets.length > 0 && scanTypes.length > 0 && !!pid && !create.isPending

  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      title="用选中资产创建任务"
      width={576}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>取消</Button>
          <Button
            icon={<Rocket className="h-4 w-4" />}
            loading={create.isPending}
            onClick={() => create.mutate()}
            disabled={!canSubmit}
          >
            创建并启动任务
          </Button>
        </div>
      }
    >
      <p className="mb-4 text-sm text-muted-foreground">
        已选 {targets.length} 个资产，选好扫描类型就直接派单，不用再手写目标列表。
      </p>

      <div className="space-y-3">
        <div className="rounded-md border bg-muted/30 p-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="text-muted-foreground">目标预览</span>
            {targets.length > 6 && (
              <button className="text-primary text-xs hover:underline" onClick={() => setShowAll((v) => !v)}>
                {showAll ? '收起' : `展开全部 ${hosts.length} 个`}
              </button>
            )}
          </div>
          <div className="mt-1 flex flex-wrap gap-1 font-mono">
            {preview.map((h) => (
              <span key={h} className="bg-background rounded border px-1.5 py-0.5">
                {h}
              </span>
            ))}
          </div>
        </div>

        <div className="space-y-1">
          <label className="text-sm font-medium">任务名称</label>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="任务名称" />
        </div>

        <div className="space-y-1">
          <label className="text-sm font-medium">归属项目</label>
          <Select
            className="w-full"
            value={pid || undefined}
            onChange={(v) => setPid(v)}
            placeholder="选择项目（任务必须归属一个项目）"
            options={(projects.data?.data || []).map((p: any) => ({
              value: String(p.id),
              label: `${p.name}（${p.code || p.id}）`,
            }))}
          />
        </div>

        <div className="space-y-1">
          <label className="text-sm font-medium">扫描类型</label>
          <div className="grid grid-cols-2 gap-2">
            {SCAN_OPTIONS.map((opt) => {
              const checked = scanTypes.includes(opt.value)
              return (
                <button
                  key={opt.value}
                  type="button"
                  onClick={() => toggleType(opt.value)}
                  className={`rounded-md border px-2 py-1.5 text-left text-xs transition-colors ${
                    checked ? 'border-primary bg-primary/5' : 'hover:bg-muted/50'
                  }`}
                >
                  <div className="flex items-center gap-1.5 font-medium">
                    <span
                      className={`flex h-3.5 w-3.5 items-center justify-center rounded border ${
                        checked ? 'border-primary bg-primary text-primary-foreground' : ''
                      }`}
                    >
                      {checked ? '✓' : ''}
                    </span>
                    {opt.label}
                  </div>
                  <div className="text-muted-foreground mt-0.5 pl-5">{opt.hint}</div>
                </button>
              )
            })}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <label className="text-sm font-medium">并发</label>
          <Input
            className="h-8 w-24"
            value={threads}
            onChange={(e) => setThreads(e.target.value.replace(/[^0-9]/g, ''))}
          />
          <span className="text-muted-foreground text-xs">按节点能力自动选执行节点</span>
        </div>
      </div>
    </Modal>
  )
}

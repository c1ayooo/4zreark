import { useEffect, useState } from 'react'
import { Button, Input, Modal, Select } from 'antd'
import type { Task } from '@/api/tasks'
import { scanTypeLabels } from '../taskMeta'

// 编辑任务配置:表单状态自管,打开时从任务初始化,保存回调交由父级落地。
export interface TaskConfigPayload {
  targets: string[]
  config: {
    scan_types: string[]
    port_scan_mode: string
    rate_per_sec: number
    target_delay_ms: number
    subdomain_dict_id: string
    dir_dict_id: string
  }
}

export default function EditConfigModal({
  open,
  task,
  onClose,
  onSave,
  saving,
}: {
  open: boolean
  task: Task
  onClose: () => void
  onSave: (payload: TaskConfigPayload) => Promise<unknown>
  saving: boolean
}) {
  const [targets, setTargets] = useState('')
  const [scanTypes, setScanTypes] = useState<string[]>([])
  const [portMode, setPortMode] = useState('quick')
  const [rate, setRate] = useState('10')
  const [delay, setDelay] = useState('500')
  const [subDict, setSubDict] = useState('')
  const [dirDict, setDirDict] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open || !task) return
    setTargets((task.targets || []).join('\n'))
    setScanTypes([...(task.config.scan_types || [])])
    setPortMode(task.config.port_scan_mode || 'quick')
    setRate(String(task.config.rate_per_sec ?? 10))
    setDelay(String(task.config.target_delay_ms ?? 500))
    setSubDict(task.config.subdomain_dict_id || '')
    setDirDict(task.config.dir_dict_id || '')
    setError('')
  }, [open, task])

  const save = async () => {
    const list = targets
      .split(/[\n,\s]+/)
      .map((t) => t.trim())
      .filter(Boolean)
    if (list.length === 0) {
      setError('至少保留一个目标')
      return
    }
    try {
      await onSave({
        targets: list,
        config: {
          scan_types: scanTypes,
          port_scan_mode: portMode,
          rate_per_sec: Number(rate) || 0,
          target_delay_ms: Number(delay) || 0,
          subdomain_dict_id: subDict.trim(),
          dir_dict_id: dirDict.trim(),
        },
      })
    } catch (e) {
      setError((e as { message?: string })?.message || '保存失败')
    }
  }

  return (
    <Modal open={open} onCancel={onClose} title="编辑任务配置" width={672} footer={null}>
      <div className="space-y-3 py-2">
        <div className="space-y-1">
          <label className="text-sm font-medium">扫描目标(每行一个)</label>
          <Input.TextArea
            rows={3}
            className="font-mono text-xs"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">扫描类型</label>
          <div className="grid gap-2 sm:grid-cols-3">
            {Object.entries(scanTypeLabels).map(([id, label]) => (
              <label key={id} className="flex items-center gap-2 rounded-md border px-2 py-1.5 text-sm">
                <input
                  type="checkbox"
                  checked={scanTypes.includes(id)}
                  onChange={(e) =>
                    setScanTypes((prev) =>
                      e.target.checked ? [...prev, id] : prev.filter((x) => x !== id)
                    )
                  }
                />
                {label}
              </label>
            ))}
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">端口模式</label>
            <Select
              value={portMode}
              onChange={setPortMode}
              className="w-full"
              options={[
                { value: 'quick', label: '快速' },
                { value: 'top1000', label: 'Top 1000' },
                { value: 'full', label: '全端口' },
              ]}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">限速(req/s)</label>
            <Input value={rate} onChange={(e) => setRate(e.target.value)} />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">目标间隔(ms)</label>
            <Input value={delay} onChange={(e) => setDelay(e.target.value)} />
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="text-sm font-medium">子域字典 ID(留空内置)</label>
            <Input value={subDict} onChange={(e) => setSubDict(e.target.value)} placeholder="dictionaries.id" />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">目录字典 ID(留空 spray 默认)</label>
            <Input value={dirDict} onChange={(e) => setDirDict(e.target.value)} placeholder="dictionaries.id" />
          </div>
        </div>
        {error && <p className="text-xs text-destructive">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" onClick={save} loading={saving}>
            保存配置
          </Button>
        </div>
      </div>
    </Modal>
  )
}

import { useEffect, useState, type FormEvent } from 'react'
import { Button, Input, Modal, Select } from 'antd'

import type { Project, ProjectInput } from '@/api/projects'

const emptyForm: ProjectInput = {
  code: '',
  name: '',
  region: 'domestic',
  description: '',
  homepage_url: '',
  color: '#64748b',
  cycle_interval_days: 30,
}

interface ProjectFormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  project?: Project | null
  onSubmit: (input: ProjectInput) => Promise<unknown>
}

export function ProjectFormDialog({
  open,
  onOpenChange,
  project,
  onSubmit,
}: ProjectFormDialogProps) {
  const [form, setForm] = useState<ProjectInput>(emptyForm)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!open) return
    setForm(
      project
        ? {
            code: project.code,
            name: project.name,
            region: project.region || 'domestic',
            description: project.description,
            homepage_url: project.homepage_url,
            color: project.color || '#64748b',
            cycle_interval_days: project.cycle_interval_days || 30,
          }
        : emptyForm,
    )
  }, [open, project])

  const set = <K extends keyof ProjectInput>(key: K, value: ProjectInput[K]) =>
    setForm((prev) => ({ ...prev, [key]: value }))

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!form.name.trim()) return
    if (!project && !form.code.trim()) return
    setSubmitting(true)
    try {
      await onSubmit({ ...form, cycle_interval_days: Number(form.cycle_interval_days) || 30 })
      onOpenChange(false)
    } catch {
      /* 错误提示由调用方的 mutation 负责，表单保持打开方便修改 */
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      width={576}
      title={project ? '编辑项目资料' : '新建项目'}
      footer={null}
    >
      <p className="text-muted-foreground mb-4 text-sm">
        项目是公司或 SRC 的资产边界，种子、监控计划和资产都归属到项目。
      </p>

      <form onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label htmlFor="project-code" className="text-sm font-medium">
              项目编码
            </label>
            <Input
              id="project-code"
              value={form.code}
              disabled={!!project}
              placeholder="acme-src"
              onChange={(e) => set('code', e.target.value)}
            />
            <p className="text-muted-foreground text-xs">
              字母、数字、下划线、短横线，创建后不可修改。
            </p>
          </div>
          <div className="space-y-1.5">
            <label htmlFor="project-name" className="text-sm font-medium">
              项目名称
            </label>
            <Input
              id="project-name"
              value={form.name}
              placeholder="示例公司 SRC"
              onChange={(e) => set('name', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-sm font-medium">地区</label>
            <Select
              className="w-full"
              value={form.region}
              onChange={(v) => set('region', v)}
              placeholder="选择地区"
              options={[
                { value: 'domestic', label: '国内' },
                { value: 'intl', label: '国际' },
              ]}
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="project-cycle" className="text-sm font-medium">
              采集周期（天）
            </label>
            <Input
              id="project-cycle"
              type="number"
              min={1}
              max={3650}
              value={form.cycle_interval_days}
              onChange={(e) => set('cycle_interval_days', Number(e.target.value))}
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="project-homepage" className="text-sm font-medium">
              主页
            </label>
            <Input
              id="project-homepage"
              value={form.homepage_url}
              placeholder="https://example.com"
              onChange={(e) => set('homepage_url', e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="project-color" className="text-sm font-medium">
              主题色
            </label>
            <div className="flex items-center gap-2">
              <Input
                id="project-color"
                type="color"
                className="h-9 w-16 p-1"
                value={form.color || '#64748b'}
                onChange={(e) => set('color', e.target.value)}
              />
              <Input
                value={form.color}
                className="font-mono"
                onChange={(e) => set('color', e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className="space-y-1.5">
          <label htmlFor="project-description" className="text-sm font-medium">
            项目说明
          </label>
          <Input.TextArea
            id="project-description"
            value={form.description}
            placeholder="沉淀范围、授权信息、对接人等"
            onChange={(e) => set('description', e.target.value)}
          />
        </div>

        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>取消</Button>
          <Button
            type="primary"
            htmlType="submit"
            loading={submitting}
            disabled={!form.name.trim()}
          >
            {project ? '保存' : '创建项目'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

export default ProjectFormDialog

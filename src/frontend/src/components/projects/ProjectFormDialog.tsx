import { useEffect, useState, type FormEvent } from 'react'

import type { Project, ProjectInput } from '@/api/projects'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'

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
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{project ? '编辑项目资料' : '新建项目'}</DialogTitle>
          <DialogDescription>
            项目是公司或 SRC 的资产边界，种子、监控计划和资产都归属到项目。
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={submit} className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="project-code">项目编码</Label>
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
              <Label htmlFor="project-name">项目名称</Label>
              <Input
                id="project-name"
                value={form.name}
                placeholder="示例公司 SRC"
                onChange={(e) => set('name', e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label>地区</Label>
              <Select value={form.region} onValueChange={(v) => set('region', v)}>
                <SelectTrigger>
                  <SelectValue placeholder="选择地区" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domestic">国内</SelectItem>
                  <SelectItem value="intl">国际</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project-cycle">采集周期（天）</Label>
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
              <Label htmlFor="project-homepage">主页</Label>
              <Input
                id="project-homepage"
                value={form.homepage_url}
                placeholder="https://example.com"
                onChange={(e) => set('homepage_url', e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="project-color">主题色</Label>
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
            <Label htmlFor="project-description">项目说明</Label>
            <Textarea
              id="project-description"
              value={form.description}
              placeholder="沉淀范围、授权信息、对接人等"
              onChange={(e) => set('description', e.target.value)}
            />
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              取消
            </Button>
            <Button type="submit" disabled={submitting || !form.name.trim()}>
              {submitting ? '保存中…' : project ? '保存' : '创建项目'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default ProjectFormDialog

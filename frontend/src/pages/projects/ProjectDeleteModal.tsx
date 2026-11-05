import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal } from 'antd'

import { projectApi } from '@/api/projects'
import { useToast } from '@/components/ui/use-toast'

export interface ProjectDeleteTarget {
  id: number
  name: string
  code: string
}

// 永久删除项目：输项目编码确认（后端同样校验，双保险）；后端级联清任务/资产/巡航等全部归属数据
export default function ProjectDeleteModal({
  project,
  open,
  onClose,
  onDeleted,
}: {
  project: ProjectDeleteTarget | null
  open: boolean
  onClose: () => void
  onDeleted?: () => void
}) {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const [confirmCode, setConfirmCode] = useState('')

  // 每次打开重置输码，避免上一次的残留直接解锁删除按钮
  useEffect(() => {
    if (open) setConfirmCode('')
  }, [open, project?.id])

  const deleteMutation = useMutation({
    mutationFn: (confirm_code: string) => projectApi.delete(project!.id, confirm_code),
    onSuccess: (res) => {
      const d = res.data
      toast({
        title: `项目「${d?.name ?? project?.name ?? ''}」已删除`,
        description: `站点 ${d?.sites ?? 0} · 原始记录 ${d?.records ?? 0} · 任务 ${d?.tasks ?? 0} · 扫描结果 ${d?.scan_results ?? 0} · 巡航 ${d?.cruise_tasks ?? 0}`,
      })
      queryClient.removeQueries({ queryKey: ['project', project?.id] })
      queryClient.invalidateQueries({ queryKey: ['projects'] })
      queryClient.invalidateQueries({ queryKey: ['asset-projects'] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      onClose()
      onDeleted?.()
    },
    onError: (e) => {
      toast({ title: '删除项目失败', description: (e as Error).message, variant: 'destructive' })
    },
  })

  if (!project) return null

  const codeMismatch = confirmCode.trim() !== project.code

  return (
    <Modal
      open={open}
      title={`永久删除项目「${project.name}」`}
      onCancel={onClose}
      width={480}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button
            danger
            type="primary"
            disabled={codeMismatch}
            loading={deleteMutation.isPending}
            onClick={() => deleteMutation.mutate(confirmCode.trim())}
          >
            永久删除
          </Button>
        </div>
      }
    >
      <p className="text-sm text-muted-foreground">
        将删除编码 <span className="font-mono text-foreground">{project.code}</span>{' '}
        归属的全部数据：站点、原始记录、种子、巡航计划、任务（含扫描结果与队列作业）、巡航任务、关系图谱、企业身份、ICP
        备案。<span className="text-destructive">此操作不可恢复。</span>
      </p>
      <div className="mt-3">
        <label className="text-sm font-medium" htmlFor="project-delete-confirm">
          请输入项目编码 <span className="font-mono text-destructive">{project.code}</span> 确认：
        </label>
        <Input
          id="project-delete-confirm"
          className="mt-1.5"
          value={confirmCode}
          onChange={(e) => setConfirmCode(e.target.value)}
          placeholder={project.code}
          autoComplete="off"
        />
      </div>
    </Modal>
  )
}

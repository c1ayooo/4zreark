import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, InputNumber, Modal, Select } from 'antd'
import { useNavigate } from 'react-router-dom'

import { projectApi } from '@/api/projects'
import { enterpriseApi } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 一键侦察：公司名 → 企业深度采集 → 采集完成后后端自动创建
// 全流水线 + 服务识别/暴露面探测/存量线索 四个扫描任务。
export default function OnboardDialog({ open, onClose }: {
  open: boolean
  onClose: () => void
}) {
  const { toast } = useToast()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [form, setForm] = useState({
    project_id: undefined as number | undefined,
    keyword: '',
    provider: 'aqc',
    depth: 2,
    max_nodes: 50,
  })

  const projects = useQuery({
    queryKey: ['asset-projects'],
    queryFn: () => projectApi.list(),
    enabled: open,
  })
  const providers = useQuery({
    queryKey: ['enterprise-providers'],
    queryFn: () => enterpriseApi.providers(),
    enabled: open,
  })

  const onboard = useMutation({
    mutationFn: () => {
      if (!form.project_id) throw new Error('先选择归属项目')
      if (!form.keyword.trim()) throw new Error('填写公司名称')
      return projectApi.onboard(form.project_id, {
        provider: form.provider,
        keyword: form.keyword.trim(),
        depth: form.depth,
        max_nodes: form.max_nodes,
      })
    },
    onSuccess: (res) => {
      toast({
        title: '一键侦察已启动',
        description: `企业采集任务 ${res.data?.job?.id?.slice(-6) ?? ''} 运行中；完成后自动创建全流水线与独立扫描任务`,
      })
      queryClient.invalidateQueries({ queryKey: ['enterprise-jobs'] })
      onClose()
      navigate(`/projects/${form.project_id}`)
    },
    onError: (e: any) =>
      toast({ title: '启动失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="一键侦察"
      width={560}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={onboard.isPending} onClick={() => onboard.mutate()}>
            启动采集
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        输入公司名称后自动执行：企业深度采集（子公司/分支域名备案确认后自动转种子）→
        采集完成后按种子自动创建全流水线与三类独立扫描任务。
      </p>
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">归属项目</label>
            <Select
              className="w-full"
              placeholder="选择项目"
              value={form.project_id}
              onChange={(v) => setForm({ ...form, project_id: v })}
              options={(projects.data?.data ?? []).map((p) => ({
                value: p.id,
                label: p.name,
              }))}
              showSearch
              optionFilterProp="label"
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">企业数据源</label>
            <Select
              className="w-full"
              value={form.provider}
              onChange={(v) => setForm({ ...form, provider: v })}
              options={(providers.data?.data?.items ?? []).map((p) => ({
                value: p.Name,
                label: `${p.Label}（${p.Auth}）`,
                disabled: !p.Available,
              }))}
            />
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">公司名称</label>
          <Input
            placeholder="如：某某科技有限责任公司"
            value={form.keyword}
            onChange={(e) => setForm({ ...form, keyword: e.target.value })}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">展开层级</label>
            <InputNumber
              className="w-full"
              min={1}
              max={3}
              value={form.depth}
              onChange={(v) => setForm({ ...form, depth: Number(v) || 1 })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">最大节点数</label>
            <InputNumber
              className="w-full"
              min={1}
              max={200}
              value={form.max_nodes}
              onChange={(v) => setForm({ ...form, max_nodes: Number(v) || 20 })}
            />
          </div>
        </div>
        <p className="text-muted-foreground text-xs">
          采集凭据（Cookie/账号）可在「工具箱 → 企业数据源」预先托管，这里不填则使用已托管会话。
        </p>
      </div>
    </Modal>
  )
}

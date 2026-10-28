import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, InputNumber, Modal, Select } from 'antd'
import { useNavigate } from 'react-router-dom'

import { projectApi } from '@/api/projects'
import { enterpriseApi } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 一键侦察：公司名称或域名 → 多平台并行采集（归一去重）→ 采集完成后
// 后端自动创建全流水线 + 服务识别/暴露面探测/存量线索扫描任务。
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
    providers: ['tyc', 'aqc'] as string[],
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
      if (!form.keyword.trim()) throw new Error('填写公司名称或域名')
      if (form.providers.length === 0) throw new Error('至少选择一个数据源')
      return projectApi.onboard(form.project_id, {
        keyword: form.keyword.trim(),
        providers: form.providers,
        depth: form.depth,
        max_nodes: form.max_nodes,
      })
    },
    onSuccess: (res) => {
      const mode = res.data?.mode
      toast({
        title: mode === 'domain' ? '域名模式已启动' : '多平台采集已启动',
        description:
          res.data?.job_errors && res.data.job_errors.length > 0
            ? `${res.data.jobs?.length ?? 0} 个数据源启动；部分源失败：${res.data.job_errors[0]}`
            : `${(res.data?.jobs?.length ?? 0)} 个数据源并行采集中，完成后自动创建扫描任务`,
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
        输入公司名称或域名，多平台并行采集、自动归一去重：企业深度采集（子公司域名备案确认后自动转种子）
        → 采集完成后自动创建全流水线与独立扫描任务。填域名时先落种子扫描，并反查主办单位继续采集其集团。
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
            <label className="text-sm font-medium">企业数据源（多选并行）</label>
            <Select
              className="w-full"
              mode="multiple"
              value={form.providers}
              onChange={(v) => setForm({ ...form, providers: v })}
              options={(providers.data?.data?.items ?? []).map((p) => ({
                value: p.Name,
                label: p.Label,
                disabled: !p.Available,
              }))}
              maxTagCount={3}
            />
          </div>
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">公司名称或域名</label>
          <Input
            placeholder="如：浙江省能源集团有限公司 或 zjenergy.com.cn"
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
            <label className="text-sm font-medium">单源最大节点数</label>
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
          各源结果按项目自动归一去重（同名企业合并、域名唯一）；采集凭据可在「工具箱 → 企业数据源」预托管。
        </p>
      </div>
    </Modal>
  )
}

import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Alert, Button, Input, Modal } from 'antd'

import { enterpriseApi } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 深度采集硬上限配置（子公司展开层级 / 节点数）。
// 热更新：保存即写入后端内存并对后续任务生效，运行中任务不受影响，无需重启服务。
export default function CollectorSettingsModal({ open, onClose }: {
  open: boolean
  onClose: () => void
}) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [maxDepth, setMaxDepth] = useState<string>('')
  const [maxNodes, setMaxNodes] = useState<string>('')

  const settings = useQuery({
    queryKey: ['enterprise-settings'],
    queryFn: () => enterpriseApi.settings(),
    enabled: open,
  })

  useEffect(() => {
    if (settings.data?.data) {
      setMaxDepth(String(settings.data.data.max_depth))
      setMaxNodes(String(settings.data.data.max_nodes))
    }
  }, [settings.data])

  const save = useMutation({
    mutationFn: () =>
      enterpriseApi.saveSettings({
        max_depth: Number(maxDepth) || undefined,
        max_nodes: Number(maxNodes) || undefined,
      }),
    onSuccess: (res) => {
      toast({
        title: '采集上限已更新并即时生效',
        description: `层级上限 ${res.data?.max_depth} · 节点上限 ${res.data?.max_nodes}；运行中的任务不受影响`,
      })
      queryClient.invalidateQueries({ queryKey: ['enterprise-settings'] })
      onClose()
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="采集上限（子公司层级 / 节点）"
      width={520}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>
            保存并生效
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        深度采集（企业页与巡航）展开子公司时的硬上限：单次任务的可配层级与节点数都不会超过这里的值。
        保存后即时生效，无需重启服务。
      </p>
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1">
          <label className="text-sm font-medium">层级上限（≥1）</label>
          <Input
            type="number"
            min={1}
            value={maxDepth}
            onChange={(e) => setMaxDepth(e.target.value)}
            placeholder="例如 5"
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">节点上限（≥1）</label>
          <Input
            type="number"
            min={1}
            value={maxNodes}
            onChange={(e) => setMaxNodes(e.target.value)}
            placeholder="例如 500"
          />
        </div>
      </div>
      <Alert
        className="mt-4"
        type="info"
        showIcon
        message="层级越深、节点越多，消耗的上游查询次数越多；数据源有风控时建议保守配置。"
      />
    </Modal>
  )
}

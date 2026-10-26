import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal, Select } from 'antd'

import { enterpriseApi, type EnterpriseProvider } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 从企业数据源采集；providers 列表由页面查询后传入（采集与深度采集共用）
export default function CollectModal({ open, projectId, providers, onClose }: {
  open: boolean
  projectId: string
  providers: EnterpriseProvider[]
  onClose: () => void
}) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [collectForm, setCollectForm] = useState({
    provider: 'aqc',
    keyword: '',
    cookie: '',
    username: '',
    password: '',
  })

  const collect = useMutation({
    mutationFn: () =>
      enterpriseApi.collect({
        project_id: Number(projectId),
        provider: collectForm.provider,
        keyword: collectForm.keyword,
        limit: 5,
        cookie: collectForm.cookie || undefined,
        username: collectForm.username || undefined,
        password: collectForm.password || undefined,
      }),
    onSuccess: (res) => {
      toast({
        title: '采集完成',
        description: `命中 ${res.data?.found ?? 0} 家企业，线索 ${res.data?.entities?.length ?? 0} 条`,
      })
      onClose()
      queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
      queryClient.invalidateQueries({ queryKey: ['enterprise-aligned'] })
    },
    onError: (e: any) =>
      toast({ title: '采集失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="从企业数据源采集"
      width={576}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            onClick={() => collect.mutate()}
            disabled={collect.isPending || !collectForm.keyword.trim()}
          >
            {collect.isPending ? '采集中…' : '开始采集'}
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        只产生线索与域名列表，不创建站点、不触发扫描；凭据仅在本次请求内使用，不落库。
      </p>
      <div className="space-y-3">
        <div className="space-y-1">
          <label className="text-sm font-medium">数据源</label>
          <Select
            className="w-full"
            value={collectForm.provider}
            onChange={(v) => setCollectForm({ ...collectForm, provider: v })}
            options={providers.map((p) => ({
              value: p.Name,
              label: `${p.Label}（${p.Auth}）`,
              disabled: !p.Available,
            }))}
          />
          <p className="text-xs text-muted-foreground">
            {providers.find((p) => p.Name === collectForm.provider)?.Hint ?? ''}
          </p>
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">企业名关键词</label>
          <Input
            value={collectForm.keyword}
            onChange={(e) => setCollectForm({ ...collectForm, keyword: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">Cookie（cookie 类数据源）</label>
          <Input
            value={collectForm.cookie}
            onChange={(e) => setCollectForm({ ...collectForm, cookie: e.target.value })}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">账号（账号类数据源）</label>
            <Input
              value={collectForm.username}
              onChange={(e) => setCollectForm({ ...collectForm, username: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">密码</label>
            <Input
              type="password"
              value={collectForm.password}
              onChange={(e) => setCollectForm({ ...collectForm, password: e.target.value })}
            />
          </div>
        </div>
      </div>
    </Modal>
  )
}

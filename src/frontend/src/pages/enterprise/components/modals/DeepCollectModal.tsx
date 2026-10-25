import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Checkbox, Input, Modal, Select } from 'antd'
import { Search } from 'lucide-react'

import { enterpriseApi, type CompanyRef, type EnterpriseProvider } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 深度采集（分支 / 投资 / 域名）；搜索结果与选中项状态常驻本组件
export default function DeepCollectModal({ open, projectId, providers, onClose }: {
  open: boolean
  projectId: string
  providers: EnterpriseProvider[]
  onClose: () => void
}) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [deepForm, setDeepForm] = useState({
    provider: 'aqc',
    keyword: '',
    cookie: '',
    username: '',
    password: '',
    depth: 2,
    max_nodes: 20,
    collect_digital: true,
  })
  const [refs, setRefs] = useState<CompanyRef[]>([])
  const [selectedRef, setSelectedRef] = useState<CompanyRef | null>(null)

  const searchProvider = useMutation({
    mutationFn: () =>
      enterpriseApi.searchProvider({
        project_id: Number(projectId),
        provider: deepForm.provider,
        keyword: deepForm.keyword,
        limit: 10,
        cookie: deepForm.cookie || undefined,
        username: deepForm.username || undefined,
        password: deepForm.password || undefined,
      }),
    onSuccess: (res) => {
      const items = res.data?.items ?? []
      setRefs(items)
      setSelectedRef(items[0] ?? null)
      if (items.length === 0) toast({ title: '没有搜索结果' })
    },
    onError: (e: any) =>
      toast({ title: '搜索失败', description: e?.message, variant: 'destructive' }),
  })

  const discover = useMutation({
    mutationFn: () => {
      if (!selectedRef) throw new Error('先搜索并选择一家企业')
      return enterpriseApi.discover({
        project_id: Number(projectId),
        provider: deepForm.provider,
        ext_id: selectedRef.ext_id,
        name: selectedRef.name,
        depth: deepForm.depth,
        max_nodes: deepForm.max_nodes,
        cookie: deepForm.cookie || undefined,
        username: deepForm.username || undefined,
        password: deepForm.password || undefined,
        collect_digital: deepForm.collect_digital || undefined,
      })
    },
    onSuccess: (res) => {
      toast({
        title: '深度采集已启动',
        description: `任务 ${res.data?.id}，分支/投资将按深度 ${res.data?.depth} 展开`,
      })
      onClose()
      setRefs([])
      setSelectedRef(null)
      queryClient.invalidateQueries({ queryKey: ['enterprise-jobs'] })
      queryClient.invalidateQueries({ queryKey: ['enterprise-candidates'] })
    },
    onError: (e: any) =>
      toast({ title: '启动失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="深度采集（分支 / 投资 / 域名）"
      width={672}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            onClick={() => discover.mutate()}
            disabled={discover.isPending || !selectedRef}
          >
            {discover.isPending ? '启动中…' : '开始深度采集'}
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        先搜索并选中根企业，再按深度逐层展开；节点与翻页有硬上限，结果只进线索与候选域名，不创建站点。
      </p>
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">数据源</label>
            <Select
              className="w-full"
              value={deepForm.provider}
              onChange={(v) => setDeepForm({ ...deepForm, provider: v })}
              options={providers.map((p) => ({
                value: p.Name,
                label: `${p.Label}（${p.Auth}）`,
                disabled: !p.Available,
              }))}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">企业名关键词</label>
            <div className="flex gap-2">
              <Input
                value={deepForm.keyword}
                onChange={(e) => setDeepForm({ ...deepForm, keyword: e.target.value })}
              />
              <Button
                onClick={() => searchProvider.mutate()}
                disabled={searchProvider.isPending || !deepForm.keyword.trim()}
              >
                <Search className="mr-1 h-4 w-4" />
                {searchProvider.isPending ? '搜索中…' : '搜索'}
              </Button>
            </div>
          </div>
          <div className="col-span-2 space-y-1">
            <label className="text-sm font-medium">Cookie（cookie 类数据源）</label>
            <Input
              value={deepForm.cookie}
              onChange={(e) => setDeepForm({ ...deepForm, cookie: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">账号（账号类数据源）</label>
            <Input
              value={deepForm.username}
              onChange={(e) => setDeepForm({ ...deepForm, username: e.target.value })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">密码</label>
            <Input
              type="password"
              value={deepForm.password}
              onChange={(e) => setDeepForm({ ...deepForm, password: e.target.value })}
            />
          </div>
        </div>

        {refs.length > 0 && (
          <div className="max-h-48 space-y-1 overflow-auto rounded-md border p-2">
            {refs.map((r) => (
              <button
                key={r.ext_id}
                className={
                  'block w-full rounded px-2 py-1 text-left text-sm ' +
                  (selectedRef?.ext_id === r.ext_id ? 'bg-primary/10 text-primary' : 'hover:bg-muted')
                }
                onClick={() => setSelectedRef(r)}
              >
                <span className="font-medium">{r.name}</span>
                <span className="ml-2 font-mono text-xs text-muted-foreground">
                  {r.ext_id}
                </span>
              </button>
            ))}
          </div>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1">
            <label className="text-sm font-medium">展开深度（1–3）</label>
            <Input
              type="number"
              min={1}
              max={3}
              value={deepForm.depth}
              onChange={(e) =>
                setDeepForm({ ...deepForm, depth: Number(e.target.value) || 1 })
              }
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">最大节点数（1–200）</label>
            <Input
              type="number"
              min={1}
              max={200}
              value={deepForm.max_nodes}
              onChange={(e) =>
                setDeepForm({ ...deepForm, max_nodes: Number(e.target.value) || 20 })
              }
            />
          </div>
        </div>

        <Checkbox
          checked={deepForm.collect_digital}
          onChange={(e) => setDeepForm({ ...deepForm, collect_digital: e.target.checked })}
        >
          顺带采集数字资产（APP / 小程序 / 公众号 / 新媒体，进数字资产候选池；仅小蓝本支持）
        </Checkbox>
      </div>
    </Modal>
  )
}

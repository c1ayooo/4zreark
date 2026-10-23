import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal, Select } from 'antd'

import { enterpriseApi, type EnterpriseDomain } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

type FormState = {
  name: string
  credit_code: string
  legal_person: string
  industry: string
  address: string
  icp: string
  domains: string
  status: string
  notes: string
}

const emptyForm: FormState = {
  name: '',
  credit_code: '',
  legal_person: '',
  industry: '',
  address: '',
  icp: '',
  domains: '',
  status: 'unverified',
  notes: '',
}

// 新建 / 更新企业线索；表单态常驻本组件，未保存关闭后输入保留（与原页面级行为一致）
export default function CreateEntityModal({ open, projectId, onClose }: {
  open: boolean
  projectId: string
  onClose: () => void
}) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [form, setForm] = useState<FormState>(emptyForm)

  const save = useMutation({
    mutationFn: () => {
      if (Number(projectId) <= 0) throw new Error('先选择归属项目')
      const icp = form.icp
        .split(/[\s,，]+/)
        .map((s) => s.trim())
        .filter(Boolean)
      const domains: EnterpriseDomain[] = form.domains
        .split(/[\s,，|]+/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((d) => ({ domain: d }))
      return enterpriseApi.upsert({
        project_id: Number(projectId),
        name: form.name.trim(),
        credit_code: form.credit_code.trim(),
        legal_person: form.legal_person.trim(),
        industry: form.industry.trim(),
        address: form.address.trim(),
        icp_numbers: icp,
        domains,
        status: form.status,
        notes: form.notes.trim(),
        source: 'manual',
      })
    },
    onSuccess: () => {
      toast({ title: '企业线索已保存' })
      onClose()
      setForm(emptyForm)
      queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
      queryClient.invalidateQueries({ queryKey: ['enterprise-aligned'] })
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="新建 / 更新企业线索"
      width={672}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            onClick={() => save.mutate()}
            disabled={save.isPending || !form.name.trim()}
          >
            {save.isPending ? '保存中…' : '保存'}
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        按项目 + 企业名唯一；同名的 APP 名单会自动对齐。
      </p>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2 space-y-1">
          <label className="text-sm font-medium">企业名</label>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">统一信用代码</label>
          <Input
            value={form.credit_code}
            onChange={(e) => setForm({ ...form, credit_code: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">法人</label>
          <Input
            value={form.legal_person}
            onChange={(e) => setForm({ ...form, legal_person: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">行业</label>
          <Input
            value={form.industry}
            onChange={(e) => setForm({ ...form, industry: e.target.value })}
          />
        </div>
        <div className="space-y-1">
          <label className="text-sm font-medium">状态</label>
          <Select
            className="w-full"
            value={form.status}
            onChange={(v) => setForm({ ...form, status: v })}
            options={[
              { value: 'unverified', label: '待核对' },
              { value: 'verified', label: '已核对' },
              { value: 'ignored', label: '已忽略' },
            ]}
          />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-sm font-medium">地址</label>
          <Input
            value={form.address}
            onChange={(e) => setForm({ ...form, address: e.target.value })}
          />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-sm font-medium">备案号（空格或逗号分隔）</label>
          <Input value={form.icp} onChange={(e) => setForm({ ...form, icp: e.target.value })} />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-sm font-medium">关联域名（空格、逗号或 | 分隔）</label>
          <Input
            value={form.domains}
            onChange={(e) => setForm({ ...form, domains: e.target.value })}
          />
        </div>
        <div className="col-span-2 space-y-1">
          <label className="text-sm font-medium">备注</label>
          <Input value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
        </div>
      </div>
    </Modal>
  )
}

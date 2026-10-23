import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Modal } from 'antd'

import { enterpriseApi } from '@/api/enterprise'
import { useToast } from '@/components/ui/use-toast'

// 批量导入企业线索
export default function ImportEntitiesModal({ open, projectId, onClose }: {
  open: boolean
  projectId: string
  onClose: () => void
}) {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [importText, setImportText] = useState('')

  const importRows = useMutation({
    mutationFn: () => {
      if (Number(projectId) <= 0) throw new Error('先选择归属项目')
      const items = importText
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [name, credit, legal, icp, domains] = line.split(/[,\t]/).map((s) => s.trim())
          if (!name) throw new Error('每行第一个字段必须是企业名')
          return {
            name,
            credit_code: credit || '',
            legal_person: legal || '',
            icp_numbers: icp ? icp.split('|').filter(Boolean) : [],
            domains: domains ? domains.split('|').filter(Boolean).map((d) => ({ domain: d })) : [],
            source: 'import',
            status: 'unverified',
          }
        })
      return enterpriseApi.importRows(Number(projectId), items)
    },
    onSuccess: (res) => {
      toast({
        title: '导入完成',
        description: `新增 ${res.data?.inserted ?? 0} · 更新 ${res.data?.updated ?? 0}`,
      })
      onClose()
      setImportText('')
      queryClient.invalidateQueries({ queryKey: ['enterprise-entities'] })
      queryClient.invalidateQueries({ queryKey: ['enterprise-aligned'] })
    },
    onError: (e: any) =>
      toast({ title: '导入失败', description: e?.message, variant: 'destructive' }),
  })

  return (
    <Modal
      open={open}
      onCancel={onClose}
      title="批量导入企业线索"
      width={672}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            onClick={() => importRows.mutate()}
            disabled={importRows.isPending || !importText.trim()}
          >
            {importRows.isPending ? '导入中…' : '确认导入'}
          </Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        每行一家：企业名,信用代码,法人,备案号(|分隔),域名(|分隔)。空字段留空即可。
      </p>
      <Input.TextArea
        className="font-mono text-sm"
        style={{ height: 224 }}
        placeholder={'示例企业有限公司,91110000XXXXXXXX,张三,京ICP备12345678号,example.com|example.cn'}
        value={importText}
        onChange={(e) => setImportText(e.target.value)}
      />
    </Modal>
  )
}

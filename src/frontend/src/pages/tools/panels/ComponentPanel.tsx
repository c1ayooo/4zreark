import { useState } from 'react'
import { Button, Card, Input } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi, type ComponentCVE } from '@/api/tools'

export default function ComponentPanel() {
  const { toast } = useToast()
  const [product, setProduct] = useState('')
  const [items, setItems] = useState<ComponentCVE[]>([])
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    try {
      setItems(await toolsApi.componentCVEs(product))
    } catch (e) {
      toast({ title: (e as Error)?.message || '查询失败', variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="组件 → CVE">
      <div className="space-y-3">
        <div className="flex gap-2">
          <Input placeholder="产品名，如 apache-tomcat / nginx" value={product} onChange={(e) => setProduct(e.target.value)} />
          <Button type="primary" onClick={run} disabled={!product} loading={busy}>查询</Button>
        </div>
        {items.length === 0 && !busy && <p className="text-xs text-muted-foreground">暂无结果。索引来自本机 POC 库的 template-id/tags 与指纹规则名。</p>}
        {items.length > 0 && (
          <div className="divide-y rounded border">
            {items.map((c) => (
              <div key={c.product + c.cve} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                <span className="font-mono">{c.cve}</span>
                <span className="truncate text-xs text-muted-foreground">{c.evidence}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </Card>
  )
}

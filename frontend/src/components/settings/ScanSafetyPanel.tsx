import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Input, Tag } from 'antd'
import { Ban, Info, Save, ShieldAlert } from 'lucide-react'
import { getErrorMessage } from '@/lib/errors'
import { useToast } from '@/components/ui/use-toast'
import { scannerApi } from '@/api/scanner'
import { useAuthStore } from '@/store/auth'

// 设置页整体已由 AdminMiddleware 保护，这里只按角色隐藏编辑控件。
const canEdit = (role?: string) => role === 'admin' || role === 'operator'

// 扫描安全面板：全局禁扫黑名单（config 只读）+ nuclei 误报黑名单（可编辑）。
// 禁扫黑名单改 config.yaml 重启生效——面板只做展示与引导，不提供假的可编辑态。
export function ScanSafetyPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const role = useAuthStore((s) => s.user?.role)
  const canWrite = canEdit(role)

  const [input, setInput] = useState('')

  const denylistQuery = useQuery({
    queryKey: ['scanner-denylist'],
    queryFn: scannerApi.getDenylist,
  })
  const nucleiQuery = useQuery({
    queryKey: ['nuclei-denylist'],
    queryFn: scannerApi.getNucleiDenylist,
  })

  const [ids, setIds] = useState<string[]>([])
  useEffect(() => {
    if (nucleiQuery.data?.data) setIds(nucleiQuery.data.data.ids)
  }, [nucleiQuery.data])

  const saveMutation = useMutation({
    mutationFn: () => scannerApi.saveNucleiDenylist(ids),
    onSuccess: (res) => {
      setIds(res.data.ids)
      queryClient.invalidateQueries({ queryKey: ['nuclei-denylist'] })
      toast({ title: '已保存，新任务创建时生效' })
    },
    onError: (e) => toast({ title: getErrorMessage(e, '保存失败'), variant: 'destructive' }),
  })

  const addIds = () => {
    const parts = input
      .split(/[\s,;\n]+/)
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean)
    if (parts.length === 0) return
    const merged = Array.from(new Set([...ids, ...parts])).sort()
    setIds(merged)
    setInput('')
  }

  const denylist = denylistQuery.data?.data
  const suffixes = denylist?.deny_domain_suffixes ?? []
  const cidrs = denylist?.deny_cidrs ?? []

  return (
    <div className="space-y-4">
      <Card
        title={
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-2">
              <Ban className="h-4 w-4" />
              全局禁扫黑名单
            </span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              与任务级授权边界叠加：命中的目标一律拒绝扫描。生效值来自 config.yaml 的
              scanner.deny_*，需要修改时编辑配置并重启（控制面与扫描节点使用同一份配置）。
            </span>
          </div>
        }
      >
        <div className="space-y-4">
          <div>
            <div className="mb-1.5 text-sm font-medium">禁扫域名后缀</div>
            {suffixes.length === 0 ? (
              <p className="text-sm text-muted-foreground">未配置（已关闭）</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {suffixes.map((s) => (
                  <Tag key={s} className="font-mono text-xs">
                    *.{s}
                  </Tag>
                ))}
              </div>
            )}
          </div>
          <div>
            <div className="mb-1.5 text-sm font-medium">禁扫网段</div>
            {cidrs.length === 0 ? (
              <p className="text-sm text-muted-foreground">未配置（已关闭）</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {cidrs.map((s) => (
                  <Tag key={s} className="font-mono text-xs">
                    {s}
                  </Tag>
                ))}
              </div>
            )}
          </div>
        </div>
      </Card>

      <Card
        title={
          <div className="flex flex-col gap-1">
            <span className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              Nuclei 误报黑名单
            </span>
            <span className="text-xs font-normal leading-relaxed text-muted-foreground">
              按 template-id 永久排除误报模板（nuclei -eid）。手动扫描、任务流水线与自动验证
              三条链路统一生效；条目即时保存，新任务创建时盖章下发到扫描节点。
            </span>
          </div>
        }
      >
        <div className="space-y-3">
          {canWrite && (
            <div className="flex gap-2">
              <Input
                placeholder="输入 template-id，支持逗号/空格/换行批量粘贴"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onPressEnter={addIds}
              />
              <Button onClick={addIds}>添加</Button>
            </div>
          )}
          {ids.length === 0 ? (
            <p className="text-sm text-muted-foreground">黑名单为空。</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {ids.map((id) => (
                <Tag
                  key={id}
                  className="font-mono text-xs"
                  closable={canWrite}
                  onClose={() => setIds((prev) => prev.filter((x) => x !== id))}
                >
                  {id}
                </Tag>
              ))}
            </div>
          )}
          <div className="flex items-center justify-between">
            <p className="flex items-center gap-1 text-xs text-muted-foreground">
              <Info className="h-3.5 w-3.5" />
              {nucleiQuery.data?.data?.config_ids?.length
                ? `config 兜底 ${nucleiQuery.data.data.config_ids.length} 条始终生效`
                : '改动在保存后对新创建的任务生效'}
            </p>
            {canWrite && (
              <Button
                type="primary"
                icon={<Save className="h-4 w-4" />}
                loading={saveMutation.isPending}
                onClick={() => saveMutation.mutate()}
              >
                保存
              </Button>
            )}
          </div>
        </div>
      </Card>
    </div>
  )
}

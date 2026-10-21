import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { reportApi, type ReportProfile } from '@/api/reports'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useToast } from '@/components/ui/use-toast'
import { FileText, Loader2 } from 'lucide-react'

export type ReportKind = 'asset' | 'vuln'

interface ReportGenerateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** 资产报告必须绑定项目；漏洞报告可留空（按工作区全局） */
  projectId?: number
  projectName?: string
  /** 默认打开的类型，缺省资产报告 */
  defaultKind?: ReportKind
  templates: ReportProfile[]
}

/**
 * 报告生成弹窗：一类报告一档模板，模板说明直接展示，避免用户选完不知道产出什么。
 * 交付信息（客户/编号/密级/测试人/联系方式）只进封面与页脚，可全部留空。
 */
export function ReportGenerateDialog({
  open,
  onOpenChange,
  projectId,
  projectName,
  defaultKind = 'asset',
  templates,
}: ReportGenerateDialogProps) {
  const { toast } = useToast()
  const [kind, setKind] = useState<ReportKind>(defaultKind)
  const [format, setFormat] = useState<'html' | 'pdf' | 'markdown'>('html')
  const [title, setTitle] = useState('')
  const [clientName, setClientName] = useState('')
  const [reportNo, setReportNo] = useState('')
  const [classification, setClassification] = useState('')
  const [tester, setTester] = useState('')
  const [contact, setContact] = useState('')

  const options = templates.filter((t) => t.type === kind)
  const [template, setTemplate] = useState('')
  const activeTemplate =
    options.find((t) => t.id === template)?.id ?? options[0]?.id ?? ''

  // 每次打开回到调用方指定的类型，避免上一次的模板选择残留。
  useEffect(() => {
    if (open) {
      setKind(defaultKind)
      setTemplate('')
    }
  }, [open, defaultKind])

  const mutation = useMutation({
    mutationFn: () =>
      reportApi.generate({
        kind,
        template: activeTemplate,
        format,
        project_id: kind === 'asset' ? projectId : undefined,
        title: title.trim() || undefined,
        delivery: {
          client_name: clientName.trim() || undefined,
          report_no: reportNo.trim() || undefined,
          classification: classification.trim() || undefined,
          tester: tester.trim() || undefined,
          contact: contact.trim() || undefined,
        },
      }),
    onSuccess: async (report) => {
      const scope =
        report.report_kind === 'asset'
          ? `${report.summary?.total_assets ?? 0} 个站点`
          : `${report.summary?.total_vulns ?? 0} 条漏洞`
      toast({ title: '报告已生成', description: `${scope}，开始下载` })
      try {
        await reportApi.download(report)
        onOpenChange(false)
      } catch {
        toast({ title: '下载失败', variant: 'destructive' })
      }
    },
    onError: (err: unknown) => {
      const msg =
        (err as { response?: { data?: { message?: string } } })?.response?.data?.message ||
        '生成报告失败'
      toast({ title: msg, variant: 'destructive' })
    },
  })

  const active = options.find((t) => t.id === activeTemplate)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            生成报告
          </DialogTitle>
          <DialogDescription>
            {kind === 'asset'
              ? `信息收集报告输出${projectName ? `「${projectName}」` : '该项目'}的域名与站点台账`
              : '漏洞报告输出工作区内的漏洞清单、复现与证据'}
            ，格式与模板可切换。
          </DialogDescription>
        </DialogHeader>

        <Tabs
          value={kind}
          onValueChange={(v) => {
            setKind(v as ReportKind)
            setTemplate('')
          }}
        >
          <TabsList className="grid grid-cols-2">
            <TabsTrigger value="asset">信息收集</TabsTrigger>
            <TabsTrigger value="vuln">漏洞交付</TabsTrigger>
          </TabsList>

          <TabsContent value="asset" className="space-y-4 pt-4">
            <div className="space-y-2">
              <Label>交付模板</Label>
              <Select value={activeTemplate} onValueChange={setTemplate}>
                <SelectTrigger>
                  <SelectValue placeholder="选择模板" />
                </SelectTrigger>
                <SelectContent>
                  {options.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {active && (
                <p className="text-muted-foreground text-xs leading-relaxed">
                  {active.description}
                  {active.max_rows ? ` · 清单上限 ${active.max_rows} 行` : ''}
                </p>
              )}
            </div>
          </TabsContent>

          <TabsContent value="vuln" className="space-y-4 pt-4">
            <div className="space-y-2">
              <Label>交付模板</Label>
              <Select value={activeTemplate} onValueChange={setTemplate}>
                <SelectTrigger>
                  <SelectValue placeholder="选择模板" />
                </SelectTrigger>
                <SelectContent>
                  {options.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {active && (
                <p className="text-muted-foreground text-xs leading-relaxed">
                  {active.description}
                </p>
              )}
            </div>
          </TabsContent>
        </Tabs>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="report-format">输出格式</Label>
            <Select value={format} onValueChange={(v) => setFormat(v as typeof format)}>
              <SelectTrigger id="report-format">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="html">HTML</SelectItem>
                <SelectItem value="pdf">PDF（无浏览器时降级 HTML）</SelectItem>
                <SelectItem value="markdown">Markdown</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="report-title">报告名称</Label>
            <Input
              id="report-title"
              placeholder="留空则按模板与日期生成"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="report-client">客户名称</Label>
            <Input
              id="report-client"
              placeholder="选填"
              value={clientName}
              onChange={(e) => setClientName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="report-no">报告编号</Label>
            <Input
              id="report-no"
              placeholder="选填"
              value={reportNo}
              onChange={(e) => setReportNo(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="report-classification">密级</Label>
            <Input
              id="report-classification"
              placeholder="如 内部 / 机密"
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="report-tester">测试人员</Label>
            <Input
              id="report-tester"
              placeholder="选填"
              value={tester}
              onChange={(e) => setTester(e.target.value)}
            />
          </div>
          <div className="space-y-2 sm:col-span-2">
            <Label htmlFor="report-contact">联系方式</Label>
            <Input
              id="report-contact"
              placeholder="选填，写在封面"
              value={contact}
              onChange={(e) => setContact(e.target.value)}
            />
          </div>
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || (kind === 'asset' && !projectId)}
          >
            {mutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                生成中
              </>
            ) : (
              '生成并下载'
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

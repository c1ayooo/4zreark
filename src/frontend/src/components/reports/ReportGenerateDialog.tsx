import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { reportApi, type ReportProfile } from '@/api/reports'
import { Button, Input, Modal, Select, Tabs } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { FileText } from 'lucide-react'

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
  const templateOptions = options.map((t) => ({ value: t.id, label: t.name }))

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
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      width={576}
      title={
        <span className="flex items-center gap-2">
          <FileText className="h-4 w-4" />
          生成报告
        </span>
      }
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={() => onOpenChange(false)}>取消</Button>
          <Button
            onClick={() => mutation.mutate()}
            loading={mutation.isPending}
            disabled={mutation.isPending || (kind === 'asset' && !projectId)}
          >
            {mutation.isPending ? '生成中' : '生成并下载'}
          </Button>
        </div>
      }
    >
      <p className="mb-4 text-sm text-muted-foreground">
        {kind === 'asset'
          ? `信息收集报告输出${projectName ? `「${projectName}」` : '该项目'}的域名与站点台账`
          : '漏洞报告输出工作区内的漏洞清单、复现与证据'}
        ，格式与模板可切换。
      </p>

      <Tabs
        activeKey={kind}
        onChange={(v) => {
          setKind(v as ReportKind)
          setTemplate('')
        }}
        items={[
          {
            key: 'asset',
            label: '信息收集',
            children: (
              <div className="space-y-2">
                <label className="text-sm font-medium">交付模板</label>
                <Select
                  className="w-full"
                  value={activeTemplate || undefined}
                  onChange={(v) => setTemplate(v)}
                  placeholder="选择模板"
                  options={templateOptions}
                />
                {active && (
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    {active.description}
                    {active.max_rows ? ` · 清单上限 ${active.max_rows} 行` : ''}
                  </p>
                )}
              </div>
            ),
          },
          {
            key: 'vuln',
            label: '漏洞交付',
            children: (
              <div className="space-y-2">
                <label className="text-sm font-medium">交付模板</label>
                <Select
                  className="w-full"
                  value={activeTemplate || undefined}
                  onChange={(v) => setTemplate(v)}
                  placeholder="选择模板"
                  options={templateOptions}
                />
                {active && (
                  <p className="text-muted-foreground text-xs leading-relaxed">
                    {active.description}
                  </p>
                )}
              </div>
            ),
          },
        ]}
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <label htmlFor="report-format" className="text-sm font-medium">输出格式</label>
          <Select
            id="report-format"
            className="w-full"
            value={format}
            onChange={(v) => setFormat(v as typeof format)}
            options={[
              { value: 'html', label: 'HTML' },
              { value: 'pdf', label: 'PDF（无浏览器时降级 HTML）' },
              { value: 'markdown', label: 'Markdown' },
            ]}
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="report-title" className="text-sm font-medium">报告名称</label>
          <Input
            id="report-title"
            placeholder="留空则按模板与日期生成"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
          />
        </div>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <label htmlFor="report-client" className="text-sm font-medium">客户名称</label>
          <Input
            id="report-client"
            placeholder="选填"
            value={clientName}
            onChange={(e) => setClientName(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="report-no" className="text-sm font-medium">报告编号</label>
          <Input
            id="report-no"
            placeholder="选填"
            value={reportNo}
            onChange={(e) => setReportNo(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="report-classification" className="text-sm font-medium">密级</label>
          <Input
            id="report-classification"
            placeholder="如 内部 / 机密"
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
          />
        </div>
        <div className="space-y-2">
          <label htmlFor="report-tester" className="text-sm font-medium">测试人员</label>
          <Input
            id="report-tester"
            placeholder="选填"
            value={tester}
            onChange={(e) => setTester(e.target.value)}
          />
        </div>
        <div className="space-y-2 sm:col-span-2">
          <label htmlFor="report-contact" className="text-sm font-medium">联系方式</label>
          <Input
            id="report-contact"
            placeholder="选填，写在封面"
            value={contact}
            onChange={(e) => setContact(e.target.value)}
          />
        </div>
      </div>
    </Modal>
  )
}

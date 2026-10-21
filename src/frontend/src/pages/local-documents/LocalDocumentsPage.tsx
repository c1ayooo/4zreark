import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileUp, Paperclip, RefreshCw, Undo2 } from 'lucide-react'

import { projectApi } from '@/api/projects'
import {
  digitalApi,
  localDocApi,
  type LocalDocCommit,
  type LocalDocPreview,
} from '@/api/digital'
import { Badge } from '@/components/ui/badge'
import { useConfirm } from '@/components/common/confirm-provider'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'

const ACCEPT = '.har,.json,.csv,.txt,.xlsx'

export default function LocalDocumentsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)

  const [projectId, setProjectId] = useState('0')
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<LocalDocPreview | null>(null)
  const [committed, setCommitted] = useState<LocalDocCommit | null>(null)

  const projects = useQuery({ queryKey: ['asset-projects'], queryFn: () => projectApi.list() })
  const canRun = Number(projectId) > 0 && file !== null

  const previewMutation = useMutation({
    mutationFn: () => localDocApi.preview(Number(projectId), file as File),
    onSuccess: (res) => {
      setPreview(res.data)
      setCommitted(null)
    },
    onError: (e: any) =>
      toast({ title: '解析失败', description: e?.message, variant: 'destructive' }),
  })

  const commit = useMutation({
    mutationFn: () => localDocApi.import(preview!.token),
    onSuccess: (res) => {
      setCommitted(res.data)
      setPreview(null)
      toast({
        title: '文档已导入',
        description: `host 记录 ${res.data?.hosts?.records ?? 0} 条 · 名单 ${
          res.data?.inserted ?? 0
        } 条`,
      })
      queryClient.invalidateQueries({ queryKey: ['digital-assets'] })
      queryClient.invalidateQueries({ queryKey: ['digital-imports'] })
    },
    onError: (e: any) =>
      toast({ title: '导入失败', description: e?.message, variant: 'destructive' }),
  })

  const undo = useMutation({
    mutationFn: (batchId: number) => digitalApi.undo(batchId),
    onSuccess: (res) => {
      toast({ title: '名单已撤销', description: `回滚 ${res.data?.deleted ?? 0} 条（host 记录不回收）` })
      setCommitted((c) => (c ? { ...c, batch: null } : c))
      queryClient.invalidateQueries({ queryKey: ['digital-assets'] })
      queryClient.invalidateQueries({ queryKey: ['digital-imports'] })
    },
    onError: (e: any) =>
      toast({ title: '撤销失败', description: e?.message, variant: 'destructive' }),
  })

  const discard = () => {
    if (preview) digitalApi.cancel(preview.token, 'local_doc').catch(() => {})
    setPreview(null)
    setCommitted(null)
    setFile(null)
    if (fileRef.current) fileRef.current.value = ''
  }

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">本地文档</h1>
          <p className="text-sm text-muted-foreground">
            HAR / JSON / CSV / TXT / XLSX 解析 → 预览 → 确认入库；只读文本，不重放请求、不执行页面 JS
          </p>
        </div>
        <Select
          value={projectId}
          onValueChange={(v) => {
            setProjectId(v)
            setPreview(null)
          }}
        >
          <SelectTrigger className="w-48">
            <SelectValue placeholder="选择归属项目" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="0">选择归属项目</SelectItem>
            {(projects.data?.data ?? []).map((p) => (
              <SelectItem key={p.id} value={String(p.id)}>
                {p.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">上传与预览</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            {/* 原生 file input 只做隐藏载体，可见入口统一走 Button，避免出现浏览器默认的丑控件 */}
            <input
              ref={fileRef}
              type="file"
              accept={ACCEPT}
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0] ?? null
                setFile(f)
                setPreview(null)
                setCommitted(null)
              }}
            />
            <Button variant="outline" onClick={() => fileRef.current?.click()}>
              <Paperclip className="mr-2 h-4 w-4" />
              选择文件
            </Button>
            {file ? (
              <span className="text-muted-foreground max-w-[260px] truncate text-sm">{file.name}</span>
            ) : (
              <span className="text-muted-foreground text-sm">支持 HAR / JSON / CSV / TXT / XLSX，最大 4 MiB</span>
            )}
            <Button
              onClick={() => previewMutation.mutate()}
              disabled={!canRun || previewMutation.isPending}
            >
              <FileUp className="mr-2 h-4 w-4" />
              {previewMutation.isPending ? '解析中…' : '解析并预览'}
            </Button>
            {(preview || committed) && (
              <Button variant="outline" onClick={discard}>
                <RefreshCw className="mr-2 h-4 w-4" /> 重新选择
              </Button>
            )}
            {!canRun && (
              <span className="text-sm text-muted-foreground">
                先选择归属项目并挑选文件（最大 4 MiB）
              </span>
            )}
          </div>

          {preview && (
            <div className="space-y-3 rounded-md border bg-muted/30 p-4">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <Badge variant="outline">{preview.format.toUpperCase()}</Badge>
                <span className="text-muted-foreground">{preview.filename}</span>
                <Badge variant="secondary">host {preview.hosts}</Badge>
                <Badge variant="secondary">名称 {preview.names}</Badge>
                <Badge variant="outline">重复 {preview.duplicates}</Badge>
                <Badge variant="outline">无效 {preview.invalid}</Badge>
              </div>

              {preview.sample_hosts.length > 0 && (
                <div className="text-sm">
                  <div className="mb-1 text-xs text-muted-foreground">host 示例</div>
                  <div className="font-mono text-xs">
                    {preview.sample_hosts.slice(0, 10).join('、')}
                  </div>
                </div>
              )}
              {preview.sample_names.length > 0 && (
                <div className="text-sm">
                  <div className="mb-1 text-xs text-muted-foreground">名称示例</div>
                  <div className="text-xs">
                    {preview.sample_names
                      .slice(0, 10)
                      .map((n) => n.name)
                      .join('、')}
                  </div>
                </div>
              )}

              <Button onClick={() => commit.mutate()} disabled={commit.isPending}>
                {commit.isPending
                  ? '导入中…'
                  : `确认导入（host ${preview.hosts} · 名称 ${preview.names}）`}
              </Button>
            </div>
          )}

          {committed && (
            <div className="space-y-2 rounded-md border border-primary/30 bg-primary/5 p-4 text-sm">
              <div className="font-medium">导入完成</div>
              <div className="text-muted-foreground">
                host 记录 {committed.hosts?.records ?? 0} 条 · 新建站点{' '}
                {committed.hosts?.new_sites ?? 0} 个 · 新增端点{' '}
                {committed.hosts?.new_endpoints ?? 0} 个
                {committed.batch
                  ? ` · 名单 ${committed.inserted} 条（回执 #${committed.batch.id}）`
                  : ''}
              </div>
              {committed.batch && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={async () => {
                    if (
                      await confirm(
                        `撤销回执 #${committed.batch!.id} 新增的名单？host 站点不会被回收。`
                      )
                    ) {
                      undo.mutate(committed.batch!.id)
                    }
                  }}
                >
                  <Undo2 className="mr-1 h-3.5 w-3.5" /> 撤销名单
                </Button>
              )}
            </div>
          )}

          <div className="text-xs text-muted-foreground">
            说明：HAR 只读取 request.url 与响应摘要，不重放；XLSX 取第一个工作表，
            与 CSV 同一套列识别规则（host/url/domain、name/app、kind/company/platform）。
            撤销只回滚该批次新增的名单，host 记录按资产生命周期处理。
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Copy, KeyRound, Plus, Power, Trash2 } from 'lucide-react'

import {
  apiKeyApi,
  MCP_SCOPES,
  MCP_SCOPE_GROUPS,
  scopeGroup,
  scopeLabel,
  type APIKey,
  type CreatedAPIKey,
} from '@/api/apiKeys'
import { projectApi } from '@/api/projects'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'

const EXPIRY_OPTIONS = [
  { value: '0', label: '永不过期' },
  { value: '7', label: '7 天' },
  { value: '30', label: '30 天' },
  { value: '90', label: '90 天' },
]

const READ_SCOPES = [
  'assets:read',
  'projects:read',
  'governance:read',
  'tasks:read',
  'vulns:read',
  'pocs:read',
]

const OPS_SCOPES = [
  'assets:read',
  'assets:write',
  'projects:read',
  'projects:write',
  'governance:read',
  'governance:write',
  'tasks:read',
  'tasks:write',
  'scans:run',
]

const SCOPE_PRESETS = [
  { label: '资产只读', scopes: ['assets:read'] },
  { label: '全部只读', scopes: READ_SCOPES },
  { label: '运维', scopes: OPS_SCOPES },
  { label: '完全控制', scopes: MCP_SCOPES.map((s) => s.name) },
]

function keyStatus(key: APIKey) {
  if (!key.enabled) return { label: '已禁用', variant: 'secondary' as const }
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) {
    return { label: '已过期', variant: 'destructive' as const }
  }
  return { label: '可用', variant: 'success' as const }
}

async function copyText(text: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  // 非 HTTPS 环境下 clipboard API 不可用，退回到临时 textarea。
  const el = document.createElement('textarea')
  el.value = text
  document.body.appendChild(el)
  el.select()
  document.execCommand('copy')
  document.body.removeChild(el)
}

export function MCPAccessPanel() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [projectID, setProjectID] = useState('0')
  const [expiryDays, setExpiryDays] = useState('0')
  const [scopes, setScopes] = useState<string[]>(['assets:read'])
  const [createdKey, setCreatedKey] = useState<CreatedAPIKey | null>(null)
  const [deleting, setDeleting] = useState<APIKey | null>(null)

  const endpoint = useMemo(
    () => (typeof window === 'undefined' ? '/api/mcp' : `${window.location.origin}/api/mcp`),
    [],
  )

  const { data, isLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: apiKeyApi.list,
  })
  const keys = data?.data?.items ?? []

  const { data: projectsData } = useQuery({
    queryKey: ['projects'],
    queryFn: projectApi.list,
    enabled: createOpen,
  })
  const projects = projectsData?.data ?? []

  const createMutation = useMutation({
    mutationFn: apiKeyApi.create,
    onSuccess: (res) => {
      setCreatedKey(res.data)
      setCreateOpen(false)
      setName('')
      setProjectID('0')
      setExpiryDays('0')
      setScopes(['assets:read'])
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
    onError: (err: { message?: string }) => {
      toast({ title: err?.message || '创建 API key 失败', variant: 'destructive' })
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      apiKeyApi.setEnabled(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
    onError: (err: { message?: string }) => {
      toast({ title: err?.message || '更新状态失败', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiKeyApi.remove(id),
    onSuccess: () => {
      toast({ title: 'API key 已删除' })
      setDeleting(null)
      queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
    onError: (err: { message?: string }) => {
      toast({ title: err?.message || '删除失败', variant: 'destructive' })
    },
  })

  const submitCreate = () => {
    if (!name.trim()) {
      toast({ title: '请填写凭证名称', variant: 'destructive' })
      return
    }
    if (scopes.length === 0) {
      toast({ title: '请至少选择一个权限', variant: 'destructive' })
      return
    }
    const days = Number(expiryDays)
    createMutation.mutate({
      name: name.trim(),
      project_id: projectID === '0' ? 0 : Number(projectID),
      scopes,
      expires_at: days > 0 ? new Date(Date.now() + days * 86400_000).toISOString() : null,
    })
  }

  const toggleScope = (scopeName: string, checked: boolean) => {
    setScopes((prev) =>
      checked ? Array.from(new Set([...prev, scopeName])) : prev.filter((s) => s !== scopeName),
    )
  }

  const handleCopy = async (text: string) => {
    try {
      await copyText(text)
      toast({ title: '已复制到剪贴板' })
    } catch {
      toast({ title: '复制失败，请手动选择文本', variant: 'destructive' })
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <KeyRound className="h-4 w-4" />
                MCP / 外部平台接入
              </CardTitle>
              <CardDescription>
                签发只读 API key，供外部平台或 MCP 客户端读取项目所属资产与详情。
                key 绑定项目后无法访问其它项目。
              </CardDescription>
            </div>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus className="mr-2 h-4 w-4" />
              新建 API key
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="rounded-lg border bg-muted/40 p-4 text-sm">
            <div className="mb-2 flex items-center gap-2 font-medium">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              MCP 端点（Streamable HTTP）
            </div>
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-background px-2 py-1 font-mono text-xs">
                {endpoint}
              </code>
              <Button variant="outline" size="sm" onClick={() => handleCopy(endpoint)}>
                <Copy className="mr-2 h-3.5 w-3.5" />
                复制
              </Button>
            </div>
            <div className="text-muted-foreground mt-3 space-y-1 text-xs">
              <p>
                鉴权：<code className="font-mono">Authorization: Bearer &lt;API key&gt;</code>
                ，或 <code className="font-mono">X-API-Key: &lt;API key&gt;</code>
              </p>
              <p>
                工具按 key 权限开放：资产、项目、治理、任务、扫描、漏洞、POC。
                写操作与扫描会修改平台数据或发起真实网络流量，请只授予可信平台。
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>访问凭证</CardTitle>
          <CardDescription>
            明文只在创建时显示一次；列表中仅保留前缀。停用后客户端立即无法访问。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>项目范围</TableHead>
                  <TableHead>权限</TableHead>
                  <TableHead>Key</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>最近使用</TableHead>
                  <TableHead>创建时间</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted-foreground py-8 text-center">
                      加载中…
                    </TableCell>
                  </TableRow>
                ) : keys.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted-foreground py-8 text-center">
                      还没有 API key，点击右上角「新建 API key」签发第一把。
                    </TableCell>
                  </TableRow>
                ) : (
                  keys.map((key) => {
                    const status = keyStatus(key)
                    return (
                      <TableRow key={key.id}>
                        <TableCell className="font-medium">{key.name}</TableCell>
                        <TableCell>
                          {key.project_id ? (
                            <span>
                              {key.project_name}
                              <span className="text-muted-foreground ml-1 font-mono text-xs">
                                {key.project_code}
                              </span>
                            </span>
                          ) : (
                            <Badge variant="warning">全部项目</Badge>
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex max-w-[220px] flex-wrap gap-1">
                            {Array.from(new Set((key.scopes ?? []).map(scopeGroup))).map((group) => (
                              <Badge key={group} variant="outline">
                                {group}
                              </Badge>
                            ))}
                            {(key.scopes ?? []).length === 0 && (
                              <span className="text-muted-foreground text-xs">无</span>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <code className="font-mono text-xs">{key.key_prefix}…</code>
                        </TableCell>
                        <TableCell>
                          <Badge variant={status.variant}>{status.label}</Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
                          {key.last_used_at ? formatDate(key.last_used_at) : '从未使用'}
                        </TableCell>
                        <TableCell className="text-muted-foreground whitespace-nowrap text-xs">
                          {formatDate(key.created_at)}
                        </TableCell>
                        <TableCell className="text-right whitespace-nowrap">
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={toggleMutation.isPending}
                            onClick={() =>
                              toggleMutation.mutate({ id: key.id, enabled: !key.enabled })
                            }
                          >
                            <Power className="mr-1.5 h-3.5 w-3.5" />
                            {key.enabled ? '停用' : '启用'}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive hover:text-destructive"
                            onClick={() => setDeleting(key)}
                          >
                            <Trash2 className="mr-1.5 h-3.5 w-3.5" />
                            删除
                          </Button>
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* 新建凭证 */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>新建 API key</DialogTitle>
            <DialogDescription>
              选择项目后，这把 key 只能读取该项目的资产；选择「全部项目」会授予全库只读权限。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="api-key-name">名称</Label>
              <Input
                id="api-key-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如：SIEM 对接 / 外部资产看板"
                maxLength={120}
              />
            </div>
            <div className="space-y-2">
              <Label>项目范围</Label>
              <Select value={projectID} onValueChange={setProjectID}>
                <SelectTrigger>
                  <SelectValue placeholder="选择项目" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="0">全部项目（只读）</SelectItem>
                  {projects.map((p) => (
                    <SelectItem key={p.id} value={String(p.id)}>
                      {p.name}（{p.code}）
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>有效期</Label>
              <Select value={expiryDays} onValueChange={setExpiryDays}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EXPIRY_OPTIONS.map((opt) => (
                    <SelectItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label>权限</Label>
                <div className="flex flex-wrap gap-1">
                  {SCOPE_PRESETS.map((preset) => (
                    <Button
                      key={preset.label}
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 px-2 text-xs"
                      onClick={() => setScopes(preset.scopes)}
                    >
                      {preset.label}
                    </Button>
                  ))}
                </div>
              </div>
              <div className="max-h-64 space-y-3 overflow-y-auto rounded-md border p-3">
                {MCP_SCOPE_GROUPS.map((group) => (
                  <div key={group}>
                    <div className="text-muted-foreground mb-1 text-xs font-medium">{group}</div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {MCP_SCOPES.filter((s) => s.group === group).map((s) => (
                        <label key={s.name} className="flex items-start gap-2 text-sm">
                          <Checkbox
                            className="mt-0.5"
                            checked={scopes.includes(s.name)}
                            onCheckedChange={(v) => toggleScope(s.name, v === true)}
                          />
                          <span>
                            <span className={s.dangerous ? 'text-destructive' : ''}>{s.label}</span>
                            <span className="text-muted-foreground block text-xs">{s.description}</span>
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {scopes.some((name) => MCP_SCOPES.find((s) => s.name === name)?.dangerous) && (
                <p className="text-destructive text-xs">
                  写/扫描权限会产生真实数据变更或网络流量，请只授予可信平台。
                </p>
              )}
              {projectID !== '0' && (
                <p className="text-muted-foreground text-xs">
                  漏洞/POC 权限只对「全部项目」的 key 生效；绑定项目的 key 即使勾选也无法调用。
                </p>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              取消
            </Button>
            <Button onClick={submitCreate} disabled={createMutation.isPending}>
              {createMutation.isPending ? '创建中…' : '创建'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 明文只显示一次 */}
      <Dialog open={!!createdKey} onOpenChange={(open) => !open && setCreatedKey(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>API key 已创建</DialogTitle>
            <DialogDescription>
              请立即复制并保存到外部平台。关闭此窗口后，平台无法再次显示完整 key。
            </DialogDescription>
          </DialogHeader>
          {createdKey && (
            <div className="space-y-3">
              <code className="block break-all rounded-md border bg-muted p-3 font-mono text-xs">
                {createdKey.key}
              </code>
              <div className="text-muted-foreground text-xs">
                项目范围：{createdKey.project_name || '全部项目'} · 有效期：
                {createdKey.expires_at ? formatDate(createdKey.expires_at) : '永不过期'}
              </div>
              <div className="text-muted-foreground text-xs">
                权限：{(createdKey.scopes ?? []).map(scopeLabel).join('、') || '未声明'}
              </div>
            </div>
          )}
          <DialogFooter>
            <Button
              onClick={() => createdKey && handleCopy(createdKey.key)}
              disabled={!createdKey}
            >
              <Copy className="mr-2 h-4 w-4" />
              复制 key
            </Button>
            <Button variant="outline" onClick={() => setCreatedKey(null)}>
              我已保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 删除确认 */}
      <AlertDialog open={!!deleting} onOpenChange={(open) => !open && setDeleting(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除 API key？</AlertDialogTitle>
            <AlertDialogDescription>
              删除后使用该 key 的外部平台会立即失去访问权限，且无法恢复。
              {deleting ? ` 即将删除「${deleting.name}」。` : ''}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => deleting && deleteMutation.mutate(deleting.id)}
            >
              删除
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

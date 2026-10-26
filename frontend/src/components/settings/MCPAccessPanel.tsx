import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Checkbox, Input, Modal, Select, Table, Tag } from 'antd'
import type { ColumnsType } from 'antd/es/table'
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

function keyStatus(key: APIKey): { label: string; color?: string } {
  if (!key.enabled) return { label: '已禁用' }
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) {
    return { label: '已过期', color: 'error' }
  }
  return { label: '可用', color: 'success' }
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

  const columns: ColumnsType<APIKey> = [
    {
      title: '名称',
      dataIndex: 'name',
      render: (_, k) => <span className="font-medium">{k.name}</span>,
    },
    {
      title: '项目范围',
      render: (_, k) =>
        k.project_id ? (
          <span>
            {k.project_name}
            <span className="text-muted-foreground ml-1 font-mono text-xs">{k.project_code}</span>
          </span>
        ) : (
          <Tag color="warning">全部项目</Tag>
        ),
    },
    {
      title: '权限',
      render: (_, k) => (
        <div className="flex max-w-[220px] flex-wrap gap-1">
          {Array.from(new Set((k.scopes ?? []).map(scopeGroup))).map((group) => (
            <Tag key={group}>{group}</Tag>
          ))}
          {(k.scopes ?? []).length === 0 && (
            <span className="text-muted-foreground text-xs">无</span>
          )}
        </div>
      ),
    },
    {
      title: 'Key',
      render: (_, k) => <code className="font-mono text-xs">{k.key_prefix}…</code>,
    },
    {
      title: '状态',
      render: (_, k) => {
        const status = keyStatus(k)
        return <Tag color={status.color}>{status.label}</Tag>
      },
    },
    {
      title: '最近使用',
      className: 'text-muted-foreground whitespace-nowrap text-xs',
      render: (_, k) => (k.last_used_at ? formatDate(k.last_used_at) : '从未使用'),
    },
    {
      title: '创建时间',
      className: 'text-muted-foreground whitespace-nowrap text-xs',
      render: (_, k) => formatDate(k.created_at),
    },
    {
      title: '操作',
      align: 'right',
      className: 'whitespace-nowrap',
      render: (_, k) => (
        <span className="inline-flex gap-1">
          <Button
            type="text"
            size="small"
            disabled={toggleMutation.isPending}
            onClick={() => toggleMutation.mutate({ id: k.id, enabled: !k.enabled })}
            icon={<Power className="h-3.5 w-3.5" />}
          >
            {k.enabled ? '停用' : '启用'}
          </Button>
          <Button
            type="text"
            size="small"
            danger
            onClick={() => setDeleting(k)}
            icon={<Trash2 className="h-3.5 w-3.5" />}
          >
            删除
          </Button>
        </span>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <section className="bg-card text-card-foreground rounded-xl border shadow">
        <div className="flex flex-col space-y-1.5 p-6">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="flex items-center gap-2 font-semibold leading-none tracking-tight">
                <KeyRound className="h-4 w-4" />
                MCP / 外部平台接入
              </h3>
              <p className="text-muted-foreground mt-1.5 text-sm">
                签发只读 API key，供外部平台或 MCP 客户端读取项目所属资产与详情。
                key 绑定项目后无法访问其它项目。
              </p>
            </div>
            <Button onClick={() => setCreateOpen(true)} icon={<Plus className="h-4 w-4" />}>
              新建 API key
            </Button>
          </div>
        </div>
        <div className="space-y-3 p-6 pt-0">
          <div className="rounded-lg border bg-muted/40 p-4 text-sm">
            <div className="mb-2 flex items-center gap-2 font-medium">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              MCP 端点（Streamable HTTP）
            </div>
            <div className="flex items-center gap-2">
              <code className="bg-background min-w-0 flex-1 break-all rounded px-2 py-1 font-mono text-xs">
                {endpoint}
              </code>
              <Button
                size="small"
                onClick={() => handleCopy(endpoint)}
                icon={<Copy className="h-3.5 w-3.5" />}
              >
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
        </div>
      </section>

      <section className="bg-card text-card-foreground rounded-xl border shadow">
        <div className="flex flex-col space-y-1.5 p-6">
          <h3 className="font-semibold leading-none tracking-tight">访问凭证</h3>
          <p className="text-muted-foreground mt-1.5 text-sm">
            明文只在创建时显示一次；列表中仅保留前缀。停用后客户端立即无法访问。
          </p>
        </div>
        <div className="p-6 pt-0">
          <div className="overflow-x-auto rounded-md border">
            <Table<APIKey>
              columns={columns}
              dataSource={keys}
              rowKey="id"
              pagination={false}
              loading={isLoading}
              locale={{ emptyText: '还没有 API key，点击右上角「新建 API key」签发第一把。' }}
            />
          </div>
        </div>
      </section>

      {/* 新建凭证 */}
      <Modal
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        title="新建 API key"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setCreateOpen(false)}>取消</Button>
            <Button loading={createMutation.isPending} onClick={submitCreate}>
              创建
            </Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          选择项目后，这把 key 只能读取该项目的资产；选择「全部项目」会授予全库只读权限。
        </p>
        <div className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="api-key-name" className="text-sm font-medium">
              名称
            </label>
            <Input
              id="api-key-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="例如：SIEM 对接 / 外部资产看板"
              maxLength={120}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">项目范围</label>
            <Select
              className="w-full"
              value={projectID}
              onChange={setProjectID}
              options={[
                { value: '0', label: '全部项目（只读）' },
                ...projects.map((p) => ({ value: String(p.id), label: `${p.name}（${p.code}）` })),
              ]}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">有效期</label>
            <Select
              className="w-full"
              value={expiryDays}
              onChange={setExpiryDays}
              options={EXPIRY_OPTIONS}
            />
          </div>
          <div className="space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <label className="text-sm font-medium">权限</label>
              <div className="flex flex-wrap gap-1">
                {SCOPE_PRESETS.map((preset) => (
                  <Button
                    key={preset.label}
                    size="small"
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
                          onChange={(e) => toggleScope(s.name, e.target.checked)}
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
      </Modal>

      {/* 明文只显示一次 */}
      <Modal
        open={!!createdKey}
        onCancel={() => setCreatedKey(null)}
        title="API key 已创建"
        footer={
          <div className="flex justify-end gap-2">
            <Button
              icon={<Copy className="h-4 w-4" />}
              onClick={() => createdKey && handleCopy(createdKey.key)}
              disabled={!createdKey}
            >
              复制 key
            </Button>
            <Button onClick={() => setCreatedKey(null)}>我已保存</Button>
          </div>
        }
      >
        <p className="text-muted-foreground mb-4 text-sm">
          请立即复制并保存到外部平台。关闭此窗口后，平台无法再次显示完整 key。
        </p>
        {createdKey && (
          <div className="space-y-3">
            <code className="bg-muted block break-all rounded-md border p-3 font-mono text-xs">
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
      </Modal>

      {/* 删除确认 */}
      <Modal
        open={!!deleting}
        onCancel={() => setDeleting(null)}
        title="删除 API key？"
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setDeleting(null)}>取消</Button>
            <Button
              danger
              loading={deleteMutation.isPending}
              onClick={() => deleting && deleteMutation.mutate(deleting.id)}
            >
              删除
            </Button>
          </div>
        }
      >
        <p className="text-sm">
          删除后使用该 key 的外部平台会立即失去访问权限，且无法恢复。
          {deleting ? ` 即将删除「${deleting.name}」。` : ''}
        </p>
      </Modal>
    </div>
  )
}

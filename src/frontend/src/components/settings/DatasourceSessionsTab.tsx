import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge, Button, Input, Modal, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { KeyRound, QrCode, RefreshCw, Trash2 } from 'lucide-react'

import {
  datasourceSessionApi,
  datasourceSessionStatusLabel,
  type DatasourceSessionView,
} from '@/api/datasourceSession'
import { useToast } from '@/components/ui/use-toast'

// 数据源会话 tab：六源状态清单 + 平台内扫码登录 + Cookie/账号密码手动维护。

const statusTag = (status: string) => {
  if (status === 'active') return <Tag color="success">{datasourceSessionStatusLabel[status]}</Tag>
  if (status === 'expired') return <Tag color="error">{datasourceSessionStatusLabel[status]}</Tag>
  return <Tag>{datasourceSessionStatusLabel[status] ?? status}</Tag>
}

export default function DatasourceSessionsTab() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const list = useQuery({ queryKey: ['datasource-sessions'], queryFn: () => datasourceSessionApi.list() })

  const [qrProvider, setQrProvider] = useState<DatasourceSessionView | null>(null)
  const [qrImage, setQrImage] = useState('')
  const [editProvider, setEditProvider] = useState<DatasourceSessionView | null>(null)
  const [editCookie, setEditCookie] = useState('')
  const [editUsername, setEditUsername] = useState('')
  const [editPassword, setEditPassword] = useState('')
  const pollTimer = useRef<ReturnType<typeof setInterval> | null>(null)

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['datasource-sessions'] })

  const stopPoll = () => {
    if (pollTimer.current) {
      clearInterval(pollTimer.current)
      pollTimer.current = null
    }
  }

  useEffect(() => stopPoll, [])

  const openQr = (p: DatasourceSessionView) => {
    setQrProvider(p)
    setQrImage('')
    qrBegin.mutate(p)
  }

  const qrBegin = useMutation({
    mutationFn: (p: DatasourceSessionView) => datasourceSessionApi.qrBegin(p.name),
    onSuccess: (res, p) => {
      const sessionId = res.data?.session_id
      if (!sessionId) return
      setQrImage(res.data?.qr_image ?? '')
      const expiresAt = res.data?.expires_at ? new Date(res.data.expires_at).getTime() : 0
      stopPoll()
      let errStreak = 0
      pollTimer.current = setInterval(async () => {
        // 前端到期即停：上游二维码存活期短于会话 TTL 时不再空转
        if (expiresAt && Date.now() > expiresAt) {
          stopPoll()
          toast({
            title: '二维码已过期',
            description: '请关闭弹窗后重新点「扫码登录」',
            variant: 'destructive',
          })
          return
        }
        try {
          const poll = await datasourceSessionApi.qrPoll(p.name, sessionId)
          errStreak = 0
          const status = poll.data?.status
          // 上游二维码自动刷新，每次轮询带回最新截图，避免扫到过期码
          if (poll.data?.qr_image) setQrImage(poll.data.qr_image)
          if (status === 'confirmed') {
            stopPoll()
            toast({
              title: '登录成功',
              description: poll.data?.message || `${p.label} 会话已保存`,
            })
            setQrProvider(null)
            invalidate()
          } else if (status === 'expired') {
            stopPoll()
            toast({
              title: '二维码已过期',
              description: '请关闭弹窗后重新点「扫码登录」',
              variant: 'destructive',
            })
          }
        } catch (e: any) {
          errStreak++
          if (errStreak >= 3) {
            stopPoll()
            toast({
              title: '轮询失败',
              description: e?.message || '请关闭弹窗重试',
              variant: 'destructive',
            })
          }
        }
      }, 2000)
    },
    onError: (e: any) => {
      toast({ title: '扫码发起失败', description: e?.message, variant: 'destructive' })
      setQrProvider(null)
    },
  })

  const qrCancel = (p: DatasourceSessionView) => {
    const sessionId = qrBegin.data?.data?.session_id
    if (sessionId) datasourceSessionApi.qrCancel(p.name, sessionId).catch(() => {})
    stopPoll()
    setQrProvider(null)
  }

  const save = useMutation({
    mutationFn: () =>
      datasourceSessionApi.save(editProvider!.name, {
        cookie: editProvider!.auth === 'cookie' ? editCookie : undefined,
        username: editProvider!.auth === 'account' ? editUsername : undefined,
        password: editProvider!.auth === 'account' && editPassword ? editPassword : undefined,
      }),
    onSuccess: () => {
      toast({ title: '会话已保存' })
      setEditProvider(null)
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' }),
  })

  const remove = useMutation({
    mutationFn: (p: DatasourceSessionView) => datasourceSessionApi.remove(p.name),
    onSuccess: () => {
      toast({ title: '会话已清除' })
      invalidate()
    },
    onError: (e: any) =>
      toast({ title: '清除失败', description: e?.message, variant: 'destructive' }),
  })

  const openEdit = (p: DatasourceSessionView) => {
    setEditProvider(p)
    setEditCookie('')
    setEditUsername('')
    setEditPassword('')
  }

  const columns: TableProps<DatasourceSessionView>['columns'] = [
    {
      title: '数据源',
      dataIndex: 'label',
      key: 'label',
      render: (v: string, p) => (
        <div>
          <span className="text-sm font-medium">{v}</span>
          <span className="ml-2 font-mono text-xs text-muted-foreground">{p.name}</span>
        </div>
      ),
    },
    {
      title: '认证方式',
      dataIndex: 'auth',
      key: 'auth',
      width: 110,
      render: (v: string) => <Tag>{v === 'account' ? '账号密码' : 'Cookie'}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => statusTag(v),
    },
    {
      title: '已存凭据',
      key: 'stored',
      width: 140,
      render: (_, p) => (
        <div className="flex gap-1">
          {p.has_cookie && <Badge status="success" text="Cookie" />}
          {p.has_account && <Badge status="success" text="账号密码" />}
          {!p.has_cookie && !p.has_account && (
            <span className="text-xs text-muted-foreground">—</span>
          )}
        </div>
      ),
    },
    {
      title: '说明',
      dataIndex: 'hint',
      key: 'hint',
      ellipsis: true,
      render: (v: string) => <span className="text-xs text-muted-foreground">{v}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      render: (_, p) => (
        <div className="flex flex-wrap gap-1">
          {p.qr_supported && p.available && (
            <Button size="small" icon={<QrCode className="h-3.5 w-3.5" />} onClick={() => openQr(p)}>
              扫码登录
            </Button>
          )}
          {p.auth === 'account' && p.available && (
            <Button
              size="small"
              icon={<KeyRound className="h-3.5 w-3.5" />}
              onClick={() => openEdit(p)}
            >
              账号密码
            </Button>
          )}
          {p.auth === 'cookie' && p.available && (
            <Button size="small" onClick={() => openEdit(p)}>
              粘贴 Cookie
            </Button>
          )}
          {(p.has_cookie || p.has_account) && (
            <Button
              size="small"
              danger
              type="text"
              icon={<Trash2 className="h-3.5 w-3.5" />}
              onClick={() => remove.mutate(p)}
            />
          )}
        </div>
      ),
    },
  ]

  const items = list.data?.data?.items ?? []

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          企业数据源的登录会话统一托管：扫码或手动维护一次，采集/深度采集/巡航自动使用；
          上游风控导致会话失效时此处会显示「已失效」，重新登录一次即可。
        </p>
        <Button icon={<RefreshCw className="h-4 w-4" />} onClick={() => list.refetch()}>
          刷新
        </Button>
      </div>

      <Table
        columns={columns}
        dataSource={items}
        rowKey="name"
        loading={list.isLoading}
        pagination={false}
      />

      <Modal
        open={!!qrProvider}
        onCancel={() => qrProvider && qrCancel(qrProvider)}
        width={420}
        title={`扫码登录 · ${qrProvider?.label ?? ''}`}
        footer={
          <Button onClick={() => qrProvider && qrCancel(qrProvider)}>关闭</Button>
        }
      >
        <div className="flex flex-col items-center gap-3 py-2">
          {qrBegin.isPending && <div className="py-8 text-sm text-muted-foreground">正在打开登录页…</div>}
          {qrBegin.isError && (
            <div className="py-2 text-sm text-destructive">{(qrBegin.error as any)?.message}</div>
          )}
          {qrImage && (
            <>
              <img
                src={qrImage}
                alt="登录二维码"
                className="h-56 w-56 rounded border bg-white object-contain p-2"
              />
              <p className="text-center text-xs text-muted-foreground">
                使用{qrBegin.data?.data?.scan_hint || '对应手机 APP'}扫一扫，
                在手机上确认登录；登录成功后会话自动保存。
              </p>
            </>
          )}
        </div>
      </Modal>

      <Modal
        open={!!editProvider}
        onCancel={() => setEditProvider(null)}
        width={560}
        title={`维护会话 · ${editProvider?.label ?? ''}`}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setEditProvider(null)}>取消</Button>
            <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>
              保存
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          <p className="text-xs text-muted-foreground">
            {editProvider?.auth === 'account'
              ? '账号密码登录后由平台自动维持会话；留空表示保持已保存的值不变。'
              : '粘贴网页版登录态 Cookie（浏览器 F12 → Network → 任意请求的 Cookie 请求头整串）；留空表示保持已保存的值不变。'}
          </p>
          {editProvider?.auth === 'cookie' && (
            <Input.TextArea
              className="font-mono text-xs"
              rows={5}
              placeholder="k=v; k2=v2; ..."
              value={editCookie}
              onChange={(e) => setEditCookie(e.target.value)}
            />
          )}
          {editProvider?.auth === 'account' && (
            <>
              <Input
                placeholder={editProvider?.name === 'fengniao' ? '手机号' : '账号'}
                value={editUsername}
                onChange={(e) => setEditUsername(e.target.value)}
              />
              <Input.Password
                placeholder="密码"
                value={editPassword}
                onChange={(e) => setEditPassword(e.target.value)}
              />
            </>
          )}
          <p className="text-xs text-muted-foreground">{editProvider?.hint}</p>
        </div>
      </Modal>
    </div>
  )
}

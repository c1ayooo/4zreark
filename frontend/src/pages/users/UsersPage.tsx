import { useState } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { userApi } from '@/api/auth'
import { registrationApi } from '@/api/registration'
import type { RegistrationCode } from '@/api/registration'
import type { User } from '@/store/auth'
import { Button, Input, Modal, Select, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { useConfirm } from '@/components/common/confirm-provider'
import { getErrorMessage } from '@/lib/errors'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import { Search, Plus, Trash2, RefreshCw, Key, Ticket, Copy } from 'lucide-react'

export default function UsersPage() {
  const { toast } = useToast()
  const confirm = useConfirm()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isPasswordDialogOpen, setIsPasswordDialogOpen] = useState(false)
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [newUser, setNewUser] = useState({
    username: '',
    email: '',
    password: '',
    nickname: '',
    role: 'user',
  })
  const [regOpen, setRegOpen] = useState(false)
  const [regForm, setRegForm] = useState({
    count: 5,
    role: 'user',
    maxUses: 1,
    expiresAt: '',
  })
  const [generatedCodes, setGeneratedCodes] = useState<string[]>([])

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['users', page, search],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      userApi.getUsers({
        page,
        pageSize: 10,
        search,
      }),
  })

  const regCodes = useQuery({
    queryKey: ['registration-codes'],
    queryFn: () => registrationApi.list(100),
  })

  const createMutation = useMutation({
    mutationFn: userApi.createUser,
    onSuccess: () => {
      toast({ title: '创建成功' })
      setIsCreateDialogOpen(false)
      setNewUser({ username: '', email: '', password: '', nickname: '', role: 'user' })
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '创建失败'), variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: userApi.deleteUser,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '删除失败'), variant: 'destructive' })
    },
  })

  const generateCodes = useMutation({
    mutationFn: () =>
      registrationApi.generate({
        count: regForm.count,
        role: regForm.role,
        max_uses: regForm.maxUses,
        expires_at: regForm.expiresAt ? new Date(regForm.expiresAt).toISOString() : null,
      }),
    onSuccess: (res) => {
      setGeneratedCodes(res.data?.codes ?? [])
      toast({ title: `已生成 ${res.data?.count ?? 0} 个注册码` })
      queryClient.invalidateQueries({ queryKey: ['registration-codes'] })
    },
    onError: (e: any) =>
      toast({ title: '生成失败', description: e?.message, variant: 'destructive' }),
  })

  const deleteCode = useMutation({
    mutationFn: (code: string) => registrationApi.remove(code),
    onSuccess: () => {
      toast({ title: '注册码已删除' })
      queryClient.invalidateQueries({ queryKey: ['registration-codes'] })
    },
    onError: (e: any) =>
      toast({ title: '删除失败', description: e?.message, variant: 'destructive' }),
  })

  const resetPasswordMutation = useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      userApi.resetPassword(id, password),
    onSuccess: () => {
      toast({ title: '密码修改成功' })
      setIsPasswordDialogOpen(false)
      setNewPassword('')
      setSelectedUserId(null)
    },
    onError: () => {
      toast({ title: '密码修改失败', variant: 'destructive' })
    },
  })

  const openPasswordDialog = (userId: string) => {
    setSelectedUserId(userId)
    setNewPassword('')
    setIsPasswordDialogOpen(true)
  }

  const handleChangePassword = () => {
    if (!newPassword || newPassword.length < 6) {
      toast({ title: '密码至少6位', variant: 'destructive' })
      return
    }
    if (selectedUserId) {
      resetPasswordMutation.mutate({ id: selectedUserId, password: newPassword })
    }
  }

  const handleCreate = () => {
    if (!newUser.username || !newUser.email || !newUser.password) {
      toast({ title: '请填写完整', variant: 'destructive' })
      return
    }
    createMutation.mutate(newUser)
  }

  const users = data?.data?.list || []
  const total = data?.data?.total || 0

  const getRoleLabel = (role: string) => {
    const labels: Record<string, string> = {
      admin: '管理员',
      user: '普通用户',
      viewer: '访客',
    }
    return labels[role] || role
  }

  const getRoleColor = (role: string) => {
    const colors: Record<string, string> = {
      admin: 'bg-red-500 text-white',
      user: 'bg-blue-500 text-white',
      viewer: 'bg-gray-500 text-white',
    }
    return colors[role] || 'bg-gray-500 text-white'
  }

  const userColumns: TableProps<User>['columns'] = [
    {
      title: '用户名',
      dataIndex: 'username',
      key: 'username',
      width: 140,
      render: (v: string) => <span className="font-medium">{v}</span>,
    },
    {
      title: '邮箱',
      dataIndex: 'email',
      key: 'email',
      width: 220,
      ellipsis: true,
    },
    {
      title: '昵称',
      dataIndex: 'nickname',
      key: 'nickname',
      width: 140,
      render: (v: string) => v || '-',
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      width: 100,
      render: (v: string) => <Tag className={cn(getRoleColor(v))}>{getRoleLabel(v)}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) => (
        <Tag className={cn(getStatusColor(v))}>{v === 'active' ? '正常' : '禁用'}</Tag>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'createdAt',
      key: 'createdAt',
      width: 170,
      render: (v: string) => formatDate(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      render: (_, user) => (
        <div className="flex gap-1">
          <Button
            type="text"
            size="small"
            aria-label="修改密码"
            icon={<Key className="h-4 w-4" />}
            onClick={() => openPasswordDialog(user.id)}
          />
          <Button
            type="text"
            size="small"
            danger
            aria-label="删除用户"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={async () => {
              const ok = await confirm({
                title: `删除用户「${user.username}」？`,
                description: '用户将被禁用且无法再登录，操作不可恢复。',
                destructive: true,
              })
              if (ok) deleteMutation.mutate(user.id)
            }}
          />
        </div>
      ),
    },
  ]

  const regCodeColumns: TableProps<RegistrationCode>['columns'] = [
    {
      title: '注册码',
      dataIndex: 'code',
      key: 'code',
      render: (v: string) => <span className="font-mono text-xs">{v}</span>,
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      width: 100,
      render: (v: string) => <span className="text-xs">{v}</span>,
    },
    {
      title: '使用次数',
      key: 'used_count',
      width: 110,
      render: (_, c) => (
        <span className="text-sm">
          {c.used_count} / {c.max_uses}
        </span>
      ),
    },
    {
      title: '过期时间',
      dataIndex: 'expires_at',
      key: 'expires_at',
      width: 170,
      render: (v: string | null) => (
        <span className="text-xs text-muted-foreground">{v ? formatDate(v) : '永不过期'}</span>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 170,
      render: (v: string) => <span className="text-xs text-muted-foreground">{formatDate(v)}</span>,
    },
    {
      title: '操作',
      key: 'actions',
      width: 70,
      render: (_, c) => (
        <Button
          type="text"
          size="small"
          danger
          aria-label="删除注册码"
          icon={<Trash2 className="h-4 w-4" />}
          onClick={async () => {
            const ok = await confirm({ title: `删除注册码 ${c.code.slice(0, 8)}…？`, destructive: true })
            if (ok) deleteCode.mutate(c.code)
          }}
        />
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">用户管理</h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="small" type="primary" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加用户
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground z-10" />
          <Input
            placeholder="搜索用户..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table
          columns={userColumns}
          dataSource={users}
          rowKey="id"
          loading={isLoading}
          locale={{ emptyText: <EmptyState title="暂无数据" className="border-0" /> }}
          pagination={{
            current: page,
            pageSize: 10,
            total,
            showQuickJumper: true,
            // page_size 固定 10、无独立 pageSize 状态，不展示切换器
            showSizeChanger: false,
            hideOnSinglePage: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      {/* 注册码 */}
      <div className="rounded-md border">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <div>
            <div className="flex items-center gap-2 text-sm font-medium">
              <Ticket className="h-4 w-4" /> 注册码
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">
              注册时填写 code；消费注册码与建用户在同一个事务里，失败不扣次数
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button type="text" size="small" onClick={() => regCodes.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
            <Button
              type="primary"
              onClick={() => {
                setGeneratedCodes([])
                setRegOpen(true)
              }}
            >
              <Plus className="mr-2 h-4 w-4" /> 生成注册码
            </Button>
          </div>
        </div>
        <Table
          columns={regCodeColumns}
          dataSource={regCodes.data?.data?.items ?? []}
          rowKey="code"
          loading={regCodes.isLoading}
          locale={{ emptyText: <EmptyState title="还没有注册码" className="border-0" /> }}
          pagination={false}
        />
      </div>

      <Modal
        open={isCreateDialogOpen}
        title="添加用户"
        onCancel={() => setIsCreateDialogOpen(false)}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setIsCreateDialogOpen(false)}>取消</Button>
            <Button type="primary" onClick={handleCreate} loading={createMutation.isPending}>
              创建
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">创建一个新的系统用户</p>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <label className="text-sm font-medium">用户名</label>
            <Input
              value={newUser.username}
              onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
              placeholder="用户名"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">邮箱</label>
            <Input
              type="email"
              value={newUser.email}
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              placeholder="邮箱"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">昵称</label>
            <Input
              value={newUser.nickname}
              onChange={(e) => setNewUser({ ...newUser, nickname: e.target.value })}
              placeholder="昵称（可选）"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">密码</label>
            <Input
              type="password"
              value={newUser.password}
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              placeholder="密码"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">角色</label>
            <Select
              className="w-full"
              value={newUser.role}
              onChange={(v) => setNewUser({ ...newUser, role: v })}
              options={[
                { value: 'admin', label: '管理员' },
                { value: 'user', label: '普通用户' },
                { value: 'viewer', label: '访客' },
              ]}
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={regOpen}
        title="生成注册码"
        width={640}
        onCancel={() => setRegOpen(false)}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setRegOpen(false)}>关闭</Button>
            <Button type="primary" onClick={() => generateCodes.mutate()} loading={generateCodes.isPending}>
              生成
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">
          明文只在生成后显示一次；注册接口传 code 即可使用，角色由注册码决定。
        </p>
        <div className="grid grid-cols-2 gap-3 py-2">
          <div className="space-y-1">
            <label className="text-sm font-medium">数量（1–100）</label>
            <Input
              type="number"
              min={1}
              max={100}
              value={regForm.count}
              onChange={(e) => setRegForm({ ...regForm, count: Number(e.target.value) || 1 })}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">角色</label>
            <Select
              className="w-full"
              value={regForm.role}
              onChange={(v) => setRegForm({ ...regForm, role: v })}
              options={[
                { value: 'viewer', label: 'viewer' },
                { value: 'user', label: 'user' },
                { value: 'operator', label: 'operator' },
                { value: 'admin', label: 'admin' },
              ]}
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">每码可用次数</label>
            <Input
              type="number"
              min={1}
              max={1000}
              value={regForm.maxUses}
              onChange={(e) =>
                setRegForm({ ...regForm, maxUses: Number(e.target.value) || 1 })
              }
            />
          </div>
          <div className="space-y-1">
            <label className="text-sm font-medium">过期时间（可选）</label>
            <Input
              type="datetime-local"
              value={regForm.expiresAt}
              onChange={(e) => setRegForm({ ...regForm, expiresAt: e.target.value })}
            />
          </div>
        </div>

        {generatedCodes.length > 0 && (
          <div className="space-y-2 rounded-md border bg-muted/30 p-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">本次生成（关闭后不再显示）</span>
              <Button
                size="small"
                onClick={() => {
                  navigator.clipboard?.writeText(generatedCodes.join('\n'))
                  toast({ title: '已复制到剪贴板' })
                }}
              >
                <Copy className="mr-1 h-3.5 w-3.5" /> 复制全部
              </Button>
            </div>
            <div className="max-h-40 overflow-auto font-mono text-xs">
              {generatedCodes.map((c) => (
                <div key={c}>{c}</div>
              ))}
            </div>
          </div>
        )}
      </Modal>

      {/* 修改密码对话框 */}
      <Modal
        open={isPasswordDialogOpen}
        title="修改密码"
        onCancel={() => setIsPasswordDialogOpen(false)}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setIsPasswordDialogOpen(false)}>取消</Button>
            <Button type="primary" onClick={handleChangePassword} loading={resetPasswordMutation.isPending}>
              确认修改
            </Button>
          </div>
        }
      >
        <p className="text-sm text-muted-foreground">为用户设置新密码</p>
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <label className="text-sm font-medium">新密码</label>
            <Input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="请输入新密码（至少6位）"
            />
          </div>
        </div>
      </Modal>
    </div>
  )
}

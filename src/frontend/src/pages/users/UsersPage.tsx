import { useState } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { userApi } from '@/api/auth'
import { registrationApi } from '@/api/registration'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import { Search, Plus, Trash2, RefreshCw, Key, Ticket, Copy } from 'lucide-react'

export default function UsersPage() {
  const { toast } = useToast()
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
    onError: () => {
      toast({ title: '创建失败', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: userApi.deleteUser,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['users'] })
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' })
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
  const totalPages = Math.ceil(total / 10)

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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">用户管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                添加用户
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>添加用户</DialogTitle>
                <DialogDescription>创建一个新的系统用户</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>用户名</Label>
                  <Input
                    value={newUser.username}
                    onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                    placeholder="用户名"
                  />
                </div>
                <div className="space-y-2">
                  <Label>邮箱</Label>
                  <Input
                    type="email"
                    value={newUser.email}
                    onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                    placeholder="邮箱"
                  />
                </div>
                <div className="space-y-2">
                  <Label>昵称</Label>
                  <Input
                    value={newUser.nickname}
                    onChange={(e) => setNewUser({ ...newUser, nickname: e.target.value })}
                    placeholder="昵称（可选）"
                  />
                </div>
                <div className="space-y-2">
                  <Label>密码</Label>
                  <Input
                    type="password"
                    value={newUser.password}
                    onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                    placeholder="密码"
                  />
                </div>
                <div className="space-y-2">
                  <Label>角色</Label>
                  <Select
                    value={newUser.role}
                    onValueChange={(v) => setNewUser({ ...newUser, role: v })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">管理员</SelectItem>
                      <SelectItem value="user">普通用户</SelectItem>
                      <SelectItem value="viewer">访客</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                  取消
                </Button>
                <Button onClick={handleCreate} disabled={createMutation.isPending}>
                  创建
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
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
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>用户名</TableHead>
              <TableHead>邮箱</TableHead>
              <TableHead>昵称</TableHead>
              <TableHead>角色</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>创建时间</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : users.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              users.map((user) => (
                <TableRow key={user.id}>
                  <TableCell className="font-medium">{user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>{user.nickname || '-'}</TableCell>
                  <TableCell>
                    <Badge className={cn(getRoleColor(user.role))}>
                      {getRoleLabel(user.role)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge className={cn(getStatusColor(user.status))}>
                      {user.status === 'active' ? '正常' : '禁用'}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatDate(user.createdAt)}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => openPasswordDialog(user.id)}
                        title="修改密码"
                      >
                        <Key className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => deleteMutation.mutate(user.id)}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            上一页
          </Button>
          <span className="py-2 px-4 text-sm">
            {page} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page === totalPages}
            onClick={() => setPage(page + 1)}
          >
            下一页
          </Button>
        </div>
      )}

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
            <Button variant="ghost" size="sm" onClick={() => regCodes.refetch()}>
              <RefreshCw className="mr-1 h-3.5 w-3.5" /> 刷新
            </Button>
            <Button
              onClick={() => {
                setGeneratedCodes([])
                setRegOpen(true)
              }}
            >
              <Plus className="mr-2 h-4 w-4" /> 生成注册码
            </Button>
          </div>
        </div>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>注册码</TableHead>
              <TableHead className="w-[100px]">角色</TableHead>
              <TableHead className="w-[110px]">使用次数</TableHead>
              <TableHead className="w-[170px]">过期时间</TableHead>
              <TableHead className="w-[170px]">创建时间</TableHead>
              <TableHead className="w-[70px]">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {regCodes.isLoading && (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  加载中…
                </TableCell>
              </TableRow>
            )}
            {!regCodes.isLoading && (regCodes.data?.data?.items ?? []).length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-6 text-center text-muted-foreground">
                  还没有注册码
                </TableCell>
              </TableRow>
            )}
            {(regCodes.data?.data?.items ?? []).map((c) => (
              <TableRow key={c.code}>
                <TableCell className="font-mono text-xs">{c.code}</TableCell>
                <TableCell className="text-xs">{c.role}</TableCell>
                <TableCell className="text-sm">
                  {c.used_count} / {c.max_uses}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {c.expires_at ? formatDate(c.expires_at) : '永不过期'}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {formatDate(c.created_at)}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => deleteCode.mutate(c.code)}
                  >
                    <Trash2 className="h-4 w-4 text-destructive" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <Dialog open={regOpen} onOpenChange={setRegOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>生成注册码</DialogTitle>
            <DialogDescription>
              明文只在生成后显示一次；注册接口传 code 即可使用，角色由注册码决定。
            </DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label>数量（1–100）</Label>
              <Input
                type="number"
                min={1}
                max={100}
                value={regForm.count}
                onChange={(e) => setRegForm({ ...regForm, count: Number(e.target.value) || 1 })}
              />
            </div>
            <div className="space-y-1">
              <Label>角色</Label>
              <Select
                value={regForm.role}
                onValueChange={(v) => setRegForm({ ...regForm, role: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="viewer">viewer</SelectItem>
                  <SelectItem value="user">user</SelectItem>
                  <SelectItem value="operator">operator</SelectItem>
                  <SelectItem value="admin">admin</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>每码可用次数</Label>
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
              <Label>过期时间（可选）</Label>
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
                  size="sm"
                  variant="outline"
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

          <DialogFooter>
            <Button variant="outline" onClick={() => setRegOpen(false)}>
              关闭
            </Button>
            <Button onClick={() => generateCodes.mutate()} disabled={generateCodes.isPending}>
              {generateCodes.isPending ? '生成中…' : '生成'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 修改密码对话框 */}
      <Dialog open={isPasswordDialogOpen} onOpenChange={setIsPasswordDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>修改密码</DialogTitle>
            <DialogDescription>为用户设置新密码</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>新密码</Label>
              <Input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="请输入新密码（至少6位）"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsPasswordDialogOpen(false)}>
              取消
            </Button>
            <Button onClick={handleChangePassword} disabled={resetPasswordMutation.isPending}>
              确认修改
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

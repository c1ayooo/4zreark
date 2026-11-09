import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { Button, Card, Input } from 'antd'

import { useAuthStore } from '@/store/auth'
import { authApi } from '@/api/auth'
import { useToast } from '@/components/ui/use-toast'
import { DecryptText } from '@/components/common/DecryptText'

/**
 * 首次部署初始化页：库里还没有任何账号时进入。
 * 创建的第一个账号即管理员，成功后该入口由后端关闭（再次访问会被引导回登录页）。
 */
export default function SetupPage() {
  const navigate = useNavigate()
  const { setAuth } = useAuthStore()
  const { toast } = useToast()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')

  const bootstrapMutation = useMutation({
    mutationFn: authApi.bootstrap,
    onSuccess: (response) => {
      if (response.code !== 0) {
        toast({
          title: '初始化失败',
          description: response.message,
          variant: 'destructive',
        })
        return
      }
      setAuth(response.data.token, response.data.user)
      toast({
        title: '初始化完成',
        description: `管理员 ${response.data.user.username} 已创建，正在进入系统`,
      })
      // 整页跳转：让应用重新拉取初始化状态，避免被引导逻辑再次拦回本页。
      window.location.replace('/dashboard')
    },
    onError: (error: { code?: number; message?: string }) => {
      // 1003 = Forbidden：系统已有账号，初始化入口已关闭。
      const closed = error?.code === 1003
      toast({
        title: closed ? '初始化入口已关闭' : '初始化失败',
        description: error?.message || '网络错误，请稍后重试',
        variant: 'destructive',
      })
      if (closed) {
        window.setTimeout(() => navigate('/login', { replace: true }), 1200)
      }
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password || !confirm) {
      toast({
        title: '请填写完整',
        description: '用户名、密码和确认密码不能为空',
        variant: 'destructive',
      })
      return
    }
    if (password !== confirm) {
      toast({
        title: '两次密码不一致',
        description: '请重新确认密码',
        variant: 'destructive',
      })
      return
    }
    bootstrapMutation.mutate({
      username: username.trim(),
      password,
      email: email.trim() || undefined,
    })
  }

  return (
    <Card className="w-full">
      <div className="space-y-1 text-center">
        <div className="mb-4 flex justify-center">
          <img
            src="/icon-192x192.png"
            alt="4zreark"
            className="h-16 w-16 rounded-xl dark:invert"
          />
        </div>
        <div className="text-2xl font-bold tracking-tight">
          <DecryptText text="4zreark" />
        </div>
        <p className="text-sm text-muted-foreground">首次部署 · 创建管理员账号</p>
      </div>
      <form onSubmit={handleSubmit} className="mt-6">
        <div className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="username" className="text-sm font-medium">
              管理员用户名
            </label>
            <Input
              id="username"
              placeholder="3-32 个字符"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="email" className="text-sm font-medium">
              邮箱（选填）
            </label>
            <Input
              id="email"
              type="email"
              placeholder="用于找回密码，可留空"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="password" className="text-sm font-medium">
              密码
            </label>
            <Input
              id="password"
              type="password"
              placeholder="至少 8 位"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="new-password"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="confirm" className="text-sm font-medium">
              确认密码
            </label>
            <Input
              id="confirm"
              type="password"
              placeholder="再次输入密码"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
            />
          </div>
        </div>
        <div className="mt-6 flex flex-col gap-4 border-t pt-6">
          <Button
            htmlType="submit"
            type="primary"
            block
            loading={bootstrapMutation.isPending}
          >
            创建管理员并进入系统
          </Button>
          <p className="text-center text-xs text-muted-foreground">
            该入口仅在系统没有账号时可用，创建完成后自动关闭。
          </p>
        </div>
      </form>
    </Card>
  )
}

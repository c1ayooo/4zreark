import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { useAuthStore } from '@/store/auth'
import { authApi } from '@/api/auth'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/components/ui/use-toast'
import { Loader2 } from 'lucide-react'

export default function LoginPage() {
  const navigate = useNavigate()
  const { setAuth } = useAuthStore()
  const { toast } = useToast()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const loginMutation = useMutation({
    mutationFn: authApi.login,
    onSuccess: (response) => {
      if (response.code === 0) {
        setAuth(response.data.token, response.data.user)
        toast({
          title: '登录成功',
          description: `欢迎回来，${response.data.user.nickname || response.data.user.username}`,
        })
        // 后端要求先改默认密码（admin 初始口令）：带标记跳设置页，其余接口已被拦截
        if ((response.data as { must_change_password?: boolean }).must_change_password) {
          toast({
            title: '请先修改默认密码',
            description: '当前使用默认口令，修改前无法使用其他功能。',
            variant: 'destructive',
          })
          navigate('/settings?must_change_password=1')
          return
        }
        navigate('/dashboard')
      } else {
        toast({
          title: '登录失败',
          description: response.message,
          variant: 'destructive',
        })
      }
    },
    onError: (error: Error) => {
      toast({
        title: '登录失败',
        description: error.message || '网络错误，请稍后重试',
        variant: 'destructive',
      })
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!username || !password) {
      toast({
        title: '请填写完整',
        description: '用户名和密码不能为空',
        variant: 'destructive',
      })
      return
    }
    loginMutation.mutate({ username, password })
  }

  return (
    <Card className="w-full">
      <CardHeader className="space-y-1 text-center">
        <div className="mb-4 flex justify-center">
          <img
            src="/icon-192x192.png"
            alt="4zreark"
            className="h-16 w-16 rounded-xl dark:invert"
          />
        </div>
        <CardTitle className="text-2xl font-bold tracking-tight">4zreark</CardTitle>
        <CardDescription>资产侦察与漏洞管理平台</CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="username">用户名</Label>
            <Input
              id="username"
              placeholder="请输入用户名"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">密码</Label>
            <Input
              id="password"
              type="password"
              placeholder="请输入密码"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>
        </CardContent>
        <CardFooter className="flex flex-col space-y-4">
          <Button
            type="submit"
            className="w-full"
            disabled={loginMutation.isPending}
          >
            {loginMutation.isPending && (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            )}
            登录
          </Button>
          <div className="pt-4 border-t text-center">
            <p className="text-xs text-muted-foreground">
              4zreark · c1ayoo
            </p>
          </div>
        </CardFooter>
      </form>
    </Card>
  )
}

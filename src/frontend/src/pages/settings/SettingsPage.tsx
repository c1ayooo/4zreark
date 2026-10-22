import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import { useAppStore } from '@/store/app'
import { authApi } from '@/api/auth'
import { settingsApi, ThirdPartyConfig } from '@/api/settings'
import { retentionApi, type RetentionReport } from '@/api/retention'
import { monitoringApi } from '@/api/monitoring'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useConfirm } from '@/components/common/confirm-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { useToast } from '@/components/ui/use-toast'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { MCPAccessPanel } from '@/components/settings/MCPAccessPanel'
import { Moon, Sun, Monitor, Palette, User, Lock, Key, CheckCircle, XCircle, Plug, Database, Plus, Trash2 } from 'lucide-react'

export default function SettingsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  // 登录接口/后端拦截器带过来的强制改密标记：admin 初始口令未改时为 true
  const mustChangePassword = searchParams.get('must_change_password') === '1'
  const { theme, setTheme } = useAppStore()
  const isAdmin = user?.role === 'admin'
  const [passwordForm, setPasswordForm] = useState({
    oldPassword: '',
    newPassword: '',
    confirmPassword: '',
  })
  const [profileForm, setProfileForm] = useState({
    nickname: user?.nickname || '',
    email: user?.email || '',
  })
  const [apiConfigForm, setApiConfigForm] = useState<Partial<ThirdPartyConfig>>({
    fofa_email: '',
    fofa_key: '',
    hunter_key: '',
    quake_key: '',
    securitytrails_key: '',
  })
  const [retentionReport, setRetentionReport] = useState<RetentionReport | null>(null)
  const [presetForm, setPresetForm] = useState({ name: '', interval_hours: 24, is_default: false })
  const queryClient = useQueryClient()

  const retention = useQuery({
    queryKey: ['retention-policy'],
    queryFn: () => retentionApi.policy(),
    enabled: isAdmin,
  })
  const retentionRun = useMutation({
    mutationFn: (dryRun: boolean) => retentionApi.run(dryRun),
    onSuccess: (res) => {
      setRetentionReport(res.data)
      toast({
        title: res.data?.dry_run ? '试运行完成' : '清理完成',
        description: `扫描结果 ${res.data?.scan_results ?? 0} · 原始记录 ${
          res.data?.raw_records ?? 0
        } · 验证 ${res.data?.verifications ?? 0} · 事件 ${res.data?.events ?? 0}`,
      })
    },
    onError: (e: any) =>
      toast({ title: '清理失败', description: e?.message, variant: 'destructive' }),
  })

  const presets = useQuery({
    queryKey: ['monitoring-presets'],
    queryFn: () => monitoringApi.list(),
    enabled: isAdmin,
  })
  const createPreset = useMutation({
    mutationFn: () => monitoringApi.create(presetForm),
    onSuccess: () => {
      toast({ title: '监控预设已创建' })
      setPresetForm({ name: '', interval_hours: 24, is_default: false })
      queryClient.invalidateQueries({ queryKey: ['monitoring-presets'] })
    },
    onError: (e: any) =>
      toast({ title: '创建预设失败', description: e?.message, variant: 'destructive' }),
  })
  const removePreset = useMutation({
    mutationFn: (id: number) => monitoringApi.remove(id),
    onSuccess: () => {
      toast({ title: '预设已删除' })
      queryClient.invalidateQueries({ queryKey: ['monitoring-presets'] })
    },
    onError: (e: any) =>
      toast({ title: '删除预设失败', description: e?.message, variant: 'destructive' }),
  })
  const presetList = presets.data?.data?.items ?? []

  // 获取当前 API 配置
  const { data: configData, refetch: refetchConfig } = useQuery({
    queryKey: ['thirdparty-config'],
    queryFn: settingsApi.getThirdPartyConfig,
  })

  // 获取已配置的数据源
  const { data: sourcesData, refetch: refetchSources } = useQuery({
    queryKey: ['thirdparty-sources'],
    queryFn: settingsApi.getConfiguredSources,
  })

  const configuredSources = sourcesData?.data?.sources || []

  // 更新 API 配置
  const updateConfigMutation = useMutation({
    mutationFn: settingsApi.updateThirdPartyConfig,
    onSuccess: () => {
      toast({ title: 'API 配置更新成功' })
      refetchConfig()
      refetchSources()
      // 清空输入的密钥（保留 email）
      setApiConfigForm(prev => ({
        ...prev,
        fofa_key: '',
        hunter_key: '',
        quake_key: '',
        securitytrails_key: '',
      }))
    },
    onError: () => {
      toast({ title: 'API 配置更新失败', variant: 'destructive' })
    },
  })

  const changePasswordMutation = useMutation({
    mutationFn: authApi.changePassword,
    onSuccess: () => {
      toast({ title: '密码修改成功，请使用新密码重新登录' })
      setPasswordForm({ oldPassword: '', newPassword: '', confirmPassword: '' })
      // 改密会 bump token_version，当前 token 已失效，直接回登录页
      logout()
      navigate('/login')
    },
    onError: () => {
      toast({ title: '密码修改失败', variant: 'destructive' })
    },
  })

  const handleChangePassword = () => {
    if (!passwordForm.oldPassword || !passwordForm.newPassword) {
      toast({ title: '请填写完整', variant: 'destructive' })
      return
    }
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      toast({ title: '两次密码不一致', variant: 'destructive' })
      return
    }
    changePasswordMutation.mutate({
      oldPassword: passwordForm.oldPassword,
      newPassword: passwordForm.newPassword,
    })
  }

  const updateProfileMutation = useMutation({
    mutationFn: authApi.updateProfile,
    onSuccess: () => {
      toast({ title: '个人信息更新成功' })
    },
    onError: () => {
      toast({ title: '个人信息更新失败', variant: 'destructive' })
    },
  })

  const handleSaveProfile = () => {
    if (!profileForm.email && !profileForm.nickname) {
      toast({ title: '请填写至少一项', variant: 'destructive' })
      return
    }
    updateProfileMutation.mutate({
      email: profileForm.email || undefined,
      nickname: profileForm.nickname || undefined,
    })
  }

  const handleSaveApiConfig = () => {
    // 只提交非空字段
    const configToUpdate: Partial<ThirdPartyConfig> = {}
    if (apiConfigForm.fofa_email) configToUpdate.fofa_email = apiConfigForm.fofa_email
    if (apiConfigForm.fofa_key) configToUpdate.fofa_key = apiConfigForm.fofa_key
    if (apiConfigForm.hunter_key) configToUpdate.hunter_key = apiConfigForm.hunter_key
    if (apiConfigForm.quake_key) configToUpdate.quake_key = apiConfigForm.quake_key
    if (apiConfigForm.securitytrails_key) configToUpdate.securitytrails_key = apiConfigForm.securitytrails_key

    if (Object.keys(configToUpdate).length === 0) {
      toast({ title: '请填写至少一个配置项', variant: 'destructive' })
      return
    }

    updateConfigMutation.mutate(configToUpdate)
  }

  // 检查某个来源是否已配置
  const isSourceConfigured = (source: string) => configuredSources.includes(source)

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">系统设置</h1>

      {mustChangePassword && (
        <div className="rounded-md border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
          当前仍在使用默认密码，修改前无法使用其他功能。请在下方「修改密码」完成修改后重新登录。
        </div>
      )}

      <Tabs defaultValue={mustChangePassword ? 'password' : 'appearance'} className="w-full">
        <TabsList
          className={
            isAdmin
              ? 'grid w-full grid-cols-6 lg:w-[780px]'
              : 'grid w-full grid-cols-4 lg:w-[520px]'
          }
        >
          <TabsTrigger value="appearance" className="flex items-center gap-2">
            <Palette className="h-4 w-4" />
            外观设置
          </TabsTrigger>
          <TabsTrigger value="profile" className="flex items-center gap-2">
            <User className="h-4 w-4" />
            个人信息
          </TabsTrigger>
          <TabsTrigger value="password" className="flex items-center gap-2">
            <Lock className="h-4 w-4" />
            修改密码
          </TabsTrigger>
          <TabsTrigger value="api" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            API配置
          </TabsTrigger>
          {isAdmin && (
            <TabsTrigger value="retention" className="flex items-center gap-2">
              <Database className="h-4 w-4" />
              数据保留
            </TabsTrigger>
          )}
          {isAdmin && (
            <TabsTrigger value="mcp" className="flex items-center gap-2">
              <Plug className="h-4 w-4" />
              MCP 接入
            </TabsTrigger>
          )}
        </TabsList>

        {/* 外观设置 */}
        <TabsContent value="appearance" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>外观设置</CardTitle>
              <CardDescription>自定义界面主题</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Label>主题模式</Label>
                <div className="flex gap-2">
                  <Button
                    variant={theme === 'light' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('light')}
                  >
                    <Sun className="h-4 w-4 mr-2" />
                    浅色
                  </Button>
                  <Button
                    variant={theme === 'dark' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('dark')}
                  >
                    <Moon className="h-4 w-4 mr-2" />
                    深色
                  </Button>
                  <Button
                    variant={theme === 'system' ? 'default' : 'outline'}
                    className="flex-1"
                    onClick={() => setTheme('system')}
                  >
                    <Monitor className="h-4 w-4 mr-2" />
                    跟随系统
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 个人信息 */}
        <TabsContent value="profile" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>个人信息</CardTitle>
              <CardDescription>更新您的个人资料</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>用户名</Label>
                <Input value={user?.username || ''} disabled />
              </div>
              <div className="space-y-2">
                <Label>昵称</Label>
                <Input
                  value={profileForm.nickname}
                  onChange={(e) => setProfileForm({ ...profileForm, nickname: e.target.value })}
                  placeholder="昵称"
                />
              </div>
              <div className="space-y-2">
                <Label>邮箱</Label>
                <Input
                  type="email"
                  value={profileForm.email}
                  onChange={(e) => setProfileForm({ ...profileForm, email: e.target.value })}
                  placeholder="邮箱"
                />
              </div>
              <Button 
                onClick={handleSaveProfile}
                disabled={updateProfileMutation.isPending}
              >
                {updateProfileMutation.isPending ? '保存中...' : '保存修改'}
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 修改密码 */}
        <TabsContent value="password" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>修改密码</CardTitle>
              <CardDescription>更新您的登录密码</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>当前密码</Label>
                <Input
                  type="password"
                  value={passwordForm.oldPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, oldPassword: e.target.value })}
                  placeholder="当前密码"
                />
              </div>
              <div className="space-y-2">
                <Label>新密码</Label>
                <Input
                  type="password"
                  value={passwordForm.newPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                  placeholder="新密码"
                />
              </div>
              <div className="space-y-2">
                <Label>确认新密码</Label>
                <Input
                  type="password"
                  value={passwordForm.confirmPassword}
                  onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })}
                  placeholder="确认新密码"
                />
              </div>
              <Button
                onClick={handleChangePassword}
                disabled={changePasswordMutation.isPending}
              >
                修改密码
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API 配置 */}
        <TabsContent value="api" className="mt-6">
          <div className="grid gap-6 lg:grid-cols-2">
            {/* FOFA */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      FOFA
                      {isSourceConfigured('fofa') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>配置 FOFA 网络空间搜索引擎 API</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Email</Label>
                  <Input
                    value={apiConfigForm.fofa_email}
                    onChange={(e) => setApiConfigForm({ ...apiConfigForm, fofa_email: e.target.value })}
                    placeholder={configData?.data?.config?.fofa_email || '输入 FOFA 账号邮箱'}
                  />
                </div>
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.fofa_key}
                    onChange={(e) => setApiConfigForm({ ...apiConfigForm, fofa_key: e.target.value })}
                    placeholder={configData?.data?.config?.fofa_key || '输入 FOFA API Key'}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Hunter */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      Hunter (鹰图)
                      {isSourceConfigured('hunter') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>配置鹰图平台 API</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.hunter_key}
                    onChange={(e) => setApiConfigForm({ ...apiConfigForm, hunter_key: e.target.value })}
                    placeholder={configData?.data?.config?.hunter_key || '输入 Hunter API Key'}
                  />
                </div>
              </CardContent>
            </Card>

            {/* Quake */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      Quake (360)
                      {isSourceConfigured('quake') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>配置 360 Quake 网络空间搜索引擎 API</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.quake_key}
                    onChange={(e) => setApiConfigForm({ ...apiConfigForm, quake_key: e.target.value })}
                    placeholder={configData?.data?.config?.quake_key || '输入 Quake API Key'}
                  />
                </div>
              </CardContent>
            </Card>

            {/* SecurityTrails */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      SecurityTrails
                      {isSourceConfigured('securitytrails') ? (
                        <Badge variant="default" className="bg-green-500">
                          <CheckCircle className="h-3 w-3 mr-1" />
                          已配置
                        </Badge>
                      ) : (
                        <Badge variant="secondary">
                          <XCircle className="h-3 w-3 mr-1" />
                          未配置
                        </Badge>
                      )}
                    </CardTitle>
                    <CardDescription>配置 SecurityTrails DNS 数据 API</CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>API Key</Label>
                  <Input
                    type="password"
                    value={apiConfigForm.securitytrails_key}
                    onChange={(e) => setApiConfigForm({ ...apiConfigForm, securitytrails_key: e.target.value })}
                    placeholder={configData?.data?.config?.securitytrails_key || '输入 SecurityTrails API Key'}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="mt-6 flex justify-end">
            <Button
              onClick={handleSaveApiConfig}
              disabled={updateConfigMutation.isPending}
            >
              保存 API 配置
            </Button>
          </div>
        </TabsContent>

        {/* 数据保留（仅管理员）：策略来自环境变量，页面只读 + 手动清理 */}
        {isAdmin && (
          <TabsContent value="retention" className="mt-6">
            <Card>
              <CardHeader>
                <CardTitle>数据保留策略</CardTitle>
                <CardDescription>
                  定时任务按此策略清理历史流水；修改需调整服务端环境变量
                  （ZRE_RETENTION_*）后重启
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="grid gap-4 sm:grid-cols-3">
                  {[
                    ['扫描结果保留', retention.data?.data.scan_results_days, '天'],
                    ['原始记录保留', retention.data?.data.raw_records_days, '天'],
                    ['验证记录保留', retention.data?.data.verifications_days, '天'],
                    ['事件条数上限', retention.data?.data.events_keep, '条'],
                    ['事件保留', retention.data?.data.events_days, '天'],
                    ['单批处理上限', retention.data?.data.batch_limit, '条'],
                  ].map(([label, value, unit]) => (
                    <div key={String(label)} className="rounded-md border p-3">
                      <div className="text-xs text-muted-foreground">{label}</div>
                      <div className="mt-1 text-lg font-semibold">
                        {value ?? '—'} <span className="text-xs font-normal">{unit}</span>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="outline"
                    onClick={() => retentionRun.mutate(true)}
                    disabled={retentionRun.isPending}
                  >
                    {retentionRun.isPending ? '执行中…' : '试运行（只统计）'}
                  </Button>
                  <Button
                    variant="destructive"
                    disabled={retentionRun.isPending}
                    onClick={async () => {
                      if (await confirm('按当前策略执行清理？过期流水会被删除。')) {
                        retentionRun.mutate(false)
                      }
                    }}
                  >
                    执行清理
                  </Button>
                  {retentionReport && (
                    <span className="text-sm text-muted-foreground">
                      上次{retentionReport.dry_run ? '试运行' : '清理'}：扫描结果{' '}
                      {retentionReport.scan_results} · 原始记录 {retentionReport.raw_records} ·
                      验证 {retentionReport.verifications} · 事件 {retentionReport.events} ·{' '}
                      {retentionReport.duration_ms}ms
                    </span>
                  )}
                </div>

                {retentionReport?.errors && retentionReport.errors.length > 0 && (
                  <div className="rounded-md border border-destructive/40 p-3 text-xs text-destructive">
                    {retentionReport.errors.join('；')}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="mt-6">
              <CardHeader>
                <CardTitle>监控预设</CardTitle>
                <CardDescription>
                  命名模板：间隔 + 预算。设为默认后，新建计划可优先采用；批量应用走
                  <code className="mx-1">/api/monitoring-bulk</code>
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap items-end gap-2">
                  <div className="space-y-1">
                    <Label>名称</Label>
                    <Input
                      className="w-48"
                      value={presetForm.name}
                      onChange={(e) => setPresetForm({ ...presetForm, name: e.target.value })}
                      placeholder="例如：每日回归"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label>间隔（小时）</Label>
                    <Input
                      className="w-28"
                      type="number"
                      min={1}
                      max={720}
                      value={presetForm.interval_hours}
                      onChange={(e) =>
                        setPresetForm({ ...presetForm, interval_hours: Number(e.target.value) || 1 })
                      }
                    />
                  </div>
                  <label className="flex h-9 items-center gap-2 text-sm">
                    <Checkbox
                      checked={presetForm.is_default}
                      onCheckedChange={(v) =>
                        setPresetForm({ ...presetForm, is_default: v === true })
                      }
                    />
                    设为默认
                  </label>
                  <Button
                    size="sm"
                    disabled={!presetForm.name.trim() || createPreset.isPending}
                    onClick={() => createPreset.mutate()}
                  >
                    <Plus className="mr-2 h-4 w-4" /> 新增
                  </Button>
                </div>

                <div className="rounded-md border">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b text-left text-xs text-muted-foreground">
                        <th className="p-2">名称</th>
                        <th className="p-2">间隔</th>
                        <th className="p-2">默认</th>
                        <th className="p-2 text-right">操作</th>
                      </tr>
                    </thead>
                    <tbody>
                      {presetList.map((p) => (
                        <tr key={p.id} className="border-b last:border-0">
                          <td className="p-2">{p.name}</td>
                          <td className="p-2">{p.interval_hours}h</td>
                          <td className="p-2">
                            {p.is_default ? <Badge>默认</Badge> : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="p-2 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={removePreset.isPending}
                              onClick={() => removePreset.mutate(p.id)}
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </td>
                        </tr>
                      ))}
                      {presetList.length === 0 && (
                        <tr>
                          <td colSpan={4} className="p-6 text-center text-sm text-muted-foreground">
                            还没有预设
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        )}

        {/* MCP / 外部平台接入（仅管理员） */}
        {isAdmin && (
          <TabsContent value="mcp" className="mt-6">
            <MCPAccessPanel />
          </TabsContent>
        )}
      </Tabs>
    </div>
  )
}

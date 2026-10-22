import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { notifyApi, NotifyConfig, NotifyHistory, InAppNotification } from '@/api/notify'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Switch } from '@/components/ui/switch'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
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
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { useToast } from '@/components/ui/use-toast'
import { formatDate } from '@/lib/utils'
import { notificationLink } from '@/lib/notifyLink'
import {
  Bell,
  Plus,
  RefreshCw,
  Trash2,
  Send,
  MessageSquare,
  Mail,
  Webhook,
  CheckCircle,
  XCircle,
  CheckCheck,
  ChevronRight,
} from 'lucide-react'

const channelTypeIcons: Record<string, React.ReactNode> = {
  dingtalk: <MessageSquare className="h-4 w-4 text-blue-500" />,
  feishu: <MessageSquare className="h-4 w-4 text-purple-500" />,
  wechat: <MessageSquare className="h-4 w-4 text-green-500" />,
  email: <Mail className="h-4 w-4 text-orange-500" />,
  webhook: <Webhook className="h-4 w-4 text-gray-500" />,
}

const channelTypeLabels: Record<string, string> = {
  dingtalk: '钉钉',
  feishu: '飞书',
  wechat: '企业微信',
  email: '邮件',
  webhook: 'WebHook',
}

export default function NotifyPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [activeTab, setActiveTab] = useState(() =>
    searchParams.get('tab') === 'inbox' ? 'inbox' : 'channels',
  )

  // 铃铛里的「查看全部」会带 ?tab=inbox，已经停留在本页时也要切过去。
  useEffect(() => {
    if (searchParams.get('tab') === 'inbox') setActiveTab('inbox')
  }, [searchParams])

  const changeTab = (tab: string) => {
    setActiveTab(tab)
    setSearchParams(tab === 'inbox' ? { tab: 'inbox' } : {}, { replace: true })
  }
  const [showAddDialog, setShowAddDialog] = useState(false)
  
  // 新建渠道表单
  const [newChannel, setNewChannel] = useState({
    name: '',
    type: 'dingtalk' as NotifyConfig['type'],
    mode: 'webhook' as 'webhook' | 'app',
    webhook: '',
    secret: '',
    appId: '',
    appSecret: '',
    receiveIdType: 'open_id',
    receiveId: '',
  })

  const resetNewChannel = () =>
    setNewChannel({
      name: '',
      type: 'dingtalk',
      mode: 'webhook',
      webhook: '',
      secret: '',
      appId: '',
      appSecret: '',
      receiveIdType: 'open_id',
      receiveId: '',
    })

  // 获取配置列表
  const { data: configsData, isLoading: configsLoading, refetch: refetchConfigs } = useQuery({
    queryKey: ['notify-configs'],
    queryFn: notifyApi.getConfigs,
  })

  // 获取通知历史
  const { data: historyData, isLoading: historyLoading } = useQuery({
    queryKey: ['notify-history'],
    queryFn: () => notifyApi.getHistory({ limit: 50 }),
    enabled: activeTab === 'history',
  })

  // 站内通知
  const { data: inboxData, isLoading: inboxLoading, refetch: refetchInbox } = useQuery({
    queryKey: ['notify-inbox'],
    queryFn: () => notifyApi.listNotifications({ page: 1, page_size: 50 }),
    enabled: activeTab === 'inbox',
    refetchInterval: activeTab === 'inbox' ? 30_000 : false,
  })

  const markAllMutation = useMutation({
    mutationFn: notifyApi.markAllRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify'] })
      refetchInbox()
    },
  })

  const markOneMutation = useMutation({
    mutationFn: notifyApi.markRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify'] })
      refetchInbox()
    },
  })

  // 创建配置
  const createMutation = useMutation({
    mutationFn: notifyApi.addConfig,
    onSuccess: () => {
      toast({ title: '创建成功' })
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] })
      setShowAddDialog(false)
      resetNewChannel()
    },
    onError: (e: any) => {
      toast({ title: '创建失败', description: e?.message, variant: 'destructive' })
    },
  })

  // 删除配置
  const deleteMutation = useMutation({
    mutationFn: ({ name, type }: { name: string; type: string }) => 
      notifyApi.deleteConfig(name, type),
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] })
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' })
    },
  })

  // 切换配置状态
  const toggleMutation = useMutation({
    mutationFn: ({ name, type, enabled }: { name: string; type: string; enabled: boolean }) =>
      notifyApi.enableConfig(name, type, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] })
    },
    onError: () => {
      toast({ title: '状态切换失败', variant: 'destructive' })
    },
  })

  // 测试配置
  const testMutation = useMutation({
    mutationFn: notifyApi.testConfig,
    onSuccess: (res) => {
      if (res.code === 0) {
        toast({ title: '测试成功', description: '通知已发送' })
      } else {
        toast({ title: '测试失败', description: res.message, variant: 'destructive' })
      }
    },
    onError: (e: any) => {
      toast({ title: '测试失败', description: e?.message, variant: 'destructive' })
    },
  })

  const configs = configsData?.data || []
  const history = historyData?.data || []
  const inbox: InAppNotification[] = inboxData?.data?.items || []
  const unread = inboxData?.data?.unread || 0

  const handleCreate = () => {
    if (!newChannel.name) {
      toast({ title: '请填写渠道名称', variant: 'destructive' })
      return
    }

    const config: NotifyConfig = {
      name: newChannel.name,
      type: newChannel.type,
      enabled: true,
    }

    if (newChannel.type === 'feishu' && newChannel.mode === 'app') {
      if (!newChannel.appId || !newChannel.appSecret || !newChannel.receiveId) {
        toast({ title: '请填写 App ID、App Secret 和接收者 ID', variant: 'destructive' })
        return
      }
      config.feishu_app_id = newChannel.appId
      config.feishu_app_secret = newChannel.appSecret
      config.feishu_receive_id_type = newChannel.receiveIdType
      config.feishu_receive_id = newChannel.receiveId
    } else {
      if (!newChannel.webhook) {
        toast({ title: '请填写 Webhook 地址', variant: 'destructive' })
        return
      }
      switch (newChannel.type) {
        case 'dingtalk':
          config.dingtalk_webhook = newChannel.webhook
          if (newChannel.secret) config.dingtalk_secret = newChannel.secret
          break
        case 'feishu':
          config.feishu_webhook = newChannel.webhook
          if (newChannel.secret) config.feishu_secret = newChannel.secret
          break
        case 'wechat':
          config.wechat_webhook = newChannel.webhook
          break
        case 'webhook':
          config.webhook_url = newChannel.webhook
          config.webhook_method = 'POST'
          break
      }
    }

    createMutation.mutate(config)
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return <Badge className="bg-green-500"><CheckCircle className="h-3 w-3 mr-1" />成功</Badge>
      case 'failed':
        return <Badge variant="destructive"><XCircle className="h-3 w-3 mr-1" />失败</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  // 获取配置的投递目标（用于展示）
  const getTargetSummary = (config: NotifyConfig): string => {
    switch (config.type) {
      case 'dingtalk':
        return config.dingtalk_webhook || ''
      case 'feishu':
        if (config.feishu_app_id) {
          return `企业应用 · ${config.feishu_receive_id_type || 'chat_id'} · ${config.feishu_receive_id || ''}`
        }
        return config.feishu_webhook || ''
      case 'wechat':
        return config.wechat_webhook || ''
      case 'webhook':
        return config.webhook_url || ''
      default:
        return ''
    }
  }

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">通知管理</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetchConfigs()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="sm" onClick={() => setShowAddDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加渠道
          </Button>
        </div>
      </div>

      {/* 标签页 */}
      <Tabs value={activeTab} onValueChange={changeTab}>
        <TabsList>
          <TabsTrigger value="channels">通知渠道</TabsTrigger>
          <TabsTrigger value="inbox">
            站内通知
            {unread > 0 && (
              <span className="ml-1 rounded-full bg-destructive px-1.5 text-[10px] leading-4 text-destructive-foreground">
                {unread > 99 ? '99+' : unread}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="history">发送历史</TabsTrigger>
        </TabsList>

        {/* 渠道列表 */}
        <TabsContent value="channels" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {configsLoading ? (
              <div className="col-span-full text-center py-8 text-muted-foreground">
                加载中...
              </div>
            ) : configs.length === 0 ? (
              <div className="col-span-full text-center py-8 text-muted-foreground">
                暂无通知渠道，点击"添加渠道"创建
              </div>
            ) : (
              configs.map((config, index) => (
                <Card key={`${config.name}-${config.type}-${index}`}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {channelTypeIcons[config.type]}
                        <CardTitle className="text-base">{config.name}</CardTitle>
                      </div>
                      <Switch
                        checked={config.enabled}
                        onCheckedChange={(checked) =>
                          toggleMutation.mutate({ name: config.name, type: config.type, enabled: checked })
                        }
                      />
                    </div>
                    <CardDescription>
                      {channelTypeLabels[config.type]}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="mb-2 truncate text-xs text-muted-foreground" title={getTargetSummary(config)}>
                      {getTargetSummary(config) || '未配置投递目标'}
                    </div>
                    <div className="flex items-center justify-end">
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => testMutation.mutate(config)}
                          disabled={testMutation.isPending}
                          title="测试"
                        >
                          <Send className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => deleteMutation.mutate({ name: config.name, type: config.type })}
                          title="删除"
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </TabsContent>

        {/* 站内通知 */}
        <TabsContent value="inbox" className="space-y-3">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              所有任务完成、漏洞、资产变更等消息都会在这里留一条；飞书渠道同时外发。
            </p>
            <Button
              variant="outline"
              size="sm"
              disabled={markAllMutation.isPending || unread === 0}
              onClick={() => markAllMutation.mutate()}
            >
              <CheckCheck className="mr-2 h-4 w-4" />
              全部已读
            </Button>
          </div>
          <div className="rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[80px]">级别</TableHead>
                  <TableHead>标题 / 内容</TableHead>
                  <TableHead className="w-[140px]">来源</TableHead>
                  <TableHead className="w-[90px]">状态</TableHead>
                  <TableHead className="w-[160px]">时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {inboxLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : inbox.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                      暂无站内通知
                    </TableCell>
                  </TableRow>
                ) : (
                  inbox.map((n) => {
                    const target = notificationLink(n)
                    const open = () => {
                      if (!n.read) markOneMutation.mutate(n.id)
                      if (target) navigate(target)
                    }
                    return (
                      <TableRow
                        key={n.id}
                        className={
                          target
                            ? 'cursor-pointer hover:bg-muted/40'
                            : n.read
                              ? undefined
                              : 'bg-muted/30'
                        }
                        tabIndex={target ? 0 : undefined}
                        onClick={open}
                        onKeyDown={(e) => {
                          if (target && (e.key === 'Enter' || e.key === ' ')) {
                            e.preventDefault()
                            open()
                          }
                        }}
                      >
                        <TableCell>
                          <Badge
                            variant={
                              n.level === 'critical'
                                ? 'destructive'
                                : n.level === 'warning'
                                  ? 'warning'
                                  : 'outline'
                            }
                          >
                            {n.level}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className={n.read ? 'text-sm' : 'text-sm font-medium'}>{n.title}</div>
                          {n.content && (
                            <div className="mt-0.5 line-clamp-2 whitespace-pre-wrap text-xs text-muted-foreground">
                              {n.content}
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{n.source || '—'}</TableCell>
                        <TableCell>
                          <Badge variant={n.read ? 'outline' : 'default'}>{n.read ? '已读' : '未读'}</Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          <div className="flex items-center justify-end gap-1">
                            {formatDate(n.created_at)}
                            {target && <ChevronRight className="size-3.5" />}
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>

        {/* 发送历史 */}
        <TabsContent value="history">
          <div className="border rounded-lg">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>类型</TableHead>
                  <TableHead>标题</TableHead>
                  <TableHead>级别</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead>时间</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {historyLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      加载中...
                    </TableCell>
                  </TableRow>
                ) : history.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                      暂无发送记录
                    </TableCell>
                  </TableRow>
                ) : (
                  history.map((item: NotifyHistory) => (
                    <TableRow key={item.id}>
                      <TableCell>
                        <Badge variant="outline">{channelTypeLabels[item.type] || item.type}</Badge>
                      </TableCell>
                      <TableCell className="max-w-xs truncate">{item.message?.title}</TableCell>
                      <TableCell>
                        <Badge variant={item.message?.level === 'warning' ? 'destructive' : 'outline'}>
                          {item.message?.level}
                        </Badge>
                      </TableCell>
                      <TableCell>{getStatusBadge(item.status)}</TableCell>
                      <TableCell>{formatDate(item.timestamp)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
      </Tabs>

      {/* 添加渠道对话框 */}
      <Dialog
        open={showAddDialog}
        onOpenChange={(open) => {
          setShowAddDialog(open)
          if (!open) resetNewChannel()
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>添加通知渠道</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>渠道名称</Label>
              <Input
                placeholder="输入渠道名称"
                value={newChannel.name}
                onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>渠道类型</Label>
              <Select
                value={newChannel.type}
                onValueChange={(value) => setNewChannel({ ...newChannel, type: value as NotifyConfig['type'] })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="dingtalk">钉钉</SelectItem>
                  <SelectItem value="feishu">飞书</SelectItem>
                  <SelectItem value="wechat">企业微信</SelectItem>
                  <SelectItem value="webhook">WebHook</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {newChannel.type === 'feishu' && (
              <div className="space-y-2">
                <Label>飞书接入方式</Label>
                <Select
                  value={newChannel.mode}
                  onValueChange={(value) =>
                    setNewChannel({ ...newChannel, mode: value as 'webhook' | 'app' })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="webhook">群机器人 Webhook</SelectItem>
                    <SelectItem value="app">企业应用机器人</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}

            {newChannel.type === 'feishu' && newChannel.mode === 'app' ? (
              <>
                <div className="space-y-2">
                  <Label>App ID</Label>
                  <Input
                    placeholder="cli_xxxxxxxxxxxxxxxx"
                    value={newChannel.appId}
                    onChange={(e) => setNewChannel({ ...newChannel, appId: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>App Secret</Label>
                  <Input
                    type="password"
                    placeholder="企业应用 App Secret"
                    value={newChannel.appSecret}
                    onChange={(e) => setNewChannel({ ...newChannel, appSecret: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>接收者类型</Label>
                  <Select
                    value={newChannel.receiveIdType}
                    onValueChange={(value) =>
                      setNewChannel({ ...newChannel, receiveIdType: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open_id">open_id（个人）</SelectItem>
                      <SelectItem value="chat_id">chat_id（群）</SelectItem>
                      <SelectItem value="user_id">user_id</SelectItem>
                      <SelectItem value="union_id">union_id</SelectItem>
                      <SelectItem value="email">email</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>接收者 ID</Label>
                  <Input
                    placeholder="ou_xxx / oc_xxx / 邮箱"
                    value={newChannel.receiveId}
                    onChange={(e) => setNewChannel({ ...newChannel, receiveId: e.target.value })}
                  />
                  <p className="text-xs text-muted-foreground">
                    企业应用需要把机器人加入目标群，或使用 open_id/邮箱发给个人。
                  </p>
                </div>
              </>
            ) : (
              <>
                <div className="space-y-2">
                  <Label>Webhook 地址</Label>
                  <Input
                    placeholder="输入 Webhook URL"
                    value={newChannel.webhook}
                    onChange={(e) => setNewChannel({ ...newChannel, webhook: e.target.value })}
                  />
                </div>
                {(newChannel.type === 'dingtalk' || newChannel.type === 'feishu') && (
                  <div className="space-y-2">
                    <Label>签名密钥 (可选)</Label>
                    <Input
                      placeholder="输入签名密钥"
                      value={newChannel.secret}
                      onChange={(e) => setNewChannel({ ...newChannel, secret: e.target.value })}
                    />
                  </div>
                )}
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddDialog(false)}>
              取消
            </Button>
            <Button onClick={handleCreate} disabled={createMutation.isPending}>
              创建
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

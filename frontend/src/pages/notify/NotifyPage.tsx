import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { notifyApi, NotifyConfig, NotifyHistory, InAppNotification } from '@/api/notify'
import { Button, Card, Input, Modal, Select, Switch, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { getErrorMessage } from '@/lib/errors'
import { useConfirm } from '@/components/common/confirm-provider'
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
import { statusTagClass } from '@/components/ui/StatusTag'

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

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = statusTagClass
export default function NotifyPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const confirm = useConfirm()
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
    minLevel: '' as NotifyConfig['min_level'],
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
      minLevel: '',
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
    onError: (e) => toast({ title: getErrorMessage(e, '标记失败'), variant: 'destructive' }),
  })

  const markOneMutation = useMutation({
    mutationFn: notifyApi.markRead,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify'] })
      refetchInbox()
    },
    onError: (e) => toast({ title: getErrorMessage(e, '标记失败'), variant: 'destructive' }),
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
    onError: (e) => {
      toast({ title: getErrorMessage(e, '删除失败'), variant: 'destructive' })
    },
  })

  // 改渠道最低接收级别：整份配置回传，后端合并脱敏密钥后覆盖保存
  const minLevelMutation = useMutation({
    mutationFn: ({ config, minLevel }: { config: NotifyConfig; minLevel: NotifyConfig['min_level'] }) =>
      notifyApi.updateConfig({ ...config, min_level: minLevel }),
    onSuccess: () => {
      toast({ title: '级别设置已保存' })
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] })
    },
    onError: (e: any) => {
      toast({ title: '保存失败', description: e?.message, variant: 'destructive' })
    },
  })

  // 切换配置状态
  const toggleMutation = useMutation({
    mutationFn: ({ name, type, enabled }: { name: string; type: string; enabled: boolean }) =>
      notifyApi.enableConfig(name, type, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notify-configs'] })
    },
    onError: (e) => {
      toast({ title: getErrorMessage(e, '状态切换失败'), variant: 'destructive' })
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
      min_level: newChannel.minLevel || undefined,
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
        return (
          <Tag className="border-transparent bg-green-500 text-white">
            <CheckCircle className="mr-1 inline h-3 w-3" />成功
          </Tag>
        )
      case 'failed':
        return (
          <Tag className={badgeCls('destructive')}>
            <XCircle className="mr-1 inline h-3 w-3" />失败
          </Tag>
        )
      default:
        return <Tag>{status}</Tag>
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

  const inboxColumns: TableProps<InAppNotification>['columns'] = [
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 80,
      render: (v: string) => (
        <Tag
          className={badgeCls(
            v === 'critical' ? 'destructive' : v === 'warning' ? 'warning' : 'outline',
          )}
        >
          {v}
        </Tag>
      ),
    },
    {
      title: '标题 / 内容',
      key: 'title',
      render: (_, n) => (
        <>
          <div className={n.read ? 'text-sm' : 'text-sm font-medium'}>{n.title}</div>
          {n.content && (
            <div className="mt-0.5 line-clamp-2 whitespace-pre-wrap text-xs text-muted-foreground">
              {n.content}
            </div>
          )}
        </>
      ),
    },
    {
      title: '来源',
      dataIndex: 'source',
      key: 'source',
      width: 140,
      render: (v: string) => <span className="text-xs text-muted-foreground">{v || '—'}</span>,
    },
    {
      title: '状态',
      dataIndex: 'read',
      key: 'read',
      width: 90,
      render: (v: boolean) => <Tag className={badgeCls(v ? 'outline' : 'default')}>{v ? '已读' : '未读'}</Tag>,
    },
    {
      title: '时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (v: string, n) => {
        const target = notificationLink(n)
        return (
          <div className="flex items-center justify-end gap-1 text-xs text-muted-foreground">
            {formatDate(v)}
            {target && <ChevronRight className="size-3.5" />}
          </div>
        )
      },
    },
  ]

  const historyColumns: TableProps<NotifyHistory>['columns'] = [
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (v: string) => <Tag>{channelTypeLabels[v] || v}</Tag>,
    },
    {
      title: '标题',
      key: 'title',
      ellipsis: true,
      render: (_, item) => <span className="max-w-xs truncate">{item.message?.title}</span>,
    },
    {
      title: '级别',
      key: 'level',
      render: (_, item) => (
        <Tag className={badgeCls(item.message?.level === 'warning' ? 'destructive' : 'outline')}>
          {item.message?.level}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (v: string) => getStatusBadge(v),
    },
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      render: (v: string) => formatDate(v),
    },
  ]

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Bell className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">通知管理</h1>
        </div>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetchConfigs()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="small" type="primary" onClick={() => setShowAddDialog(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加渠道
          </Button>
        </div>
      </div>

      {/* 标签页 */}
      <Tabs
        activeKey={activeTab}
        onChange={changeTab}
        items={[
          {
            key: 'channels',
            label: '通知渠道',
            children: (
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
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          {channelTypeIcons[config.type]}
                          <span className="text-base font-semibold">{config.name}</span>
                        </div>
                        <Switch
                          checked={config.enabled}
                          onChange={(checked) =>
                            toggleMutation.mutate({
                              name: config.name,
                              type: config.type,
                              enabled: checked,
                            })
                          }
                        />
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground">
                        {channelTypeLabels[config.type]}
                      </p>
                      <div
                        className="mb-2 mt-3 truncate text-xs text-muted-foreground"
                        title={getTargetSummary(config)}
                      >
                        {getTargetSummary(config) || '未配置投递目标'}
                      </div>
                      <div className="mb-2 flex items-center gap-2 text-xs text-muted-foreground">
                        <span>最低级别</span>
                        <Select
                          size="small"
                          className="w-[150px]"
                          value={config.min_level || ''}
                          onChange={(value) =>
                            minLevelMutation.mutate({ config, minLevel: value as NotifyConfig['min_level'] })
                          }
                          disabled={minLevelMutation.isPending}
                          options={[
                            { value: '', label: '全部消息' },
                            { value: 'warning', label: 'warning+' },
                            { value: 'critical', label: '仅 critical' },
                          ]}
                        />
                      </div>
                      <div className="flex items-center justify-end">
                        <div className="flex gap-1">
                          <Button
                            type="text"
                            size="small"
                            onClick={() => testMutation.mutate(config)}
                            disabled={testMutation.isPending}
                            aria-label="测试"
                            icon={<Send className="h-4 w-4" />}
                          />
                          <Button
                            type="text"
                            size="small"
                            danger
                            onClick={async () => {
                              const ok = await confirm({
                                title: `删除通知渠道「${config.name}」？`,
                                destructive: true,
                              })
                              if (ok) deleteMutation.mutate({ name: config.name, type: config.type })
                            }}
                            aria-label="删除"
                            icon={<Trash2 className="h-4 w-4" />}
                          />
                        </div>
                      </div>
                    </Card>
                  ))
                )}
              </div>
            ),
          },
          {
            key: 'inbox',
            label: (
              <span className="flex items-center gap-1">
                站内通知
                {unread > 0 && (
                  <span className="rounded-full bg-destructive px-1.5 text-[10px] leading-4 text-destructive-foreground">
                    {unread > 99 ? '99+' : unread}
                  </span>
                )}
              </span>
            ),
            children: (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    所有任务完成、漏洞、资产变更等消息都会在这里留一条；飞书渠道同时外发。
                  </p>
                  <Button
                    size="small"
                    disabled={markAllMutation.isPending || unread === 0}
                    onClick={() => markAllMutation.mutate()}
                  >
                    <CheckCheck className="mr-2 h-4 w-4" />
                    全部已读
                  </Button>
                </div>
                <div className="rounded-lg border">
                  <Table
                    columns={inboxColumns}
                    dataSource={inbox}
                    rowKey="id"
                    loading={inboxLoading}
                    locale={{
                      emptyText: <EmptyState title="暂无站内通知" className="border-0" />,
                    }}
                    onRow={(record) => {
                      const target = notificationLink(record)
                      const open = () => {
                        if (!record.read) markOneMutation.mutate(record.id)
                        if (target) navigate(target)
                      }
                      return {
                        className: target
                          ? 'cursor-pointer'
                          : record.read
                            ? undefined
                            : 'bg-muted/30',
                        tabIndex: target ? 0 : undefined,
                        onClick: open,
                        onKeyDown: (e: React.KeyboardEvent) => {
                          if (target && (e.key === 'Enter' || e.key === ' ')) {
                            e.preventDefault()
                            open()
                          }
                        },
                      }
                    }}
                    pagination={false}
                  />
                </div>
              </div>
            ),
          },
          {
            key: 'history',
            label: '发送历史',
            children: (
              <div className="border rounded-lg">
                <Table
                  columns={historyColumns}
                  dataSource={history}
                  rowKey="id"
                  loading={historyLoading}
                  locale={{
                    emptyText: <EmptyState title="暂无发送记录" className="border-0" />,
                  }}
                  pagination={false}
                />
              </div>
            ),
          },
        ]}
      />

      {/* 添加渠道对话框 */}
      <Modal
        open={showAddDialog}
        title="添加通知渠道"
        onCancel={() => {
          setShowAddDialog(false)
          resetNewChannel()
        }}
        footer={
          <div className="flex justify-end gap-2">
            <Button
              onClick={() => {
                setShowAddDialog(false)
                resetNewChannel()
              }}
            >
              取消
            </Button>
            <Button type="primary" onClick={handleCreate} loading={createMutation.isPending}>
              创建
            </Button>
          </div>
        }
      >
        <div className="space-y-4 py-2">
          <div className="space-y-2">
            <label className="text-sm font-medium">渠道名称</label>
            <Input
              placeholder="输入渠道名称"
              value={newChannel.name}
              onChange={(e) => setNewChannel({ ...newChannel, name: e.target.value })}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">渠道类型</label>
            <Select
              className="w-full"
              value={newChannel.type}
              onChange={(value) =>
                setNewChannel({ ...newChannel, type: value as NotifyConfig['type'] })
              }
              options={[
                { value: 'dingtalk', label: '钉钉' },
                { value: 'feishu', label: '飞书' },
                { value: 'wechat', label: '企业微信' },
                { value: 'webhook', label: 'WebHook' },
              ]}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">最低接收级别</label>
            <Select
              className="w-full"
              value={newChannel.minLevel || ''}
              onChange={(value) =>
                setNewChannel({ ...newChannel, minLevel: value as NotifyConfig['min_level'] })
              }
              options={[
                { value: '', label: '全部消息（info 及以上）' },
                { value: 'warning', label: 'warning 及以上' },
                { value: 'critical', label: '仅 critical' },
              ]}
            />
            <p className="text-xs text-muted-foreground">
              级别低于门槛的消息不会发到这个渠道，避免普通通知刷屏重要群。
            </p>
          </div>
          {newChannel.type === 'feishu' && (
            <div className="space-y-2">
              <label className="text-sm font-medium">飞书接入方式</label>
              <Select
                className="w-full"
                value={newChannel.mode}
                onChange={(value) =>
                  setNewChannel({ ...newChannel, mode: value as 'webhook' | 'app' })
                }
                options={[
                  { value: 'webhook', label: '群机器人 Webhook' },
                  { value: 'app', label: '企业应用机器人' },
                ]}
              />
            </div>
          )}

          {newChannel.type === 'feishu' && newChannel.mode === 'app' ? (
            <>
              <div className="space-y-2">
                <label className="text-sm font-medium">App ID</label>
                <Input
                  placeholder="cli_xxxxxxxxxxxxxxxx"
                  value={newChannel.appId}
                  onChange={(e) => setNewChannel({ ...newChannel, appId: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">App Secret</label>
                <Input
                  type="password"
                  placeholder="企业应用 App Secret"
                  value={newChannel.appSecret}
                  onChange={(e) => setNewChannel({ ...newChannel, appSecret: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">接收者类型</label>
                <Select
                  className="w-full"
                  value={newChannel.receiveIdType}
                  onChange={(value) =>
                    setNewChannel({ ...newChannel, receiveIdType: value })
                  }
                  options={[
                    { value: 'open_id', label: 'open_id（个人）' },
                    { value: 'chat_id', label: 'chat_id（群）' },
                    { value: 'user_id', label: 'user_id' },
                    { value: 'union_id', label: 'union_id' },
                    { value: 'email', label: 'email' },
                  ]}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium">接收者 ID</label>
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
                <label className="text-sm font-medium">Webhook 地址</label>
                <Input
                  placeholder="输入 Webhook URL"
                  value={newChannel.webhook}
                  onChange={(e) => setNewChannel({ ...newChannel, webhook: e.target.value })}
                />
              </div>
              {(newChannel.type === 'dingtalk' || newChannel.type === 'feishu') && (
                <div className="space-y-2">
                  <label className="text-sm font-medium">签名密钥 (可选)</label>
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
      </Modal>
    </div>
  )
}

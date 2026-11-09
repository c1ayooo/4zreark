import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Card, Form, Input, InputNumber, Modal, Switch, Table, message } from 'antd'
import type { TableProps } from 'antd'
import { PlayCircle, Plus, RefreshCw, Search, Trash2 } from 'lucide-react'
import { sentinelApi, SentinelRepo, SentinelRepoPayload } from '@/api/sentinel'
import { formatDate } from '@/lib/utils'
import { getErrorMessage } from '@/lib/errors'

export default function SentinelReposPage() {
  const queryClient = useQueryClient()
  const [keyword, setKeyword] = useState('')
  const [search, setSearch] = useState('')
  const [open, setOpen] = useState(false)
  const [form] = Form.useForm<SentinelRepoPayload>()

  const reposQuery = useQuery({
    queryKey: ['sentinel-repos', search],
    queryFn: () => sentinelApi.listRepos(search || undefined),
  })
  const repos = reposQuery.data?.items ?? []
  const cloneHosts = reposQuery.data?.clone_hosts ?? ['github.com']

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['sentinel-repos'] })
    queryClient.invalidateQueries({ queryKey: ['sentinel-overview'] })
  }

  const createMutation = useMutation({
    mutationFn: (payload: SentinelRepoPayload) => sentinelApi.createRepo(payload),
    onSuccess: () => {
      message.success('仓库已创建并开始采集')
      setOpen(false)
      form.resetFields()
      invalidate()
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      sentinelApi.updateRepo(id, { enabled }),
    onSuccess: () => {
      message.success('已更新采集开关')
      invalidate()
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  const collectMutation = useMutation({
    mutationFn: (id: string) => sentinelApi.collectRepo(id),
    onSuccess: () => {
      message.success('已加入采集队列')
      invalidate()
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => sentinelApi.deleteRepo(id),
    onSuccess: () => {
      message.success('已删除仓库')
      invalidate()
    },
    onError: (err) => message.error(getErrorMessage(err)),
  })

  const columns: TableProps<SentinelRepo>['columns'] = [
    {
      title: '仓库',
      dataIndex: 'full_name',
      render: (value: string, row) => (
        <div className="space-y-0.5">
          <div className="font-medium">{value}</div>
          <a
            href={row.clone_url}
            target="_blank"
            rel="noreferrer"
            className="text-xs text-muted-foreground hover:text-primary"
          >
            {row.clone_url}
          </a>
        </div>
      ),
    },
    {
      title: '分支',
      dataIndex: 'branch',
      width: 130,
      render: (value: string, row) => (
        <span className="font-mono text-xs">{value || row.default_branch || 'main'}</span>
      ),
    },
    {
      title: '采集间隔',
      dataIndex: 'interval_minutes',
      width: 110,
      render: (value: number) => <span className="text-xs">{value} 分钟</span>,
    },
    {
      title: '最近检查',
      dataIndex: 'last_checked_at',
      width: 180,
      render: (value: string | null, row) => (
        <div className="space-y-0.5 text-xs">
          <div className="text-muted-foreground">{value ? formatDate(value) : '尚未采集'}</div>
          {row.last_error ? <div className="text-[11px] text-red-500">{row.last_error}</div> : null}
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      width: 90,
      render: (value: boolean, row) => (
        <Switch
          size="small"
          checked={value}
          loading={toggleMutation.isPending}
          onChange={(checked) => toggleMutation.mutate({ id: row.id, enabled: checked })}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      render: (_, row) => (
        <div className="flex items-center gap-1">
          <Button
            type="link"
            size="small"
            icon={<PlayCircle className="h-3.5 w-3.5" />}
            onClick={() => collectMutation.mutate(row.id)}
          >
            立即检查
          </Button>
          <Button
            type="link"
            size="small"
            danger
            icon={<Trash2 className="h-3.5 w-3.5" />}
            onClick={() => {
              Modal.confirm({
                title: `删除 ${row.full_name}？`,
                content: '已采集的提交与判定会一并移除，操作不可恢复。',
                okButtonProps: { danger: true },
                onOk: () => deleteMutation.mutate(row.id),
              })
            }}
          >
            删除
          </Button>
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">仓库</h1>
          <p className="text-sm text-muted-foreground">
            只允许 {cloneHosts.join('、')} 的 https 地址；clone 全程用 git 参数直传，不经 shell。
          </p>
        </div>
        <Button type="primary" icon={<Plus className="h-4 w-4" />} onClick={() => setOpen(true)}>
          新增仓库
        </Button>
      </header>

      <Card className="border-border/60">
        <div className="mb-4 flex flex-wrap items-center gap-2">
          <Input
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onPressEnter={() => setSearch(keyword.trim())}
            placeholder="搜索 owner/repo"
            prefix={<Search className="h-4 w-4 text-muted-foreground" />}
            allowClear
            className="max-w-xs"
          />
          <Button icon={<Search className="h-4 w-4" />} onClick={() => setSearch(keyword.trim())}>
            搜索
          </Button>
          <Button icon={<RefreshCw className="h-4 w-4" />} onClick={() => reposQuery.refetch()}>
            刷新
          </Button>
        </div>

        <Table<SentinelRepo>
          rowKey="id"
          size="middle"
          columns={columns}
          dataSource={repos}
          loading={reposQuery.isLoading}
          pagination={false}
          scroll={{ x: 900 }}
          locale={{ emptyText: '还没有仓库：添加一个公开仓库开始采集' }}
        />
      </Card>

      <Modal
        title="新增仓库"
        open={open}
        onCancel={() => setOpen(false)}
        onOk={() => form.submit()}
        okText="创建并采集"
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ interval_minutes: 60, enabled: true }}
          onFinish={(values) => createMutation.mutate(values)}
        >
          <Form.Item
            name="clone_url"
            label="Clone URL"
            rules={[{ required: true, message: '请填写 https 的 clone 地址' }]}
            extra={`仅支持 https，主机需在白名单内（${cloneHosts.join('、')}）`}
          >
            <Input placeholder="https://github.com/owner/repo" />
          </Form.Item>
          <Form.Item name="full_name" label="展示名" extra="留空则从 URL 推导 owner/repo">
            <Input placeholder="owner/repo" />
          </Form.Item>
          <div className="grid grid-cols-2 gap-3">
            <Form.Item name="branch" label="分支" extra="留空跟随默认分支">
              <Input placeholder="main" />
            </Form.Item>
            <Form.Item name="interval_minutes" label="采集间隔（分钟）">
              <InputNumber min={10} max={1440} className="w-full" />
            </Form.Item>
          </div>
          <Form.Item name="enabled" label="启用采集" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

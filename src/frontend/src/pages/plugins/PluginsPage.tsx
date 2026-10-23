import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { nodeApi, Plugin } from '@/api/nodes'
import { Button, Input, Modal, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import EmptyState from '@/components/common/EmptyState'
import { formatDate } from '@/lib/utils'
import { Search, Plus, Upload, RefreshCw, Trash2, Settings } from 'lucide-react'

export default function PluginsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newPlugin, setNewPlugin] = useState<Partial<Plugin>>({
    name: '',
    type: 'scanner',
    version: '1.0.0',
    description: '',
    author: '',
    enabled: true,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['plugins', page, search],
    queryFn: () =>
      nodeApi.getPlugins({
        page,
        pageSize: 10,
        search,
      }),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      nodeApi.togglePlugin(id, enabled),
    onSuccess: () => {
      toast({ title: '更新成功' })
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      toast({ title: '更新失败', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: nodeApi.deletePlugin,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' })
    },
  })

  const createMutation = useMutation({
    mutationFn: nodeApi.createPlugin,
    onSuccess: () => {
      toast({ title: '插件创建成功' })
      setIsCreateDialogOpen(false)
      setNewPlugin({
        name: '',
        type: 'scanner',
        version: '1.0.0',
        description: '',
        author: '',
        enabled: true,
      })
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      toast({ title: '创建失败', variant: 'destructive' })
    },
  })

  const uploadMutation = useMutation({
    mutationFn: nodeApi.uploadPlugin,
    onSuccess: () => {
      toast({ title: '插件上传成功' })
      queryClient.invalidateQueries({ queryKey: ['plugins'] })
    },
    onError: () => {
      toast({ title: '上传失败', variant: 'destructive' })
    },
  })

  const handleUpload = () => {
    fileInputRef.current?.click()
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      uploadMutation.mutate(file)
    }
    e.target.value = ''
  }

  const handleCreate = () => {
    if (!newPlugin.name) {
      toast({ title: '请填写插件名称', variant: 'destructive' })
      return
    }
    createMutation.mutate(newPlugin)
  }

  const plugins = data?.data?.list || []
  const total = data?.data?.total || 0

  const columns: TableProps<Plugin>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (_, plugin) => (
        <div>
          <p className="font-medium">{plugin.name}</p>
          {plugin.description && (
            <p className="text-xs text-muted-foreground truncate max-w-xs">
              {plugin.description}
            </p>
          )}
        </div>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 110,
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 90,
    },
    {
      title: '作者',
      dataIndex: 'author',
      key: 'author',
      render: (v: string) => v || '-',
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 90,
      render: (_, plugin) => (
        <Switch
          checked={plugin.enabled}
          onChange={(checked) => toggleMutation.mutate({ id: plugin.id, enabled: checked })}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updatedAt',
      key: 'updatedAt',
      width: 170,
      render: (v: string) => formatDate(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 110,
      render: (_, plugin) => (
        <div className="flex gap-1">
          <Button type="text" icon={<Settings className="h-4 w-4" />} />
          <Button
            type="text"
            danger
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => deleteMutation.mutate(plugin.id)}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        className="hidden"
        accept=".zip,.tar.gz"
        onChange={handleFileChange}
      />

      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">插件管理</h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button size="small" onClick={handleUpload}>
            <Upload className="h-4 w-4 mr-2" />
            上传插件
          </Button>
          <Button type="primary" size="small" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            添加插件
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4">
        <Input
          placeholder="搜索插件..."
          className="flex-1 max-w-sm"
          prefix={<Search className="h-4 w-4 text-muted-foreground" />}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table
          columns={columns}
          dataSource={plugins}
          rowKey="id"
          loading={isLoading}
          locale={{ emptyText: <EmptyState title="暂无数据" className="border-0" /> }}
          pagination={{
            current: page,
            pageSize: 10,
            total,
            showQuickJumper: true,
            hideOnSinglePage: true,
            onChange: (p) => setPage(p),
          }}
        />
      </div>

      {/* Create Plugin Dialog */}
      <Modal
        open={isCreateDialogOpen}
        title="添加插件"
        onCancel={() => setIsCreateDialogOpen(false)}
        footer={
          <div className="flex justify-end gap-2">
            <Button onClick={() => setIsCreateDialogOpen(false)}>取消</Button>
            <Button type="primary" onClick={handleCreate} disabled={createMutation.isPending}>
              创建
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">插件名称 *</label>
            <Input
              value={newPlugin.name}
              onChange={(e) => setNewPlugin({ ...newPlugin, name: e.target.value })}
              placeholder="插件名称"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">类型</label>
            <Select
              className="w-full"
              value={newPlugin.type}
              onChange={(v) => setNewPlugin({ ...newPlugin, type: v })}
              options={[
                { value: 'scanner', label: '扫描器' },
                { value: 'fingerprint', label: '指纹识别' },
                { value: 'poc', label: 'POC' },
                { value: 'exploit', label: '漏洞利用' },
                { value: 'other', label: '其他' },
              ]}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">版本</label>
            <Input
              value={newPlugin.version}
              onChange={(e) => setNewPlugin({ ...newPlugin, version: e.target.value })}
              placeholder="1.0.0"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">作者</label>
            <Input
              value={newPlugin.author}
              onChange={(e) => setNewPlugin({ ...newPlugin, author: e.target.value })}
              placeholder="作者名称"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">描述</label>
            <Input.TextArea
              value={newPlugin.description}
              onChange={(e) => setNewPlugin({ ...newPlugin, description: e.target.value })}
              placeholder="插件描述"
            />
          </div>
        </div>
      </Modal>
    </div>
  )
}

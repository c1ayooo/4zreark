import { useEffect, useState, useRef } from 'react'
import {keepPreviousData, useQuery, useMutation, useQueryClient} from '@tanstack/react-query'
import { pocApi, POC, CreatePOCRequest } from '@/api/pocs'
import { Button, Dropdown, Input, Modal, Select, Switch, Table, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useConfirm } from '@/components/common/confirm-provider'
import EmptyState from '@/components/common/EmptyState'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, getSeverityColor } from '@/lib/utils'
import { Search, Plus, Eye, Upload, RefreshCw, Trash2, FileArchive, FileText, ChevronDown } from 'lucide-react'
import { useDebouncedValue } from '@/hooks/useDebouncedValue'

// shadcn Badge variant → antd Tag 的主题配色（沿用原 CSS 变量，保持视觉不变）
const badgeCls = (variant: 'default' | 'secondary' | 'destructive' | 'outline') =>
  variant === 'default'
    ? 'border-transparent bg-primary text-primary-foreground'
    : variant === 'secondary'
      ? 'border-transparent bg-secondary text-secondary-foreground'
      : variant === 'destructive'
        ? 'border-transparent bg-destructive text-destructive-foreground'
        : ''

export default function POCsPage() {
  const confirm = useConfirm()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const fileInputRef = useRef<HTMLInputElement>(null)
  const zipInputRef = useRef<HTMLInputElement>(null)
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search)
  useEffect(() => { setPage(1) }, [debouncedSearch])
  const [page, setPage] = useState(1)
  const [selectedPOC, setSelectedPOC] = useState<POC | null>(null)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [isImporting, setIsImporting] = useState(false)
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [newPOC, setNewPOC] = useState<CreatePOCRequest>({
    name: '',
    type: 'custom',
    severity: 'medium',
    description: '',
    content: '',
    cveId: '',
    tags: [],
    author: '',
    enabled: true,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['pocs', page, debouncedSearch],
    // 切筛选/翻页时保留上一份数据渲染，列表不塌陷（消除点击闪烁）
    placeholderData: keepPreviousData,
    queryFn: () =>
      pocApi.list({
        page,
        pageSize: 10,
        search: debouncedSearch,
      }),
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      pocApi.toggleEnabled(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
    },
    onError: () => {
      toast({ title: '切换状态失败', variant: 'destructive' })
    },
  })

  const createMutation = useMutation({
    mutationFn: pocApi.create,
    onSuccess: () => {
      toast({ title: 'POC 创建成功' })
      setIsCreateDialogOpen(false)
      setNewPOC({
        name: '',
        type: 'custom',
        severity: 'medium',
        description: '',
        content: '',
        cveId: '',
        tags: [],
        author: '',
        enabled: true,
      })
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
      refetch()
    },
    onError: () => {
      toast({ title: 'POC 创建失败', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: pocApi.delete,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
    },
    onError: () => {
      toast({ title: '删除失败', variant: 'destructive' })
    },
  })

  const batchDeleteMutation = useMutation({
    mutationFn: pocApi.batchDelete,
    onSuccess: (response) => {
      const result = response.data || response
      toast({
        title: '批量删除完成',
        description: `成功删除 ${result.deleted} 个，失败 ${result.failed} 个`
      })
      setSelectedIds([])
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
    },
    onError: () => {
      toast({ title: '批量删除失败', variant: 'destructive' })
    },
  })

  const handleBatchDelete = async () => {
    if (selectedIds.length === 0) {
      toast({ title: '请先选择要删除的POC', variant: 'destructive' })
      return
    }
    if (await confirm(`确定要删除选中的 ${selectedIds.length} 个POC吗？`)) {
      batchDeleteMutation.mutate(selectedIds)
    }
  }

  const clearAllMutation = useMutation({
    mutationFn: pocApi.clearAll,
    onSuccess: (response) => {
      const result = response.data || response
      toast({
        title: '清除完成',
        description: `已删除 ${result.deleted} 个POC`
      })
      setSelectedIds([])
      queryClient.invalidateQueries({ queryKey: ['pocs'] })
      refetch()
    },
    onError: () => {
      toast({ title: '清除失败', variant: 'destructive' })
    },
  })

  const handleClearAll = async () => {
    if (total === 0) {
      toast({ title: '没有POC可清除', variant: 'destructive' })
      return
    }
    if (await confirm(`确定要清除所有 ${total} 个POC吗？此操作不可恢复！`)) {
      clearAllMutation.mutate()
    }
  }

  const handleCreate = () => {
    if (!newPOC.name || !newPOC.content) {
      toast({ title: '请填写名称和内容', variant: 'destructive' })
      return
    }
    createMutation.mutate(newPOC)
  }

  const handleImport = () => {
    fileInputRef.current?.click()
  }

  const handleZipImport = () => {
    zipInputRef.current?.click()
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string

      // 尝试解析 Nuclei YAML 模板
      const parsedPOC = parseNucleiTemplate(content, file.name)

      setNewPOC(parsedPOC)
      setIsCreateDialogOpen(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  // 解析 Nuclei 模板 YAML
  const parseNucleiTemplate = (content: string, filename: string): CreatePOCRequest => {
    const result: CreatePOCRequest = {
      name: filename.replace(/\.(yaml|yml|json)$/, ''),
      type: 'nuclei',
      severity: 'medium',
      description: '',
      content: content,
      cveId: '',
      tags: [],
      author: '',
      enabled: true,
    }

    try {
      // 简单解析 YAML（不使用库，手动匹配关键字段）
      const lines = content.split('\n')

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim()

        // 解析 id
        if (line.startsWith('id:')) {
          const id = line.replace('id:', '').trim().replace(/['"]/g, '')
          result.name = id
        }

        // 解析 name
        if (line.startsWith('name:')) {
          const name = line.replace('name:', '').trim().replace(/['"]/g, '')
          if (name) result.name = name
        }

        // 解析 author
        if (line.startsWith('author:')) {
          result.author = line.replace('author:', '').trim().replace(/['"]/g, '')
        }

        // 解析 severity
        if (line.startsWith('severity:')) {
          const severity = line.replace('severity:', '').trim().toLowerCase().replace(/['"]/g, '')
          if (['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
            result.severity = severity
          }
        }

        // 解析 description
        if (line.startsWith('description:')) {
          let desc = line.replace('description:', '').trim()
          // 处理多行描述
          if (desc === '|' || desc === '>') {
            desc = ''
            for (let j = i + 1; j < lines.length; j++) {
              const nextLine = lines[j]
              if (nextLine.match(/^\s{2,}/) || nextLine.trim() === '') {
                desc += nextLine.trim() + ' '
              } else {
                break
              }
            }
          }
          result.description = desc.replace(/['"]/g, '').trim()
        }

        // 解析 tags
        if (line.startsWith('tags:')) {
          const tagsStr = line.replace('tags:', '').trim().replace(/['"]/g, '')
          if (tagsStr) {
            result.tags = tagsStr.split(',').map(t => t.trim()).filter(Boolean)
          }
        }

        // 解析 cve-id
        if (line.includes('cve-id:') || line.includes('cveid:')) {
          // 可能是数组格式
          const nextLines: string[] = []
          for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
            if (lines[j].trim().startsWith('-')) {
              nextLines.push(lines[j].trim().replace(/^-\s*/, '').replace(/['"]/g, ''))
            } else if (!lines[j].trim().startsWith('#')) {
              break
            }
          }
          if (nextLines.length > 0) {
            result.cveId = nextLines[0]
          } else {
            const cveMatch = line.match(/CVE-\d{4}-\d+/i)
            if (cveMatch) {
              result.cveId = cveMatch[0].toUpperCase()
            }
          }
        }
      }

      // 如果在 content 中找到 CVE 但没解析到，尝试全文搜索
      if (!result.cveId) {
        const cveMatch = content.match(/CVE-\d{4}-\d+/i)
        if (cveMatch) {
          result.cveId = cveMatch[0].toUpperCase()
        }
      }
    } catch (error) {
      console.error('Failed to parse YAML:', error)
    }

    return result
  }

  const handleZipFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    if (!file.name.endsWith('.zip')) {
      toast({ title: '请选择 ZIP 文件', variant: 'destructive' })
      return
    }

    setIsImporting(true)
    try {
      const response = await pocApi.importZip(file)
      // 兼容两种响应格式
      const result = response.data || response
      const imported = result.imported ?? 0
      const failed = result.failed ?? 0
      const skipped = result.skipped ?? 0

      toast({
        title: 'ZIP 导入完成',
        description: `成功导入 ${imported} 个POC，失败 ${failed} 个，跳过 ${skipped} 个`,
      })
      // 强制刷新列表
      await queryClient.invalidateQueries({ queryKey: ['pocs'] })
      refetch()
    } catch (error) {
      toast({ title: '导入失败', variant: 'destructive' })
    } finally {
      setIsImporting(false)
      e.target.value = ''
    }
  }

  const pocs = data?.data?.list || []
  const total = data?.data?.total || 0

  const getSeverityLabel = (severity: string) => {
    const labels: Record<string, string> = {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    }
    return labels[severity] || severity
  }

  const columns: TableProps<POC>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      ellipsis: true,
      render: (v: string) => <span className="font-medium max-w-xs truncate">{v}</span>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      width: 100,
      render: (v: string) => <Tag>{v}</Tag>,
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (v: string) => <Tag className={cn(getSeverityColor(v))}>{getSeverityLabel(v)}</Tag>,
    },
    {
      title: 'CVE',
      dataIndex: 'cveId',
      key: 'cveId',
      width: 130,
      render: (v: string) => v || '-',
    },
    {
      title: '标签',
      key: 'tags',
      width: 160,
      render: (_, poc) => (
        <div className="flex gap-1 flex-wrap max-w-32">
          {poc.tags?.slice(0, 2).map((tag) => (
            <Tag key={tag} className={cn('text-xs', badgeCls('secondary'))}>
              {tag}
            </Tag>
          ))}
          {poc.tags && poc.tags.length > 2 && (
            <Tag className={cn('text-xs', badgeCls('secondary'))}>+{poc.tags.length - 2}</Tag>
          )}
        </div>
      ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 80,
      render: (v: boolean, poc) => (
        <Switch
          checked={v}
          onChange={(checked) => toggleMutation.mutate({ id: poc.id, enabled: checked })}
        />
      ),
    },
    {
      title: '更新时间',
      dataIndex: 'updatedAt',
      key: 'updatedAt',
      width: 150,
      render: (v: string) => formatDate(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      render: (_, poc) => (
        <div className="flex gap-1">
          <Button
            type="text"
            size="small"
            aria-label="查看POC"
            icon={<Eye className="h-4 w-4" />}
            onClick={() => setSelectedPOC(poc)}
          />
          <Button
            type="text"
            size="small"
            danger
            aria-label="删除POC"
            icon={<Trash2 className="h-4 w-4" />}
            onClick={() => deleteMutation.mutate(poc.id)}
          />
        </div>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      {/* Hidden file input for single file import */}
      <input
        type="file"
        ref={fileInputRef}
        className="hidden"
        accept=".yaml,.yml,.json"
        onChange={handleFileChange}
      />
      {/* Hidden file input for ZIP import */}
      <input
        type="file"
        ref={zipInputRef}
        className="hidden"
        accept=".zip"
        onChange={handleZipFileChange}
      />

      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">POC管理</h1>
        <div className="flex gap-2">
          <Button size="small" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Dropdown
            trigger={['click']}
            menu={{
              items: [
                {
                  key: 'file',
                  icon: <FileText className="h-4 w-4" style={{ fontSize: 0 }} />,
                  label: '导入单个文件 (YAML/JSON)',
                  onClick: () => handleImport(),
                },
                {
                  key: 'zip',
                  icon: <FileArchive className="h-4 w-4" style={{ fontSize: 0 }} />,
                  label: '批量导入 (ZIP包)',
                  onClick: () => handleZipImport(),
                },
              ],
            }}
          >
            <Button size="small" disabled={isImporting}>
              <Upload className="h-4 w-4 mr-2" />
              {isImporting ? '导入中...' : '导入'}
              <ChevronDown className="h-4 w-4 ml-2" />
            </Button>
          </Dropdown>
          <Button size="small" type="primary" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            新建POC
          </Button>
          <Button
            danger
            size="small"
            onClick={handleClearAll}
            disabled={clearAllMutation.isPending || total === 0}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            {clearAllMutation.isPending ? '清除中...' : '清除所有'}
          </Button>
        </div>
      </div>

      {/* Search */}
      <div className="flex gap-4 items-center">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground z-10" />
          <Input
            placeholder="搜索POC..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        {selectedIds.length > 0 && (
          <Button
            type="primary"
            danger
            size="small"
            onClick={handleBatchDelete}
            disabled={batchDeleteMutation.isPending}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            删除选中 ({selectedIds.length})
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table
          rowSelection={{
            selectedRowKeys: selectedIds,
            onChange: (keys) => setSelectedIds(keys as string[]),
          }}
          columns={columns}
          dataSource={pocs}
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

      {/* POC Detail Dialog */}
      <Modal
        open={!!selectedPOC}
        title={selectedPOC?.name}
        width={768}
        footer={null}
        onCancel={() => setSelectedPOC(null)}
      >
        <div className="space-y-4 py-2">
          <div className="grid grid-cols-3 gap-4">
            <div>
              <p className="text-sm text-muted-foreground">类型</p>
              <p className="font-medium">{selectedPOC?.type}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">CVE</p>
              <p className="font-medium">{selectedPOC?.cveId || '-'}</p>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">作者</p>
              <p className="font-medium">{selectedPOC?.author || '-'}</p>
            </div>
          </div>
          {selectedPOC?.description && (
            <div>
              <p className="text-sm text-muted-foreground mb-1">描述</p>
              <p className="text-sm">{selectedPOC.description}</p>
            </div>
          )}
          {selectedPOC?.tags && selectedPOC.tags.length > 0 && (
            <div>
              <p className="text-sm text-muted-foreground mb-1">标签</p>
              <div className="flex gap-1 flex-wrap">
                {selectedPOC.tags.map((tag) => (
                  <Tag key={tag}>{tag}</Tag>
                ))}
              </div>
            </div>
          )}
          <div>
            <p className="text-sm text-muted-foreground mb-1">代码</p>
            <Input.TextArea
              value={selectedPOC?.content || ''}
              readOnly
              rows={10}
              className="font-mono text-sm"
            />
          </div>
        </div>
      </Modal>

      {/* Create POC Dialog */}
      <Modal
        open={isCreateDialogOpen}
        title="新建 POC"
        width={768}
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
        <div className="space-y-4 py-2">
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">名称 *</label>
              <Input
                value={newPOC.name}
                onChange={(e) => setNewPOC({ ...newPOC, name: e.target.value })}
                placeholder="POC 名称"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">类型</label>
              <Select
                className="w-full"
                value={newPOC.type}
                onChange={(v) => setNewPOC({ ...newPOC, type: v })}
                options={[
                  { value: 'nuclei', label: 'Nuclei' },
                  { value: 'xray', label: 'Xray' },
                  { value: 'custom', label: '自定义' },
                ]}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">严重程度</label>
              <Select
                className="w-full"
                value={newPOC.severity}
                onChange={(v) => setNewPOC({ ...newPOC, severity: v })}
                options={[
                  { value: 'critical', label: '严重' },
                  { value: 'high', label: '高危' },
                  { value: 'medium', label: '中危' },
                  { value: 'low', label: '低危' },
                  { value: 'info', label: '信息' },
                ]}
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium">CVE ID</label>
              <Input
                value={newPOC.cveId}
                onChange={(e) => setNewPOC({ ...newPOC, cveId: e.target.value })}
                placeholder="CVE-XXXX-XXXX"
              />
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">描述</label>
            <Input
              value={newPOC.description}
              onChange={(e) => setNewPOC({ ...newPOC, description: e.target.value })}
              placeholder="POC 描述"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">标签 (逗号分隔)</label>
            <Input
              value={newPOC.tags?.join(', ')}
              onChange={(e) => setNewPOC({ ...newPOC, tags: e.target.value.split(',').map(t => t.trim()).filter(Boolean) })}
              placeholder="web, rce, sql"
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium">POC 内容 *</label>
            <Input.TextArea
              value={newPOC.content}
              onChange={(e) => setNewPOC({ ...newPOC, content: e.target.value })}
              placeholder="POC YAML/JSON 内容"
              rows={10}
              className="font-mono text-sm"
            />
          </div>
        </div>
      </Modal>
    </div>
  )
}

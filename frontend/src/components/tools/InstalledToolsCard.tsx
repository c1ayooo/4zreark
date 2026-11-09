import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert, Button, Card, Input, Select, Space, Switch, Table, Tag, Tooltip } from 'antd'
import { Download, RefreshCw, Search } from 'lucide-react'
import { useToast } from '@/components/ui/use-toast'
import {
  toolRuntimeApi,
  type InstalledTool,
  type InstalledToolsResult,
} from '@/api/tools'

// 平台自身工具只认项目内部目录（data/bin/tools、data/bin/nuclei、data/bin/browser、
// tools/<os>）。系统 PATH 上的同名工具是「环境外部候选」，不算平台安装。

const SOURCE_META: Record<string, { label: string; color: string }> = {
  managed: { label: '托管安装', color: 'blue' },
  vendored: { label: '项目内 vendored', color: 'geekblue' },
  nuclei: { label: 'nuclei 运行时', color: 'purple' },
  browser: { label: '自带浏览器', color: 'cyan' },
  override: { label: '环境变量覆盖', color: 'orange' },
  system: { label: '系统 PATH', color: 'orange' },
}

const SOURCE_OPTIONS = Object.entries(SOURCE_META).map(([value, meta]) => ({ value, label: meta.label }))

function formatSize(n?: number): string {
  if (!n || n <= 0) return '—'
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GB`
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KB`
  return `${n} B`
}

function formatTime(v?: string): string {
  if (!v) return '—'
  const d = new Date(v)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString()
}

export default function InstalledToolsCard({ onChanged }: { onChanged?: () => void }) {
  const { toast } = useToast()
  const [data, setData] = useState<InstalledToolsResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [ensuring, setEnsuring] = useState(false)
  const [keyword, setKeyword] = useState('')
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [includeExternal, setIncludeExternal] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      setData(await toolRuntimeApi.installed({
        q: q || undefined,
        source: source || undefined,
        include_external: includeExternal,
      }))
    } catch (e) {
      toast({ title: (e as Error)?.message || '检索已安装工具失败', variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }, [q, source, includeExternal, toast])

  useEffect(() => { load() }, [load])

  const ensure = async () => {
    setEnsuring(true)
    try {
      const res = await toolRuntimeApi.ensureInstalled()
      const failed = Object.entries(res).filter(([, v]) => v.startsWith('error:'))
      toast({
        title: failed.length ? `${failed.length} 个工具补装失败` : '项目内工具巡检完成',
        description: failed.length
          ? failed.map(([k, v]) => `${k}: ${v}`).join('；')
          : '缺失的工具已自动安装到项目目录内部',
        variant: failed.length ? 'destructive' : undefined,
      })
      await load()
      onChanged?.()
    } catch (e) {
      toast({ title: (e as Error)?.message || '补装失败', variant: 'destructive' })
    } finally {
      setEnsuring(false)
    }
  }

  const columns = useMemo(() => [
    {
      title: '工具',
      width: 190,
      render: (_: unknown, t: InstalledTool) => (
        <div>
          <div className="font-medium">{t.name}</div>
          <div className="text-xs text-muted-foreground">{t.description || (t.managed ? '受管扫描工具' : '项目内工具')}</div>
        </div>
      ),
    },
    {
      title: '位置 / 来源',
      width: 170,
      render: (_: unknown, t: InstalledTool) => {
        const meta = SOURCE_META[t.source] || { label: t.source, color: 'default' }
        return (
          <Space size={4} wrap>
            <Tag color={t.in_project ? 'success' : 'orange'}>{t.in_project ? '项目内部' : '环境外部'}</Tag>
            <Tag color={meta.color}>{meta.label}</Tag>
          </Space>
        )
      },
    },
    {
      title: '版本',
      width: 130,
      render: (_: unknown, t: InstalledTool) => <span className="font-mono text-xs">{t.version || '—'}</span>,
    },
    {
      title: '大小 / 权限',
      width: 140,
      render: (_: unknown, t: InstalledTool) => (
        <Space size={4}>
          <span className="text-xs">{formatSize(t.size_bytes)}</span>
          {!t.executable && <Tooltip title="文件没有执行权限"><Tag color="error">不可执行</Tag></Tooltip>}
        </Space>
      ),
    },
    {
      title: '路径 / 修改时间',
      render: (_: unknown, t: InstalledTool) => (
        <div>
          <div className="font-mono text-xs break-all">{t.path}</div>
          <div className="text-xs text-muted-foreground">{formatTime(t.mod_time)}{t.note ? ` · ${t.note}` : ''}</div>
        </div>
      ),
    },
  ], [])

  const rows = data?.items ?? []

  return (
    <Card
      title="平台已安装工具（项目内部）"
      extra={
        <Space wrap>
          <Input
            size="small"
            allowClear
            placeholder="名称 / 路径关键字"
            value={keyword}
            onChange={(e) => setKeyword(e.target.value)}
            onPressEnter={() => setQ(keyword.trim())}
            style={{ width: 190 }}
          />
          <Button size="small" icon={<Search className="h-3.5 w-3.5" />} onClick={() => setQ(keyword.trim())}>检索</Button>
          <Select
            size="small"
            allowClear
            placeholder="全部来源"
            options={SOURCE_OPTIONS}
            value={source || undefined}
            onChange={(v) => setSource(v || '')}
            style={{ width: 150 }}
          />
          <Tooltip title="把系统 PATH / 环境变量指向的外部工具也列入结果（明确标记为环境外部）">
            <Space size={6}>
              <Switch size="small" checked={includeExternal} onChange={setIncludeExternal} />
              <span className="text-xs">含外部</span>
            </Space>
          </Tooltip>
          <Button size="small" icon={<RefreshCw className="h-3.5 w-3.5" />} onClick={load} loading={loading}>刷新</Button>
          <Button
            size="small"
            type="primary"
            icon={<Download className="h-3.5 w-3.5" />}
            loading={ensuring}
            onClick={ensure}
          >
            检测并安装缺失工具
          </Button>
        </Space>
      }
    >
      {data && data.external_count > 0 && (
        <Alert
          className="mb-3"
          type="warning"
          showIcon
          message={`环境里发现 ${data.external_count} 个外部工具，不算平台自身安装`}
          description="平台只把项目内部目录里的二进制视为已安装。点击「检测并安装缺失工具」会把缺失工具自动下载到项目目录内部；也可勾选「含外部」查看这些路径。"
        />
      )}
      <Table
        rowKey={(r: InstalledTool) => r.path}
        size="small"
        loading={loading}
        pagination={false}
        dataSource={rows}
        columns={columns as never}
        locale={{ emptyText: '项目内部尚未检测到工具' }}
      />
      {!!data?.roots?.length && (
        <p className="mt-3 text-xs text-muted-foreground break-all">
          检索目录：{data.roots.join(' · ')} · 命中 {data.total} 项
        </p>
      )}
    </Card>
  )
}

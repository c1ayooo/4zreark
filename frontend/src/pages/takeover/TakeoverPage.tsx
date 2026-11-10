import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { takeoverApi, TakeoverFingerprint, TakeoverResult } from '@/api/takeover'
import { Button, Card, Input, Progress, Table, Tabs, Tag } from 'antd'
import type { TableProps } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import RecordDetailDrawer from '@/components/common/RecordDetailDrawer'
import {
  Globe,
  Play,
  AlertTriangle,
  CheckCircle,
  Shield,
  Target,
} from 'lucide-react'

export default function TakeoverPage() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState('single')
  const [singleDomain, setSingleDomain] = useState('')
  const [batchDomains, setBatchDomains] = useState('')
  const [results, setResults] = useState<TakeoverResult[]>([])
  const [scanning, setScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  // 历史记录表与扫描结果表共用一个详情抽屉，行点击打开
  const [detail, setDetail] = useState<TakeoverResult | null>(null)

  // 接管指纹库：展示当前可识别的服务与判定方式
  const { data: fingerprintsData } = useQuery({
    queryKey: ['takeover-fingerprints'],
    queryFn: takeoverApi.getFingerprints,
  })

  // 单域名扫描
  const singleMutation = useMutation({
    mutationFn: takeoverApi.check,
    onSuccess: (res) => {
      setResults([res.data])
      if (res.data.vulnerable) {
        toast({
          title: '发现可接管域名!',
          description: `${res.data.domain} - ${res.data.service || '未知服务'}`,
          variant: 'destructive',
        })
      } else {
        toast({ title: '扫描完成', description: '未发现可接管域名' })
      }
    },
    onError: () => {
      toast({ title: '扫描失败', variant: 'destructive' })
    },
  })

  // 批量扫描
  const batchMutation = useMutation({
    mutationFn: takeoverApi.batchCheck,
    onMutate: () => {
      setScanning(true)
      setProgress(0)
    },
    onSuccess: (res) => {
      setResults(res.data.results)
      setScanning(false)
      setProgress(100)
      if (res.data.vulnerable > 0) {
        toast({
          title: `发现 ${res.data.vulnerable} 个可接管域名!`,
          variant: 'destructive',
        })
      } else {
        toast({ title: '扫描完成', description: '未发现可接管域名' })
      }
    },
    onError: () => {
      setScanning(false)
      toast({ title: '扫描失败', variant: 'destructive' })
    },
  })

  const fingerprints: TakeoverFingerprint[] = fingerprintsData?.data || []

  const handleSingleScan = () => {
    if (!singleDomain) {
      toast({ title: '请输入域名', variant: 'destructive' })
      return
    }
    setResults([])
    singleMutation.mutate(singleDomain)
  }

  const handleBatchScan = () => {
    const domains = batchDomains
      .split('\n')
      .map((d) => d.trim())
      .filter((d) => d)
    
    if (domains.length === 0) {
      toast({ title: '请输入至少一个域名', variant: 'destructive' })
      return
    }
    setResults([])
    batchMutation.mutate(domains)
  }

  // 统计结果
  const vulnerableCount = results.filter((r) => r.vulnerable).length
  const safeCount = results.filter((r) => !r.vulnerable).length

  const renderVulnerableTag = (vulnerable: boolean) =>
    vulnerable ? (
      <Tag className="flex w-fit items-center gap-1 border-transparent bg-destructive text-destructive-foreground">
        <AlertTriangle className="h-3 w-3" />
        可接管
      </Tag>
    ) : (
      <Tag className="flex w-fit items-center gap-1">
        <CheckCircle className="h-3 w-3" />
        安全
      </Tag>
    )

  // 行点击看详情：历史表与结果表同构（TakeoverResult），共用 onRow 与抽屉字段
  const onRow: TableProps<TakeoverResult>['onRow'] = (record) => ({
    className: 'cursor-pointer',
    onClick: () => setDetail(record),
  })

  const detailFields = detail
    ? [
        { label: '域名', value: detail.domain },
        { label: '状态', value: detail.vulnerable ? '可接管' : '安全' },
        { label: '服务', value: detail.service || '' },
        { label: 'CNAME', value: detail.cname || '' },
        { label: '指纹', value: detail.fingerprints?.join(', ') || '' },
        { label: '判定原因', value: detail.reason || '' },
        ...(detail.discussion ? [{ label: '说明', value: detail.discussion }] : []),
      ]
    : []

  const resultColumns: TableProps<TakeoverResult>['columns'] = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (_, result) => <span className="font-medium">{result.domain}</span>,
    },
    {
      title: '状态',
      dataIndex: 'vulnerable',
      key: 'vulnerable',
      width: 90,
      render: (_, result) => renderVulnerableTag(result.vulnerable),
    },
    {
      title: '服务',
      dataIndex: 'service',
      key: 'service',
      render: (_, result) => result.service || '-',
    },
    {
      title: 'CNAME',
      dataIndex: 'cname',
      key: 'cname',
      ellipsis: true,
      render: (_, result) => result.cname || '-',
    },
    {
      title: '判定原因',
      dataIndex: 'reason',
      key: 'reason',
      ellipsis: true,
      render: (_, result) => (
        <span className="text-xs text-muted-foreground">{result.reason || '-'}</span>
      ),
    },
  ]

  return (
    <div className="space-y-6">
      {/* 页面头部 */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Globe className="h-6 w-6 text-primary" />
          <h1 className="text-2xl font-bold">子域名接管检测</h1>
        </div>
      </div>

      {/* 指纹库概览 */}
      <Card title={<span className="text-sm font-medium">接管指纹库</span>}>
        <p className="text-sm text-muted-foreground">
          共内置 {fingerprints.length} 个服务的接管指纹，命中 CNAME 尾缀或响应特征即判定可接管
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {fingerprints.slice(0, 20).map((fp) => (
            <Tag key={fp.service}>{fp.service}</Tag>
          ))}
          {fingerprints.length > 20 && <Tag>+{fingerprints.length - 20} 更多</Tag>}
        </div>
      </Card>

      {/* 标签页 */}
      <Tabs
        activeKey={activeTab}
        onChange={setActiveTab}
        items={[
          {
            key: 'single',
            label: '单域名扫描',
            children: (
              <Card>
                <div className="flex gap-4">
                  <div className="flex-1">
                    <Input
                      placeholder="输入子域名，如: sub.example.com"
                      value={singleDomain}
                      onChange={(e) => setSingleDomain(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleSingleScan()}
                    />
                  </div>
                  <Button
                    type="primary"
                    onClick={handleSingleScan}
                    disabled={singleMutation.isPending}
                  >
                    <Target className="h-4 w-4 mr-2" />
                    开始扫描
                  </Button>
                </div>
              </Card>
            ),
          },
          {
            key: 'batch',
            label: '批量扫描',
            children: (
              <Card>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">域名列表 (每行一个)</label>
                    <Input.TextArea
                      placeholder="sub1.example.com&#10;sub2.example.com&#10;sub3.example.com"
                      rows={8}
                      value={batchDomains}
                      onChange={(e) => setBatchDomains(e.target.value)}
                    />
                  </div>
                  {scanning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>扫描进度</span>
                        <span>{progress}%</span>
                      </div>
                      <Progress percent={progress} showInfo={false} />
                    </div>
                  )}
                  <Button
                    type="primary"
                    onClick={handleBatchScan}
                    disabled={batchMutation.isPending}
                    className="w-full"
                  >
                    <Play className="h-4 w-4 mr-2" />
                    批量扫描
                  </Button>
                </div>
              </Card>
            ),
          },
        ]}
      />

      {/* 扫描结果 */}
      {results.length > 0 && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              扫描结果
            </span>
          }
        >
          <p className="text-sm text-muted-foreground">
            共扫描 {results.length} 个域名，发现 {vulnerableCount} 个可接管，{safeCount} 个安全
          </p>
          <div className="mt-4 rounded-lg border">
            <Table<TakeoverResult>
              columns={resultColumns}
              dataSource={results}
              rowKey={(_, index) => String(index)}
              onRow={onRow}
              rowClassName={(result) =>
                result.vulnerable ? 'bg-red-50 dark:bg-red-950/20' : ''
              }
              pagination={false}
            />
          </div>
        </Card>
      )}

      <RecordDetailDrawer
        open={detail !== null}
        onClose={() => setDetail(null)}
        title={detail ? `接管详情 · ${detail.domain}` : '接管详情'}
        fields={detailFields}
        raw={detail ?? undefined}
      />
    </div>
  )
}

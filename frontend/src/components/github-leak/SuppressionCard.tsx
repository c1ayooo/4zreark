import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Input, Select, Tabs, Table, Tag } from 'antd'
import { Ban, Plus, Sparkles } from 'lucide-react'
import { githubMonitorApi, type GitHubRulePrecision, type GitHubSuppression } from '@/api/githubMonitor'
import { useToast } from '@/components/ui/use-toast'
import { LEAK_OPS_KEY } from './shared'

const SUPPRESSION_TYPE_OPTIONS = [
  { value: 'repo', label: '仓库（owner/name）' },
  { value: 'org', label: '组织/用户' },
  { value: 'path_glob', label: '路径通配' },
  { value: 'rule', label: '规则名' },
  { value: 'fingerprint_prefix', label: '指纹前缀' },
]

/** 抑制治理：静默清单 + 规则精度 + 从域名/组织自动建规则。 */
export function SuppressionCard() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [patternType, setPatternType] = useState('repo')
  const [pattern, setPattern] = useState('')
  const [note, setNote] = useState('')
  const [domain, setDomain] = useState('')
  const [org, setOrg] = useState('')

  const invalidate = () => queryClient.invalidateQueries({ queryKey: LEAK_OPS_KEY })

  const suppressionsQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'suppressions'],
    queryFn: () => githubMonitorApi.listSuppressions(),
  })
  const suppressions = suppressionsQuery.data?.data?.suppressions ?? []

  const precisionQuery = useQuery({
    queryKey: [...LEAK_OPS_KEY, 'precision'],
    queryFn: () => githubMonitorApi.rulePrecisionStats(),
  })
  const precision = precisionQuery.data?.data?.rules ?? []

  const suppressionMutation = useMutation({
    mutationFn: async (
      action:
        | { type: 'add'; body: { pattern_type: string; pattern: string; note?: string } }
        | { type: 'delete'; id: string },
    ) => {
      if (action.type === 'delete') return githubMonitorApi.deleteSuppression(action.id)
      return githubMonitorApi.addSuppression(action.body)
    },
    onSuccess: (res) => {
      toast({ title: res.message || '已保存' })
      setPattern('')
      setNote('')
      invalidate()
    },
    onError: (e: Error) => toast({ title: '操作失败', description: e.message, variant: 'destructive' }),
  })

  const autoRules = useMutation({
    mutationFn: () => githubMonitorApi.addAutoRules({ domain: domain.trim() || undefined, org: org.trim() || undefined }),
    onSuccess: (res) => {
      toast({ title: `已生成 ${res.data?.added ?? 0} 条规则（2 分钟内热更生效）` })
      setDomain('')
      setOrg('')
      invalidate()
    },
    onError: (e: Error) => toast({ title: '生成失败', description: e.message, variant: 'destructive' }),
  })

  const suppressionsPane = (
    <div>
      <div className="mb-3 flex flex-wrap gap-2">
        <Select
          size="small"
          className="w-40"
          value={patternType}
          onChange={setPatternType}
          options={SUPPRESSION_TYPE_OPTIONS}
        />
        <Input
          size="small"
          className="w-72"
          placeholder="匹配值（如 owner/repo、*.example.com/*）"
          value={pattern}
          onChange={(e) => setPattern(e.target.value)}
          onPressEnter={() =>
            pattern.trim() &&
            suppressionMutation.mutate({ type: 'add', body: { pattern_type: patternType, pattern: pattern.trim(), note: note.trim() || undefined } })
          }
        />
        <Input
          size="small"
          className="w-44"
          placeholder="备注（可选）"
          value={note}
          onChange={(e) => setNote(e.target.value)}
        />
        <Button
          size="small"
          type="primary"
          icon={<Plus className="size-3.5" />}
          disabled={!pattern.trim()}
          loading={suppressionMutation.isPending}
          onClick={() =>
            suppressionMutation.mutate({ type: 'add', body: { pattern_type: patternType, pattern: pattern.trim(), note: note.trim() || undefined } })
          }
        >
          加抑制
        </Button>
      </div>
      <div className="flex min-h-[40px] flex-wrap gap-1.5">
        {suppressions.length === 0 ? (
          <span className="text-xs text-muted-foreground">暂无抑制规则；标记误报时会自动按指纹静默</span>
        ) : (
          suppressions.map((s: GitHubSuppression) => (
            <Tag
              key={s.id}
              closable
              onClose={(e) => {
                e.preventDefault()
                suppressionMutation.mutate({ type: 'delete', id: s.id })
              }}
              className="max-w-[440px]"
            >
              <span className="font-mono text-[10px] text-muted-foreground">[{s.pattern_type}]</span> {s.pattern}
              {s.note && <span className="ml-1 text-[10px] text-muted-foreground">· {s.note}</span>}
            </Tag>
          ))
        )}
      </div>
    </div>
  )

  const precisionPane = (
    <Table<GitHubRulePrecision>
      rowKey="rule_name"
      size="small"
      tableLayout="fixed"
      loading={precisionQuery.isLoading}
      dataSource={precision}
      pagination={false}
      locale={{ emptyText: '暂无判定数据——处置命中后这里会给出精确率' }}
      columns={[
        { title: '规则', dataIndex: 'rule_name', key: 'rule_name', ellipsis: true },
        { title: '命中', dataIndex: 'total', key: 'total', width: 80 },
        { title: '确认', dataIndex: 'confirmed', key: 'confirmed', width: 80 },
        { title: '误报', dataIndex: 'false_positive', key: 'false_positive', width: 80 },
        { title: '忽略', dataIndex: 'ignored', key: 'ignored', width: 80 },
        {
          title: '精确率',
          dataIndex: 'precision',
          key: 'precision',
          width: 100,
          render: (v: number) => <span className={v < 0.5 ? 'text-destructive' : 'text-emerald-500'}>{(v * 100).toFixed(0)}%</span>,
        },
      ]}
    />
  )

  const autoPane = (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground">
        从平台资产域名或 GitHub 组织自动生成监控关键词规则（规则写在内核，2 分钟热更生效）。
      </p>
      <div className="flex flex-wrap gap-2">
        <Input size="small" className="w-64" placeholder="域名（如 lixiang.com）" value={domain} onChange={(e) => setDomain(e.target.value)} />
        <Input size="small" className="w-64" placeholder="组织（如 LiAutoInc）" value={org} onChange={(e) => setOrg(e.target.value)} />
        <Button
          size="small"
          type="primary"
          icon={<Sparkles className="size-3.5" />}
          disabled={!domain.trim() && !org.trim()}
          loading={autoRules.isPending}
          onClick={() => autoRules.mutate()}
        >
          生成规则
        </Button>
      </div>
    </div>
  )

  return (
    <div className="rounded-xl border border-border bg-card/50 p-4">
      <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
        <Ban className="size-4 text-primary" /> 抑制与规则治理
      </div>
      <Tabs
        size="small"
        items={[
          { key: 'suppressions', label: '误报抑制', children: suppressionsPane },
          { key: 'precision', label: '规则精度', children: precisionPane },
          { key: 'auto', label: '自动建规则', children: autoPane },
        ]}
      />
    </div>
  )
}

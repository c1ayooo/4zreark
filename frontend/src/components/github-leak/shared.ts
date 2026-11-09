/** 全局「敏感信息监控」页共享常量：保证各块操作后精确失效，不做全量 refetch。 */

export const LEAK_OPS_KEY = ['github-leak-ops']
export const LEAK_GLOBAL_FINDINGS_KEY = ['github-leak-global-findings']

/** 状态中文标签（与包层 ValidStatus 枚举一致） */
export const FINDING_STATUS_LABEL: Record<string, string> = {
  new: '待研判',
  triaged: '已研判',
  confirmed: '已确认',
  false_positive: '误报',
  ignored: '已忽略',
  resolved: '已处置',
}

export const FINDING_STATUS_OPTIONS = [
  { value: '', label: '全部状态' },
  { value: 'new', label: '待研判' },
  { value: 'triaged', label: '已研判' },
  { value: 'confirmed', label: '已确认' },
  { value: 'false_positive', label: '误报' },
  { value: 'ignored', label: '已忽略' },
  { value: 'resolved', label: '已处置' },
]

export const VERIFY_STATUS_OPTIONS = [
  { value: 'valid', label: '有效' },
  { value: 'invalid', label: '无效' },
  { value: 'restricted', label: '受限' },
  { value: 'unverifiable', label: '无法验证' },
]

export const severityClass = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'border-transparent bg-red-600 text-white'
    case 'high':
      return 'border-transparent bg-orange-500 text-white'
    case 'medium':
      return 'border-transparent bg-amber-500 text-white'
    default:
      return 'border-transparent bg-secondary text-secondary-foreground'
  }
}

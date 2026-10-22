import type { InAppNotification } from '@/api/notify'

// 通知点击目标：优先用后端写入的 link，旧通知按 source 兜底。
export function notificationLink(n: InAppNotification): string | null {
  const extra = n.extra ?? {}
  const link = typeof extra.link === 'string' ? extra.link : ''
  if (link.startsWith('/')) return link

  const vulnID = extra.vuln_id
  if (typeof vulnID === 'string' && vulnID) return `/vulnerabilities/${vulnID}`

  switch (n.source) {
    case 'vuln-review':
      return '/vulnerabilities'
    case 'node-watchdog':
      return '/nodes'
    case 'intel':
      return '/vuln-intel'
    case 'monitor':
      return '/monitor'
    default:
      return null
  }
}

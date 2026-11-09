import type { InAppNotification } from '@/api/notify'

// 通知点击目标：优先用后端写入的 link，旧通知按 source 兜底。
export function notificationLink(n: InAppNotification): string | null {
  const extra = n.extra ?? {}
  const link = typeof extra.link === 'string' ? extra.link : ''
  const localPath = toLocalPath(link)
  if (localPath) return localPath

  const vulnID = extra.vuln_id
  if (typeof vulnID === 'string' && vulnID) return `/vulnerabilities/${vulnID}`

  switch (n.source) {
    case 'vuln-review':
      return '/vulnerabilities'
    case 'node-watchdog':
      return '/nodes'
    case 'intel':
    case 'vuln-intel':
      return '/vuln-intel'
    case 'monitor':
    case 'asset_monitor':
      return '/monitor'
    case 'github-leak':
      return '/github-leaks'
    default:
      return null
  }
}

// 后端配置 Server.PublicURL 时 extra.link 会是绝对地址（IM 卡片「前往处置」用），
// 站内通知需还原成同源 SPA 路由；外域链接一律不跳，避免 navigate 跳出平台。
function toLocalPath(link: string): string | null {
  if (!link) return null
  if (link.startsWith('/') && !link.startsWith('//')) return link
  if (!/^https?:\/\//i.test(link)) return null
  try {
    const url = new URL(link)
    if (url.origin !== window.location.origin) return null
    return url.pathname + url.search + url.hash
  } catch {
    return null
  }
}

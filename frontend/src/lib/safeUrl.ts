// 安全审计 M16：动态外链统一出口。只放行 http/https，
// 拒绝 javascript:/data:/vbscript:/file: 等可执行协议。
// 渲染层所有用户/数据可控的 href 必须经它过滤；返回 undefined 时
// React 渲染出的 <a> 没有 href，链接降级为不可点击的文本。
const SAFE_PROTOCOLS = new Set(['http:', 'https:'])

export function safeExternalURL(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined
  const trimmed = raw.trim()
  if (trimmed === '') return undefined
  try {
    const u = new URL(trimmed)
    if (!SAFE_PROTOCOLS.has(u.protocol)) return undefined
    return u.toString()
  } catch {
    return undefined
  }
}

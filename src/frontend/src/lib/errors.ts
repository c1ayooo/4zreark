// 统一的后端错误信息提取。
// api 拦截器把业务错误(HTTP 200 + code≠0)转成 reject(body 含 message),
// HTTP 层错误 reject error.response.data——两处都取 message,取不到用 fallback。
export function getErrorMessage(e: unknown, fallback = '操作失败'): string {
  const err = e as { message?: string; response?: { data?: { message?: string } } } | null
  if (!err) return fallback
  return (
    (typeof err.message === 'string' && err.message) ||
    (typeof err.response?.data?.message === 'string' && err.response.data.message) ||
    fallback
  )
}

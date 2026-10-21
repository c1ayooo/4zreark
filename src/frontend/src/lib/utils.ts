import { type ClassValue, clsx } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date) {
  return new Date(date).toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function formatNumber(num: number) {
  return num.toLocaleString('zh-CN')
}

export function truncate(str: string, length: number) {
  if (str.length <= length) return str
  return str.slice(0, length) + '...'
}

export function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-red-500 text-white'
    case 'high':
      return 'bg-orange-500 text-white'
    case 'medium':
      return 'bg-yellow-500 text-black'
    case 'low':
      return 'bg-blue-500 text-white'
    case 'info':
      return 'bg-gray-500 text-white'
    default:
      return 'bg-gray-400 text-white'
  }
}

export function getStatusColor(status: string) {
  if (!status || typeof status !== 'string') {
    return 'bg-gray-500 text-white'
  }
  switch (status.toLowerCase()) {
    case 'running':
    case 'online':
    case 'active':
      return 'bg-primary text-primary-foreground'
    case 'pending':
    case 'queued':
    case 'busy':
      return 'bg-amber-500 text-black'
    case 'failed':
    case 'offline':
    case 'error':
      return 'bg-destructive text-destructive-foreground'
    case 'completed':
    case 'success':
      return 'bg-secondary text-secondary-foreground'
    case 'paused':
    case 'stopped':
    case 'disabled':
      return 'bg-muted text-muted-foreground'
    default:
      return 'bg-muted text-muted-foreground'
  }
}

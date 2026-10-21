import { useEffect, useState } from 'react'
import { useWebSocket } from '@/hooks/useWebSocket'
import { cn } from '@/lib/utils'

interface SystemData {
  cpu_usage: number
  memory_usage: number
  memory_total: number
  memory_used: number
  disk_usage: number
  disk_total: number
  disk_used: number
}

interface NodesData {
  total: number
  online: number
  offline: number
}

interface MonitorData {
  type: string
  timestamp: number
  system: SystemData
  nodes: NodesData
}

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${Math.round((bytes / Math.pow(k, i)) * 100) / 100} ${sizes[i]}`
}

function formatPercentage(value: number) {
  return Math.min(100, Math.max(0, value)).toFixed(1)
}

function Meter({
  label,
  value,
  detail,
}: {
  label: string
  value: number
  detail: string
}) {
  const bar = value >= 85 ? 'hsl(var(--destructive))' : 'hsl(var(--primary))'
  return (
    <div>
      <p className="text-[13px] text-muted-foreground">{label}</p>
      <p className="mt-2 text-2xl font-semibold tabular-nums">{formatPercentage(value)}%</p>
      <p className="mt-1 text-[13px] tabular-nums text-muted-foreground">{detail}</p>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full transition-[width] duration-500"
          style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: bar }}
        />
      </div>
    </div>
  )
}

export default function RealTimeMonitor() {
  const [monitorData, setMonitorData] = useState<MonitorData | null>(null)
  const [connectionStatus, setConnectionStatus] = useState<
    'connected' | 'disconnected' | 'connecting'
  >('connecting')

  const { isConnected } = useWebSocket('/api/ws', {
    onMessage: (message) => {
      if (message.type === 'monitor_data') {
        setMonitorData(message as MonitorData)
      }
    },
    onOpen: () => setConnectionStatus('connected'),
    onClose: () => setConnectionStatus('disconnected'),
  })

  useEffect(() => {
    setConnectionStatus(isConnected ? 'connected' : 'disconnected')
  }, [isConnected])

  const system = monitorData?.system
  const nodes = monitorData?.nodes

  return (
    <section className="border-t pt-6">
      <div className="flex items-baseline justify-between gap-4">
        <h2 className="text-[15px] font-semibold">运行环境</h2>
        <span
          className={cn(
            'inline-flex items-center gap-1.5 text-[13px]',
            connectionStatus === 'connected' ? 'text-primary' : 'text-destructive'
          )}
        >
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
          {connectionStatus === 'connected'
            ? '实时连接'
            : connectionStatus === 'connecting'
              ? '连接中'
              : '已断开'}
        </span>
      </div>

      <div className="mt-4 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        <Meter
          label="CPU"
          value={system?.cpu_usage ?? 0}
          detail={system ? `${system.cpu_usage.toFixed(1)}% 使用中` : '等待数据'}
        />
        <Meter
          label="内存"
          value={system?.memory_usage ?? 0}
          detail={
            system
              ? `${formatBytes(system.memory_used)} / ${formatBytes(system.memory_total)}`
              : '等待数据'
          }
        />
        <Meter
          label="磁盘"
          value={system?.disk_usage ?? 0}
          detail={
            system
              ? `${formatBytes(system.disk_used)} / ${formatBytes(system.disk_total)}`
              : '等待数据'
          }
        />
        <div>
          <p className="text-[13px] text-muted-foreground">扫描节点</p>
          <p className="mt-2 text-2xl font-semibold tabular-nums">
            {nodes?.online ?? 0}
            <span className="ml-1 text-base font-normal text-muted-foreground">
              / {nodes?.total ?? 0}
            </span>
          </p>
          <p
            className={cn(
              'mt-1 text-[13px] tabular-nums',
              (nodes?.offline ?? 0) > 0 ? 'text-destructive' : 'text-muted-foreground'
            )}
          >
            {(nodes?.offline ?? 0) > 0 ? `${nodes?.offline} 个离线` : '全部在线'}
          </p>
        </div>
      </div>

      {monitorData?.timestamp ? (
        <p className="mt-4 text-[13px] tabular-nums text-muted-foreground">
          最后更新：
          {new Date(monitorData.timestamp * 1000).toLocaleString('zh-CN')}
        </p>
      ) : null}
    </section>
  )
}

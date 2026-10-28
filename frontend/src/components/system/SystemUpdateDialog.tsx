import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Badge, Button, Modal, Progress, Tag } from 'antd'
import { ArrowUpCircle, RefreshCw } from 'lucide-react'

import { systemApi, type UpdateState, type VersionInfo } from '@/api/system'
import { useAuthStore } from '@/store/auth'
import { useToast } from '@/components/ui/use-toast'

const stageText: Record<string, string> = {
  idle: '待机',
  checking: '检查更新中…',
  downloading: '下载新版本中…',
  verifying: '校验 sha256…',
  replacing: '替换二进制…',
  restarting: '服务重启中…',
  done: '更新完成',
  error: '更新失败',
}

function fmtBytes(n: number) {
  if (n <= 0) return '0'
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(0)} KB`
  return `${n} B`
}

// 顶栏版本徽标：轮询 /system/version，有新版时点亮；点击开更新弹窗。
export function SystemUpdateButton() {
  const [open, setOpen] = useState(false)
  const version = useQuery({
    queryKey: ['system-version'],
    queryFn: () => systemApi.version(),
    refetchInterval: 30 * 60 * 1000,
    staleTime: 5 * 60 * 1000,
  })
  const info = version.data?.data
  const hasUpdate = !!info?.has_update

  return (
    <>
      <Badge dot={hasUpdate} offset={[-2, 2]}>
        <Button
          type="text"
          size="small"
          onClick={() => {
            version.refetch()
            setOpen(true)
          }}
          icon={<ArrowUpCircle className={hasUpdate ? 'h-4 w-4 text-primary' : 'h-4 w-4'} />}
          aria-label="版本更新"
          title={hasUpdate ? `有新版本 ${info?.latest}，点击查看` : `当前版本 ${info?.current ?? ''}`}
        />
      </Badge>
      <SystemUpdateDialog
        open={open}
        onClose={() => setOpen(false)}
        info={info}
        loading={version.isLoading}
      />
    </>
  )
}

// 更新弹窗：版本对照 + 一键更新 + 进度条（1s 轮询后端下载/校验/替换/重启状态）。
function SystemUpdateDialog({ open, onClose, info, loading }: {
  open: boolean
  onClose: () => void
  info?: VersionInfo
  loading: boolean
}) {
  const { toast } = useToast()
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const [state, setState] = useState<UpdateState | null>(null)
  const [countdown, setCountdown] = useState<number | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // 更新进行中：1s 轮询进度
  useEffect(() => {
    if (!state || ['idle', 'done', 'error', 'restarting'].includes(state.stage)) {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
      return
    }
    pollRef.current = setInterval(async () => {
      try {
        const res = await systemApi.updateStatus()
        setState(res.data)
      } catch {
        // 轮询失败多为服务正在重启，忽略本帧
      }
    }, 1000)
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [state?.stage, state])

  // 重启阶段：倒计时后整页刷新（新二进制已由 supervise 拉起）
  useEffect(() => {
    if (state?.stage !== 'restarting') return
    setCountdown(8)
    const t = setInterval(() => {
      setCountdown((c) => {
        if (c !== null && c <= 1) {
          clearInterval(t)
          window.location.reload()
          return 0
        }
        return c !== null ? c - 1 : null
      })
    }, 1000)
    return () => clearInterval(t)
  }, [state?.stage])

  const start = async () => {
    try {
      const res = await systemApi.startUpdate(info?.latest ?? '')
      setState(res.data)
      toast({ title: '更新已启动' })
    } catch (e: any) {
      toast({ title: '启动失败', description: e?.response?.data?.message || e?.message, variant: 'destructive' })
    }
  }

  const stage = state?.stage
  const running = !!state && !['idle', 'done', 'error'].includes(stage as string)
  const percent = Math.round(state?.percent ?? 0)

  return (
    <Modal
      open={open}
      onCancel={() => {
        if (!running) onClose()
      }}
      closable={!running}
      maskClosable={!running}
      keyboard={!running}
      width={520}
      title="系统更新"
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose} disabled={running}>
            {running ? '更新进行中…' : '关闭'}
          </Button>
          {isAdmin && !running && (
            <Button type="primary" onClick={start} disabled={!info?.has_update} icon={<ArrowUpCircle className="h-4 w-4" />}>
              更新到 {info?.latest}
            </Button>
          )}
        </div>
      }
    >
      <div className="space-y-4">
        <div className="flex items-center justify-between rounded-lg border p-3">
          <div>
            <p className="text-muted-foreground text-xs">当前版本</p>
            <p className="font-mono text-sm font-semibold">{info?.current || '—'}</p>
          </div>
          <div className="text-muted-foreground/50">→</div>
          <div className="text-right">
            <p className="text-muted-foreground text-xs">GitHub 最新版</p>
            {loading ? (
              <RefreshCw className="animate-spin" />
            ) : (
              <p className="font-mono text-sm font-semibold">{info?.latest || '检测失败'}</p>
            )}
          </div>
        </div>

        {info?.has_update ? (
          <div className="flex items-center justify-between text-sm">
            <span>
              发现新版本
              {info.published_at ? <span className="text-muted-foreground ml-2 text-xs">发布于 {info.published_at}</span> : null}
              {info.asset_size ? <span className="text-muted-foreground ml-2 text-xs">{fmtBytes(info.asset_size)}</span> : null}
            </span>
            {info.release_url && (
              <a href={info.release_url} target="_blank" rel="noreferrer" className="text-primary text-xs hover:underline">
                查看 Release
              </a>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">
            {info?.error ? `检测失败：${info.error}` : info?.current === 'dev'
              ? '当前为源码构建（dev），无法与 Release 比较；仍可手动更新到最新 Release。'
              : '已是最新版本。'}
          </p>
        )}

        {running && (
          <div className="space-y-2 rounded-lg border p-3">
            <div className="flex items-center justify-between text-sm">
              <span>{stage ? stageText[stage] ?? stage : ""}</span>
              {stage === 'downloading' && (
                <span className="font-mono text-xs text-muted-foreground">
                  {fmtBytes(state?.downloaded ?? 0)} / {fmtBytes(state?.total ?? 0)}
                </span>
              )}
            </div>
            <Progress
              percent={percent}
              status={stage === 'verifying' || stage === 'replacing' ? 'active' : 'normal'}
              strokeWidth={8}
            />
            <p className="text-muted-foreground text-xs">
              替换完成后服务会自动重启（supervise 拉起新版本），页面将自动刷新。
            </p>
          </div>
        )}

        {stage === 'restarting' && (
          <div className="rounded-lg border p-3 text-center text-sm">
            服务重启中，<span className="font-mono font-semibold">{countdown}</span> 秒后自动刷新页面…
          </div>
        )}

        {stage === 'error' && (
          <div className="rounded-lg border border-destructive/30 p-3 text-sm text-destructive">
            更新失败：{state?.error}
            <div className="text-muted-foreground mt-1 text-xs">当前进程仍按旧版本运行，可重试或手动部署。</div>
          </div>
        )}

        {stage === 'done' && (
          <div className="flex items-center gap-2 text-sm">
            <Tag color="success">更新完成</Tag>
            已切换到 {state?.target_version}
          </div>
        )}

        {!isAdmin && info?.has_update && (
          <p className="text-muted-foreground text-xs">仅管理员可执行更新，请联系管理员。</p>
        )}
      </div>
    </Modal>
  )
}

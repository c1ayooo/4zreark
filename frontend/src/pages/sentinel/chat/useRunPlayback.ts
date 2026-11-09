/**
 * run 事件回放引擎（demo）
 *
 * 生产实现时替换为 WebSocket 订阅（§8.0）：
 *   发送 {"type":"run.subscribe","run_id":...,"last_seq":...}，
 *   收到 run.event 按 seq 去重后 push 进 played；
 *   断线重连带 last_seq，服务端从 run_event 表补发。
 * 审批等待逻辑与生产一致：approval.required 挂起 run，用户决策后 resume。
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import type { RunEvent } from './mockRuns'

export type PlaybackStatus = 'idle' | 'running' | 'awaiting-approval' | 'finished'

export function useRunPlayback(events: RunEvent[]) {
  const [played, setPlayed] = useState<RunEvent[]>([])
  const [playing, setPlaying] = useState(true)
  const [speed, setSpeed] = useState(2)
  const [status, setStatus] = useState<PlaybackStatus>('idle')
  const [pendingApproval, setPendingApproval] = useState<string | null>(null)

  const idxRef = useRef(0)
  const timerRef = useRef<number | null>(null)

  const reset = useCallback(() => {
    if (timerRef.current) window.clearTimeout(timerRef.current)
    idxRef.current = 0
    setPlayed([])
    setPlaying(true)
    setStatus('running')
    setPendingApproval(null)
  }, [])

  // 场景切换 → 重置回放
  useEffect(() => {
    reset()
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current)
    }
  }, [events, reset])

  // 推进：每次 played 变化后调度下一个事件
  useEffect(() => {
    if (!playing || pendingApproval) return
    if (idxRef.current >= events.length) {
      setStatus('finished')
      return
    }
    const next = events[idxRef.current]
    timerRef.current = window.setTimeout(
      () => {
        setPlayed((prev) => [...prev, next])
        idxRef.current += 1
        if (next.type === 'approval.required') {
          setPendingApproval(String(next.payload.call_id))
          setStatus('awaiting-approval')
        }
      },
      Math.max(80, next.delay / speed),
    )
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current)
    }
  }, [played.length, playing, speed, pendingApproval, events])

  // 审批决策：合成 approval.resolved 事件并恢复播放
  const resolveApproval = useCallback(
    (decision: 'approved' | 'rejected') => {
      if (!pendingApproval) return
      const resolved: RunEvent = {
        seq: 0,
        type: 'approval.resolved',
        payload: { call_id: pendingApproval, decision },
        delay: 0,
      }
      setPlayed((prev) => [...prev, resolved])
      setPendingApproval(null)
      setStatus('running')
      setPlaying(true)
    },
    [pendingApproval],
  )

  const toggle = useCallback(() => setPlaying((p) => !p), [])
  const replay = useCallback(() => reset(), [reset])
  const changeSpeed = useCallback((s: number) => setSpeed(s), [])

  return {
    played,
    playing,
    speed,
    status,
    pendingApproval,
    resolveApproval,
    toggle,
    replay,
    changeSpeed,
  }
}

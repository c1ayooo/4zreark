import type { Task } from '@/api/tasks'

// 任务域共享元数据:状态/扫描类型的中文标签与次要 Tag 类名。
// 此前在 TasksPage/TaskDetailPage/ProjectDetailPage 各写一份,现收敛于此。

export const TAG_SECONDARY = 'border-transparent bg-secondary text-secondary-foreground'

export const TASK_STATUS_LABELS: Record<string, string> = {
  pending: '等待中',
  running: '运行中',
  paused: '已暂停',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

export const getStatusLabel = (status: string) => TASK_STATUS_LABELS[status] || status

export const scanTypeLabels: Record<string, string> = {
  subdomain: '子域名枚举',
  takeover: '子域名接管',
  port_scan: '端口扫描',
  fingerprint: '指纹识别',
  crawler: 'Web 爬虫',
  dir_scan: '目录扫描',
  sensitive: '敏感信息',
  vuln_scan: '漏洞扫描',
  service_detect: '服务识别',
  exposure_scan: '暴露面探测',
  clue_hunt: '存量线索',
}

export type TaskMetaLike = Pick<Task, 'type' | 'status' | 'projectId' | 'nodeId' | 'createdAt' | 'targets'> & {
  config: Task['config']
}

export function taskConfigSummary(task: TaskMetaLike): { label: string; value: string }[] {
  return [
    { label: '任务类型', value: task.type },
    { label: '归属项目', value: `#${task.projectId ?? 0}` },
    { label: '执行节点', value: task.nodeId || '自动选择' },
    {
      label: '扫描节奏',
      value: task.config.rate_per_sec
        ? `${task.config.rate_per_sec} req/s · 目标间隔 ${task.config.target_delay_ms ?? 0}ms`
        : '默认（未显式限速）',
    },
    { label: '端口模式', value: task.config.port_scan_mode || 'quick' },
    { label: '超时 / 并发', value: `${task.config.timeout ?? '默认'}s / ${task.config.concurrent ?? '默认'}` },
  ]
}

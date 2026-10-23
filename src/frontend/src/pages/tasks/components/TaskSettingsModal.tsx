import { Modal, Tag } from 'antd'
import type { Task } from '@/api/tasks'
import { cn, formatDate } from '@/lib/utils'
import { DetailBlock } from './DetailBits'
import { getStatusLabel, scanTypeLabels, TAG_SECONDARY, taskConfigSummary } from '../taskMeta'

// 任务设置弹窗:任务对象的只读档案(类型/节奏/目标/字典/扫描类型/原始配置)。
export default function TaskSettingsModal({
  task,
  open,
  onClose,
}: {
  task: Task
  open: boolean
  onClose: () => void
}) {
  return (
    <Modal open={open} onCancel={onClose} title="任务设置" width={672} footer={null}>
      <div className="space-y-3 py-2 text-sm">
        <div className="grid gap-3 sm:grid-cols-2">
          {taskConfigSummary(task).map(({ label, value }) => (
            <DetailBlock key={label} label={label} value={value} />
          ))}
          <DetailBlock label="当前状态" value={getStatusLabel(task.status)} />
          <DetailBlock label="创建时间" value={formatDate(task.createdAt)} />
        </div>

        <div>
          <div className="text-muted-foreground text-xs">扫描类型</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {(task.config.scanTypes || []).length === 0 ? (
              <span className="text-muted-foreground text-xs">未显式配置</span>
            ) : (
              (task.config.scanTypes || []).map((t) => (
                <Tag key={t} className={cn(TAG_SECONDARY, 'text-xs')}>
                  {scanTypeLabels[t] || t}
                </Tag>
              ))
            )}
          </div>
        </div>

        <div>
          <div className="text-muted-foreground text-xs">扫描目标</div>
          <div className="mt-1 flex flex-wrap gap-1">
            {task.targets.map((t) => (
              <Tag key={t} className="font-mono text-xs">
                {t}
              </Tag>
            ))}
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <DetailBlock
            label="子域字典"
            value={
              task.config.subdomain_dict_id
                ? `${task.config.subdomain_dict_id} · ${task.config.subdomain_wordlist?.length ?? 0} 条`
                : '内置词表'
            }
          />
          <DetailBlock
            label="目录字典"
            value={
              task.config.dir_dict_id
                ? `${task.config.dir_dict_id} · ${task.config.dir_wordlist?.length ?? 0} 条`
                : 'spray 默认字典'
            }
          />
        </div>

        <details className="rounded-md border p-3">
          <summary className="text-muted-foreground cursor-pointer text-xs">原始配置 JSON</summary>
          <pre className="bg-muted/50 mt-2 max-h-64 overflow-auto rounded p-2 font-mono text-xs">
            {JSON.stringify(task.config, null, 2)}
          </pre>
        </details>
      </div>
    </Modal>
  )
}

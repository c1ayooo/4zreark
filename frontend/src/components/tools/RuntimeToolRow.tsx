import { Button, Tag } from 'antd'
import { Download, RefreshCw } from 'lucide-react'

// RuntimeToolRow 与 toolruntime 的 ToolRow 同款视觉：nuclei（独立运行时）
// 与自带浏览器（rod 托管）用这行渲染进工具列表，不再是样式各异的摘要行。
// 数据形状由调用方适配（各自状态源 → 这里的纯展示 props）。
export interface RuntimeToolRowProps {
  name: string
  description?: string
  installed: boolean
  version?: string
  detail?: string
  updateAvailable?: boolean
  updateBusy?: boolean
  updateLabel?: string
  onUpdate?: () => void
  note?: string
}

export default function RuntimeToolRow({
  name,
  description,
  installed,
  version,
  detail,
  updateAvailable,
  updateBusy,
  updateLabel,
  onUpdate,
  note,
}: RuntimeToolRowProps) {
  const badge = !installed ? (
    <Tag>未安装</Tag>
  ) : updateAvailable ? (
    <Tag className="border-transparent bg-amber-600 text-white">有新版本</Tag>
  ) : (
    <Tag className="border-transparent bg-emerald-600 text-white">正常</Tag>
  )
  return (
    <div className="grid gap-2 rounded-md border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{name}</span>
        {badge}
        {description && <span className="text-xs text-muted-foreground">{description}</span>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>
          已装 <span className="text-foreground">{installed ? version || '已安装' : '—'}</span>
        </span>
        {detail && <span>{detail}</span>}
      </div>
      {onUpdate && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="small"
            icon={<Download className="h-3 w-3" />}
            loading={updateBusy}
            onClick={onUpdate}
          >
            {updateLabel || '安装/更新'}
          </Button>
          {installed && (
            <Button size="small" icon={<RefreshCw className="h-3 w-3" />} onClick={onUpdate}>
              检查
            </Button>
          )}
        </div>
      )}
      {note && <div className="text-xs text-amber-600">{note}</div>}
    </div>
  )
}

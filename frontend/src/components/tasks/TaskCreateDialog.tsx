import { Modal } from 'antd'
import TaskCreateForm from '@/components/tasks/TaskCreateForm'

interface TaskCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

// 创建任务对话框：薄 Modal 外壳，表单体在共享的 TaskCreateForm（与创建页面同一份实现）
export default function TaskCreateDialog({ open, onOpenChange }: TaskCreateDialogProps) {
  return (
    <Modal
      open={open}
      onCancel={() => onOpenChange(false)}
      width={576}
      title={<span className="text-base font-semibold">创建扫描任务</span>}
      footer={null}
    >
      <TaskCreateForm
        variant="dialog"
        queriesEnabled={open}
        onCancel={() => onOpenChange(false)}
        onCreated={() => onOpenChange(false)}
      />
    </Modal>
  )
}

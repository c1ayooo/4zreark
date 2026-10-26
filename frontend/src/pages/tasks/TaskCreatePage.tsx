import { useNavigate, useSearchParams } from 'react-router-dom'
import TaskCreateForm from '@/components/tasks/TaskCreateForm'

// 创建任务页面：全页外壳，表单体在共享的 TaskCreateForm（与 TaskCreateDialog 同一份实现）
export default function TaskCreatePage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  // 支持从项目详情带 project_id 预选归属项目
  const initialProjectId = Number(searchParams.get('project_id')) || undefined

  return (
    <div className="mx-auto w-full max-w-2xl px-4 py-8">
      <h1 className="text-2xl font-semibold">创建扫描任务</h1>
      <p className="mt-1 text-sm text-muted-foreground">
        填写目标与扫描模块，创建后任务进入队列调度执行；创建成功自动返回任务列表。
      </p>
      <div className="mt-6">
        <TaskCreateForm
          variant="page"
          initialProjectId={initialProjectId}
          onCreated={() => navigate('/tasks')}
          onCancel={() => navigate('/tasks')}
        />
      </div>
    </div>
  )
}

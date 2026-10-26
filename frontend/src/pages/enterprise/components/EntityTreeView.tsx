import { useMemo } from 'react'
import { Tree, Tag } from 'antd'
import { DataNode } from 'antd/es/tree'

import {
  entityTypeLabel,
  type EnterpriseEntity,
  type EnterpriseJob,
} from '@/api/enterprise'
import { statusTagClass } from '@/components/ui/StatusTag'

// 深度采集（BFS）落库的实体股权树：按任务分组，任务内用
// parent_ext_id → ext_id 挂接（跨任务 ext_id 体系不互通，不能全局建树）。
// 手工/单次采集的实体（无 job_id）归入「独立线索」平铺组。
export default function EntityTreeView({ entities, jobs, total, loading }: {
  entities: EnterpriseEntity[]
  jobs: EnterpriseJob[]
  total: number
  loading: boolean
}) {
  const grouped = useMemo(() => {
    const byJob = new Map<string, EnterpriseEntity[]>()
    const loose: EnterpriseEntity[] = []
    for (const e of entities) {
      if (e.job_id) {
        const arr = byJob.get(e.job_id)
        if (arr) arr.push(e)
        else byJob.set(e.job_id, [e])
      } else {
        loose.push(e)
      }
    }
    return { byJob, loose }
  }, [entities])

  // 任务内建树：ext_id → 子节点；parent 不在本任务里（跨任务合并/翻页截断）
  // 的实体提到顶层，类型徽标仍保留，不丢数据。
  const buildForest = (list: EnterpriseEntity[]): DataNode[] => {
    const extIds = new Set(list.map((e) => e.ext_id).filter(Boolean))
    const childrenOf = new Map<string, EnterpriseEntity[]>()
    for (const e of list) {
      if (!e.parent_ext_id) continue
      const arr = childrenOf.get(e.parent_ext_id)
      if (arr) arr.push(e)
      else childrenOf.set(e.parent_ext_id, [e])
    }
    const toNode = (e: EnterpriseEntity): DataNode => ({
      key: `ent-${e.id}`,
      title: (
        <span className="flex items-center gap-2">
          <span className="text-sm font-medium">{e.name}</span>
          <Tag className={statusTagClass(e.entity_type === 'root' ? 'default' : 'outline')}>
            {entityTypeLabel[e.entity_type] ?? e.entity_type}
          </Tag>
          {(e.domains?.length ?? 0) > 0 && (
            <span className="text-xs text-muted-foreground">域名 {e.domains.length}</span>
          )}
          {e.legal_person && (
            <span className="text-xs text-muted-foreground">法人 {e.legal_person}</span>
          )}
        </span>
      ),
      children: (childrenOf.get(e.ext_id) ?? []).map(toNode),
    })
    // 根 = 无父链，或父企业不在本任务集合里的孤儿（提升到顶层）
    const roots = list.filter((e) => !e.parent_ext_id || !extIds.has(e.parent_ext_id))
    return roots.map(toNode)
  }

  const jobSections: DataNode[] = []
  for (const [jobId, list] of grouped.byJob) {
    const job = jobs.find((j) => j.id === jobId)
    jobSections.push({
      key: `job-${jobId}`,
      title: (
        <span className="flex items-center gap-2">
          <span className="text-sm font-medium">
            {job ? `${job.keyword || jobId.slice(-6)}（${job.provider}）` : `任务 ${jobId.slice(-6)}`}
          </span>
          <span className="text-xs text-muted-foreground">
            {list.length} 家企业{job ? ` · 深度 ${job.depth}` : ''}
          </span>
        </span>
      ),
      children: buildForest(list),
    })
  }

  const looseSection: DataNode[] =
    grouped.loose.length > 0
      ? [
          {
            key: 'loose',
            title: (
              <span className="text-sm font-medium text-muted-foreground">
                独立线索（手工/单次采集，{grouped.loose.length} 条）
              </span>
            ),
            children: buildForest(grouped.loose),
          },
        ]
      : []

  return (
    <div className={loading ? 'animate-pulse opacity-60' : ''}>
      <p className="text-muted-foreground mb-2 text-xs">
        按「深度采集任务」分组的股权树：根企业 → 分支/投资逐层展开；
        {total > entities.length && ` 当前列表共 ${total} 条，树形视图一次最多装载 500 条，`}
        跨平台对同名企业的合并会导致部分节点的父链失效，这些节点会提升到所在任务顶层。
      </p>
      {jobSections.length + looseSection.length === 0 ? (
        <div className="text-muted-foreground py-10 text-center text-sm">
          没有可展示的企业（深度采集完成后这里会出现任务股权树）
        </div>
      ) : (
        <Tree
          treeData={[...jobSections, ...looseSection]}
          defaultExpandAll
          defaultExpandParent
          selectable={false}
          showLine
          blockNode
        />
      )}
    </div>
  )
}

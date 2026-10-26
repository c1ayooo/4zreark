import { Table } from 'antd'
import type { ColumnsType } from 'antd/es/table'

export { TAG_SECONDARY } from '../../taskMeta'

// 结果表通用的「序号」列：跨页连续编号（第 N 页第 M 行 = (N-1)*size+M+1）。
export const indexColumn = (page: number, pageSize: number) => ({
  title: '序号',
  key: 'index',
  width: 64,
  className: 'text-muted-foreground',
  render: (_: unknown, __: unknown, index: number) => (page - 1) * pageSize + index + 1,
})

// shadcn Badge 变体 → antd Tag 的等价 className 映射（保持原视觉语义）
export const TAG_PRIMARY = 'border-transparent bg-primary text-primary-foreground'
export const TAG_DESTRUCTIVE = 'border-transparent bg-destructive text-destructive-foreground'

// 10 个结果表共享的页面状态，由 TaskDetailPage 组装传入；表格只读字段，回调写回页面状态
export interface ResultsTableCtx {
  results: Record<string, unknown>[]
  total: number
  page: number
  pageSize: number
  loading: boolean
  selectedRows: string[]
  onSelectedRowsChange: (rows: string[]) => void
  onPageChange: (page: number, pageSize: number) => void
  onViewVuln: (vuln: Record<string, unknown>) => void
}

// antd Table 公共包装：行选择/服务端分页/加载文案在各结果表间保持一致
export function ResultTable({
  ctx,
  rowKey,
  columns,
  scrollX,
  emptyText = '暂无数据',
  rowClassName,
}: {
  ctx: ResultsTableCtx
  rowKey: string
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  columns: ColumnsType<any>
  scrollX: number
  emptyText?: string
  rowClassName?: (record: Record<string, unknown>) => string
}) {
  return (
    <Table
      rowKey={rowKey}
      columns={columns}
      dataSource={ctx.results}
      rowSelection={{
        selectedRowKeys: ctx.selectedRows,
        onChange: (keys: React.Key[]) => ctx.onSelectedRowsChange(keys.map(String)),
        columnWidth: 48,
      }}
      pagination={{
        current: ctx.page,
        pageSize: ctx.pageSize,
        total: ctx.total,
        showQuickJumper: true,
        showSizeChanger: true,
        showTotal: (t: number) => `共 ${t} 条结果`,
        onChange: ctx.onPageChange,
      }}
      locale={{ emptyText: ctx.loading ? '加载中...' : emptyText }}
      rowClassName={rowClassName}
      sticky
      scroll={{ x: scrollX }}
    />
  )
}

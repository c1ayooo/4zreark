import { useQuery } from '@tanstack/react-query'
import { Button, Modal, Table } from 'antd'
import type { TableProps } from 'antd'

import { icpApi, type ICPFiling } from '@/api/icp'

// 官方备案查询结果；icpId 非空时打开并拉取详情
export default function IcpResultModal({ icpId, onClose }: {
  icpId: string | null
  onClose: () => void
}) {
  const icpDetail = useQuery({
    queryKey: ['icp-detail', icpId],
    queryFn: () => icpApi.get(icpId as string, 500),
    enabled: icpId !== null,
  })

  const filingColumns: TableProps<ICPFiling>['columns'] = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (_, f) => <span className="font-mono text-xs">{f.domain || '—'}</span>,
    },
    {
      title: '服务备案号',
      dataIndex: 'service_licence',
      key: 'service_licence',
      width: 170,
      render: (_, f) => <span className="font-mono text-xs">{f.service_licence || '—'}</span>,
    },
    {
      title: '主体备案号',
      dataIndex: 'main_licence',
      key: 'main_licence',
      width: 170,
      render: (_, f) => <span className="font-mono text-xs">{f.main_licence || '—'}</span>,
    },
    {
      title: '主办单位',
      dataIndex: 'unit_name',
      key: 'unit_name',
      width: 220,
      render: (_, f) => <span className="text-xs">{f.unit_name || '—'}</span>,
    },
    {
      title: '性质',
      dataIndex: 'nature_name',
      key: 'nature_name',
      width: 90,
      render: (_, f) => <span className="text-xs">{f.nature_name || '—'}</span>,
    },
    {
      title: '更新时间',
      dataIndex: 'update_record_time',
      key: 'update_record_time',
      width: 120,
      render: (_, f) => (
        <span className="text-xs text-muted-foreground">{f.update_record_time || '—'}</span>
      ),
    },
  ]

  return (
    <Modal
      open={icpId !== null}
      onCancel={onClose}
      width={1024}
      title={`官方备案结果 · ${icpDetail.data?.data?.query?.query ?? icpId}`}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>关闭</Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        共 {icpDetail.data?.data?.query?.total ?? 0} 条，本次抓取{' '}
        {icpDetail.data?.data?.query?.fetched ?? 0} 条（单次最多 20 页）
      </p>
      <div className="max-h-[60vh] overflow-auto rounded-md border">
        <Table<ICPFiling>
          columns={filingColumns}
          dataSource={icpDetail.data?.data?.filings ?? []}
          rowKey="id"
          loading={icpDetail.isLoading}
          pagination={false}
          locale={{ emptyText: '没有备案记录' }}
        />
      </div>
    </Modal>
  )
}

import { useQuery } from '@tanstack/react-query'
import { Button, Modal, Table } from 'antd'
import type { TableProps } from 'antd'

import { enterpriseApi, type AlignedDigitalAsset, type EnterpriseEntity } from '@/api/enterprise'

// APP 名单归属对齐；entity 非空时打开并拉取对齐名单
export default function AlignedAssetsModal({ entity, onClose }: {
  entity: EnterpriseEntity | null
  onClose: () => void
}) {
  const alignedQuery = useQuery({
    queryKey: ['enterprise-aligned', entity?.id],
    queryFn: () => enterpriseApi.alignedAssets(entity!.id),
    enabled: entity !== null,
  })

  const alignedColumns: TableProps<AlignedDigitalAsset>['columns'] = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (_, a) => <span className="text-sm">{a.name}</span>,
    },
    {
      title: '类型',
      dataIndex: 'kind',
      key: 'kind',
      width: 100,
      render: (_, a) => <span className="text-xs">{a.kind}</span>,
    },
    {
      title: '平台',
      dataIndex: 'platform',
      key: 'platform',
      width: 120,
      render: (_, a) => <span className="text-xs">{a.platform || '—'}</span>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (_, a) => <span className="text-xs">{a.status}</span>,
    },
  ]

  return (
    <Modal
      open={entity !== null}
      onCancel={onClose}
      title={`APP 名单归属对齐 · ${entity?.name}`}
      width={672}
      footer={
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>关闭</Button>
        </div>
      }
    >
      <p className="text-muted-foreground mb-4 text-sm">
        同项目内 `company` 与企业名完全一致的名单；不同主体同名需人工核对。
      </p>
      <div className="rounded-md border">
        <Table<AlignedDigitalAsset>
          columns={alignedColumns}
          dataSource={alignedQuery.data?.data?.items ?? []}
          rowKey="id"
          loading={alignedQuery.isLoading}
          pagination={false}
          locale={{ emptyText: '没有对齐的 APP 名单' }}
        />
      </div>
    </Modal>
  )
}

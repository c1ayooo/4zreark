import { Modal, Tag } from 'antd'
import { cn, getSeverityColor } from '@/lib/utils'
import { DetailBlock, Section } from './DetailBits'

import { safeExternalURL } from '@/lib/safeUrl'
// 漏洞详情弹窗:fields 来自 scan_results 的自由 json,按存在性渲染。
export default function VulnDetailModal({
  vuln,
  onClose,
}: {
  vuln: Record<string, unknown> | null
  onClose: () => void
}) {
  const selectedVuln = vuln
  return (
    <Modal
        open={selectedVuln !== null}
        onCancel={onClose}
        title={(selectedVuln?.name as string) || '漏洞详情'}
        width={672}
        footer={null}
      >
        {selectedVuln && (
          <div className="max-h-[75vh] space-y-4 overflow-y-auto text-sm">
            <div className="flex flex-wrap items-center gap-2">
              <Tag className={cn(getSeverityColor(String(selectedVuln.severity || '')), 'text-xs')}>
                {String(selectedVuln.severity || 'unknown')}
              </Tag>
              {(selectedVuln.vuln_id as string) && (
                <Tag className="font-mono">
                  {selectedVuln.vuln_id as string}
                </Tag>
              )}
              <span className="text-muted-foreground">
                {(selectedVuln.source as string) || 'nuclei'}
              </span>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <DetailBlock label="目标" value={(selectedVuln.target as string) || '-'} />
              <DetailBlock label="匹配位置" value={(selectedVuln.matched_at as string) || '-'} />
            </div>

            {(selectedVuln.description as string) && (
              <Section title="漏洞描述">
                <p className="text-muted-foreground whitespace-pre-wrap">
                  {selectedVuln.description as string}
                </p>
              </Section>
            )}

            {(selectedVuln.evidence as string) && (
              <Section title="证据">
                <pre className="bg-muted/50 rounded-md border p-3 font-mono text-xs whitespace-pre-wrap break-all">
                  {selectedVuln.evidence as string}
                </pre>
              </Section>
            )}

            {(selectedVuln.remediation as string) && (
              <Section title="修复建议">
                <p className="text-muted-foreground whitespace-pre-wrap">
                  {selectedVuln.remediation as string}
                </p>
              </Section>
            )}

            {Array.isArray(selectedVuln.reference) && (selectedVuln.reference as string[]).length > 0 && (
              <Section title="参考链接">
                <ul className="space-y-1">
                  {(selectedVuln.reference as string[]).map((r) => (
                    <li key={r}>
                      <a
                        href={safeExternalURL(r) ?? undefined}
                        target="_blank"
                        rel="noreferrer"
                        className="text-primary break-all hover:underline"
                      >
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              </Section>
            )}

            <Section title="原始数据">
              <pre className="bg-muted/50 max-h-56 overflow-auto rounded-md border p-3 font-mono text-xs whitespace-pre-wrap break-all">
                {JSON.stringify(selectedVuln, null, 2)}
              </pre>
            </Section>
          </div>
        )}
      </Modal>
  )
}

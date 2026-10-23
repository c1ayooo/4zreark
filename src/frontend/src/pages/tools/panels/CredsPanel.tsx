import { useState } from 'react'
import { Button, Card, Input, Select } from 'antd'
import { useToast } from '@/components/ui/use-toast'
import { toolsApi } from '@/api/tools'
import { ResultBlock } from './ResultBlock'

export default function CredsPanel() {
  const { toast } = useToast()
  const [kind, setKind] = useState('db')
  const [projectID, setProjectID] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [dbType, setDbType] = useState('postgres')
  const [database, setDatabase] = useState('')
  const [provider, setProvider] = useState('aliyun')
  const [accessKey, setAccessKey] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [result, setResult] = useState<unknown>(null)
  const [busy, setBusy] = useState(false)

  const submit = async () => {
    setBusy(true)
    setResult(null)
    try {
      if (kind === 'cloud') {
        setResult(await toolsApi.verifyCloud({ provider, access_key_id: accessKey, secret_key: secretKey }))
      } else if (kind === 'db') {
        setResult(await toolsApi.verifyDB({
          project_id: Number(projectID), type: dbType, host, port: Number(port) || 0,
          username, password, database,
        }))
      } else {
        setResult(await toolsApi.verifySSH({
          project_id: Number(projectID), host, port: Number(port) || 0, username, password,
        }))
      }
    } catch (e) {
      const msg = (e as { response?: { data?: { message?: string } } })?.response?.data?.message || (e as Error)?.message || '验证失败'
      toast({ title: msg, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="凭据只读验证">
      <div className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          <div>
            <div className="mb-1 text-xs text-muted-foreground">类型</div>
            <Select
              value={kind}
              onChange={(v) => setKind(v)}
              options={[
                { value: 'db', label: '数据库' },
                { value: 'ssh', label: 'SSH' },
                { value: 'cloud', label: '云 AK/SK' },
              ]}
            />
          </div>
          {kind === 'cloud' ? (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">云厂商</div>
              <Select
                value={provider}
                onChange={(v) => setProvider(v)}
                options={[
                  { value: 'aliyun', label: '阿里云' },
                  { value: 'tencent', label: '腾讯云' },
                  { value: 'aws', label: 'AWS' },
                  { value: 'huawei', label: '华为云' },
                  { value: 'volc', label: '火山引擎' },
                ]}
              />
            </div>
          ) : (
            <div>
              <div className="mb-1 text-xs text-muted-foreground">项目 ID（scope 依据）</div>
              <Input value={projectID} onChange={(e) => setProjectID(e.target.value)} placeholder="如 1" />
            </div>
          )}
        </div>

        {kind === 'cloud' ? (
          <div className="grid gap-3 md:grid-cols-2">
            <Input placeholder="AccessKeyId" value={accessKey} onChange={(e) => setAccessKey(e.target.value)} />
            <Input placeholder="SecretKey" type="password" value={secretKey} onChange={(e) => setSecretKey(e.target.value)} />
          </div>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            {kind === 'db' && (
              <Select
                value={dbType}
                onChange={(v) => setDbType(v)}
                options={[
                  { value: 'postgres', label: 'PostgreSQL' },
                  { value: 'redis', label: 'Redis' },
                ]}
              />
            )}
            <Input placeholder="主机" value={host} onChange={(e) => setHost(e.target.value)} />
            <Input placeholder="端口（可空）" value={port} onChange={(e) => setPort(e.target.value)} />
            <Input placeholder="用户名" value={username} onChange={(e) => setUsername(e.target.value)} />
            <Input placeholder="密码 / 私钥" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            {kind === 'db' && <Input placeholder="库名（可空）" value={database} onChange={(e) => setDatabase(e.target.value)} />}
          </div>
        )}

        <Button type="primary" onClick={submit} loading={busy}>验证</Button>
        <ResultBlock value={result} />
      </div>
    </Card>
  )
}

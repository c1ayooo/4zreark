import { Tabs } from 'antd'
import { Radio, KeyRound, GitCompare, Code2, Quote, Boxes, ScrollText, Github, Building2, PackageSearch, Terminal, RefreshCw } from 'lucide-react'
import ToolUpdatePanel from '@/pages/tools/ToolUpdatePanel'
import OOBPanel from '@/pages/tools/panels/OOBPanel'
import CredsPanel from '@/pages/tools/panels/CredsPanel'
import DiffPanel from '@/pages/tools/panels/DiffPanel'
import WebReconPanel from '@/pages/tools/panels/WebReconPanel'
import QuotePanel from '@/pages/tools/panels/QuotePanel'
import ComponentPanel from '@/pages/tools/panels/ComponentPanel'
import PlaybookPanel from '@/pages/tools/panels/PlaybookPanel'
import GithubLeakPanel from '@/pages/tools/panels/GithubLeakPanel'
import EnterprisePanel from '@/pages/tools/panels/EnterprisePanel'
import ExtractPanel from '@/pages/tools/panels/ExtractPanel'
import RuntimePanel from '@/pages/tools/panels/RuntimePanel'

export default function ToolkitPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold">工具箱</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          手工验证工具。所有会发流量的操作都要求项目授权（项目种子），凭据验证只做只读探测。
        </p>
      </div>

      <Tabs
        defaultActiveKey="oob"
        items={[
          { key: 'oob', label: <span className="flex items-center gap-2"><Radio className="h-4 w-4" />带外验证</span>, children: <OOBPanel /> },
          { key: 'creds', label: <span className="flex items-center gap-2"><KeyRound className="h-4 w-4" />凭据验证</span>, children: <CredsPanel /> },
          { key: 'diff', label: <span className="flex items-center gap-2"><GitCompare className="h-4 w-4" />差分组</span>, children: <DiffPanel /> },
          { key: 'web', label: <span className="flex items-center gap-2"><Code2 className="h-4 w-4" />JS 侦察</span>, children: <WebReconPanel /> },
          { key: 'quote', label: <span className="flex items-center gap-2"><Quote className="h-4 w-4" />引文校验</span>, children: <QuotePanel /> },
          { key: 'component', label: <span className="flex items-center gap-2"><Boxes className="h-4 w-4" />组件 CVE</span>, children: <ComponentPanel /> },
          { key: 'playbook', label: <span className="flex items-center gap-2"><ScrollText className="h-4 w-4" />验证剧本</span>, children: <PlaybookPanel /> },
          { key: 'ghleak', label: <span className="flex items-center gap-2"><Github className="h-4 w-4" />GitHub 泄露</span>, children: <GithubLeakPanel /> },
          { key: 'enterprise', label: <span className="flex items-center gap-2"><Building2 className="h-4 w-4" />企业检索</span>, children: <EnterprisePanel /> },
          { key: 'extract', label: <span className="flex items-center gap-2"><PackageSearch className="h-4 w-4" />报文提取</span>, children: <ExtractPanel /> },
          { key: 'updates', label: <span className="flex items-center gap-2"><RefreshCw className="h-4 w-4" />更新策略</span>, children: <ToolUpdatePanel /> },
          { key: 'runtime', label: <span className="flex items-center gap-2"><Terminal className="h-4 w-4" />运行时</span>, children: <RuntimePanel /> },
        ]}
      />
    </div>
  )
}

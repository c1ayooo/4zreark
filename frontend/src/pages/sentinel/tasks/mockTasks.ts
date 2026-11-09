/**
 * LLM 自动化分析任务 + 产物（前端演示数据）
 *
 * 一个"任务"= 一次 LLM 参与的自动化作业，四类：
 *   judge  提交判定（diff → 是否安全修复）
 *   repro  差分复现（生成 POC → 双环境验证）
 *   audit  代码审计（上传包 → semgrep + LLM 审阅）
 *   assess 资产风险评估（§10 资采 AI 化）
 *
 * 一个"产物"= 任务的可交付物，三类：poc（差分 PoC 源码）/ nuclei（模板 YAML）/ report（证据包或报告）
 * 产物状态机：draft → pending_review → verified / rejected → deprecated
 * 铁律：非 verified 产物不可下载、不可下发扫描，只能预览。
 */
import type { RunEvent, RunEventType } from '../chat/mockRuns'

export type TaskKind = 'judge' | 'repro' | 'audit' | 'assess'
export type TaskStatus = 'queued' | 'running' | 'ok' | 'failed' | 'cancelled'
export type StepStatus = 'pending' | 'running' | 'ok' | 'failed' | 'skipped'
export type ArtifactKind = 'poc' | 'nuclei' | 'report'
export type ArtifactStatus = 'draft' | 'pending_review' | 'verified' | 'rejected' | 'deprecated'

export interface ArtifactVerification {
  vuln: string
  fix: string
  runs: number
  oracle: string
  verdict: 'differential-ok' | 'failed'
  reachedPocPoint: boolean
}

export interface Artifact {
  id: string
  kind: ArtifactKind
  title: string
  lang: string
  status: ArtifactStatus
  /** ai = LLM 起草；human = 人工上传/手写 */
  source: 'ai' | 'human'
  confidence?: number
  lines: number
  bytes: number
  sha256: string
  content: string
  /** nuclei 模板的一键复跑命令 */
  command?: string
  verification?: ArtifactVerification
}

export interface Step {
  key: string
  label: string
  status: StepStatus
  duration?: string
  /** LLM 节点：模型、token、置信度、结构化决策 */
  model?: string
  tokens?: number
  confidence?: number
  note?: string
  output?: Record<string, unknown>
}

export interface SentinelTask {
  id: string
  kind: TaskKind
  title: string
  target: string
  status: TaskStatus
  queue: 'collect' | 'judge' | 'repro' | 'audit' | 'ai'
  stage: string
  progress: number
  model?: string
  tokens?: { in: number; out: number }
  cost?: number
  duration: string
  retries: number
  createdAt: string
  failReason?: { code: string; message: string; advice: string }
  steps: Step[]
  artifacts: Artifact[]
  events: RunEvent[]
}

export const KIND_META: Record<TaskKind, { label: string; cls: string }> = {
  judge: { label: '提交判定', cls: 'border-sky-200 bg-sky-50 text-sky-700' },
  repro: { label: '差分复现', cls: 'border-violet-200 bg-violet-50 text-violet-700' },
  audit: { label: '代码审计', cls: 'border-teal-200 bg-teal-50 text-teal-700' },
  assess: { label: '资产评估', cls: 'border-amber-200 bg-amber-50 text-amber-700' },
}

export const STATUS_META: Record<TaskStatus, { label: string; cls: string }> = {
  queued: { label: '排队中', cls: 'border-slate-200 bg-slate-50 text-slate-600' },
  running: { label: '运行中', cls: 'border-sky-200 bg-sky-50 text-sky-700' },
  ok: { label: '成功', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700' },
  failed: { label: '失败', cls: 'border-rose-200 bg-rose-50 text-rose-700' },
  cancelled: { label: '已取消', cls: 'border-slate-200 bg-slate-50 text-slate-500' },
}

export const ARTIFACT_STATUS_META: Record<ArtifactStatus, { label: string; cls: string }> = {
  draft: { label: 'AI 草稿', cls: 'border-slate-200 bg-slate-50 text-slate-600' },
  pending_review: { label: '待人工审核', cls: 'border-amber-200 bg-amber-50 text-amber-700' },
  verified: { label: '已验证', cls: 'border-emerald-200 bg-emerald-50 text-emerald-700' },
  rejected: { label: '已否决', cls: 'border-rose-200 bg-rose-50 text-rose-700' },
  deprecated: { label: '已弃用', cls: 'border-slate-200 bg-slate-50 text-slate-500' },
}

export const STEP_DOT: Record<StepStatus, string> = {
  pending: 'border-border bg-background',
  running: 'border-sky-400 bg-sky-100',
  ok: 'border-emerald-400 bg-emerald-100',
  failed: 'border-rose-400 bg-rose-100',
  skipped: 'border-border bg-muted',
}

/* ---------- 造事件（delay 用于前端回放节奏） ---------- */
let seq = 0
function e(type: RunEventType, payload: Record<string, unknown>, delay = 500): RunEvent {
  seq += 1
  return { seq, type, payload, delay }
}

const NUCLEI_TEMPLATE = `id: CVE-2026-41234

info:
  name: CommitPay Invoice XMLDecoder RCE
  author: sentinel-ai
  severity: critical
  description: |
    InvoiceParser 在 1.4.2 及之前版本把请求体直接交给 XMLDecoder，
    未做类型白名单，可导致任意代码执行。
  reference:
    - https://github.com/commitpay/x-invoice/commit/9f2e1c3
  tags: cve,rce,deserialization,java

http:
  - raw:
      - |
        POST /api/invoice/parse HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/xml

        <java><object class="java.beans.XMLDecoder">
          <void method="readObject"><string>__payload__</string></void>
        </object></java>
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "poc_marker_7f3a"
      - type: status
        status:
          - 200
`

const POC_SOURCE = `#!/usr/bin/env python3
# sentinel differential poc - finding #4520
# vuln image: commitpay/x-invoice:1.4.2  fix image: 1.4.3
import sys
import urllib.request

print("__POC_START__")          # oracle 哨兵要求：崩溃前必须出现
body = open("payload.xml", "rb").read()
req = urllib.request.Request(
    "http://127.0.0.1:8080/api/invoice/parse",
    data=body,
    headers={"Content-Type": "application/xml"},
)
try:
    urllib.request.urlopen(req, timeout=10).read()
except Exception as exc:        # 目标崩溃时连接被断开
    print(exc, file=sys.stderr)
print("__POC_SENT__")
`

const REPORT_MD = `# CVE-2026-41234 复现报告

- 仓库：commitpay/x-invoice
- 修复提交：9f2e1c3（XmlDecoderTypeFilter 白名单）
- 影响版本：<= 1.4.2

## 差分结论
| 环境 | 输入 | 结果 |
|---|---|---|
| vuln (1.4.2) | payload.xml | SIGSEGV，ASAN 未启用，core dump 1 份 |
| fix  (1.4.3) | payload.xml | 正常返回 200，无崩溃 |

oracle：3/3 次 vuln 硬崩溃，fix 0/3，\`__POC_START__\` 均出现 → differential-ok

## 修复建议
1. 禁用 XMLDecoder，改用 Jackson XML + 显式类型白名单；
2. 入口层限制请求体大小（<= 64KB）与 Content-Type；
3. 在 CI 中加入该 PoC 作为回归用例（测试环境）。
`

const JUDGE_EVIDENCE = `{
  "verdict": "security_fix",
  "confidence": 0.82,
  "vuln_class": "DESERIALIZATION",
  "evidence": [
    {
      "file": "src/main/java/com/x/invoice/InvoiceParser.java",
      "hunk": "@@ -88,7 +88,12 @@",
      "reason": "新增 XmlDecoderTypeFilter，仅允许 Invoice/Lines 两类，符合修复特征"
    },
    {
      "file": "src/main/java/com/x/invoice/InvoiceParser.java",
      "hunk": "@@ -101,2 +106,9 @@",
      "reason": "readObject 前增加类型校验，阻断 gadget 链入口"
    }
  ],
  "reject_reasons": []
}
`

export const TASKS: SentinelTask[] = [
  {
    id: 'T-1042',
    kind: 'repro',
    title: '复现 9f2e1c3 修复的反序列化漏洞',
    target: 'commitpay/x-invoice@9f2e1c3',
    status: 'ok',
    queue: 'repro',
    stage: 'differential-ok',
    progress: 100,
    model: 'claude-sonnet-4-5',
    tokens: { in: 48200, out: 6100 },
    cost: 2.86,
    duration: '6m12s',
    retries: 1,
    createdAt: '11-09 10:02',
    steps: [
      { key: 'prep', label: 'diff 切分 + 入口识别', status: 'ok', duration: '1.2s', note: '3 个 hunk → 2 个候选入口' },
      {
        key: 'judge', label: '判定：安全修复', status: 'ok', duration: '8.4s', model: 'deepseek-chat', tokens: 3100, confidence: 0.82,
        output: { verdict: 'security_fix', vuln_class: 'DESERIALIZATION', evidence: 'InvoiceParser.java:88 白名单' },
      },
      { key: 'plan', label: '构建探测', status: 'ok', duration: '22s', note: 'maven 3.9 · pom.xml 命中，无网络依赖' },
      { key: 'image', label: '双镜像构建', status: 'ok', duration: '3m40s', note: 'vuln=1.4.2 fix=1.4.3，依赖层复用' },
      {
        key: 'poc', label: 'POC 生成循环', status: 'ok', duration: '1m50s', model: 'claude-sonnet-4-5', tokens: 41200, confidence: 0.88,
        note: '第 2 轮命中硬崩溃，共 2 轮 4 次执行', output: { rounds: 2, execs: 4, crash: 'SIGSEGV' },
      },
      { key: 'oracle', label: 'Oracle 崩溃判定', status: 'ok', duration: '14s', note: 'vuln 3/3 硬崩溃 · fix 0/3', output: { reached_poc_point: true, vuln_crash: 3, fix_crash: 0 } },
      { key: 'verify', label: '四条否决', status: 'ok', duration: '0.2s', note: 'differential-ok' },
    ],
    artifacts: [
      {
        id: 'A-1', kind: 'nuclei', title: 'CVE-2026-41234.yaml', lang: 'yaml', status: 'verified', source: 'ai',
        confidence: 0.88, lines: 32, bytes: 986, sha256: 'c41a9f2e7b13d884', content: NUCLEI_TEMPLATE,
        command: 'nuclei -t CVE-2026-41234.yaml -u https://target.example -severity critical',
        verification: {
          vuln: '1.4.2：matcher 命中 poc_marker_7f3a',
          fix: '1.4.3：200 但无 marker，未命中',
          runs: 3, oracle: '3/3 稳定复现，无 flaky', verdict: 'differential-ok', reachedPocPoint: true,
        },
      },
      {
        id: 'A-2', kind: 'poc', title: 'poc_invoice_rce.py', lang: 'python', status: 'verified', source: 'ai',
        confidence: 0.88, lines: 18, bytes: 624, sha256: '7d3b1e5a2c9f4b70', content: POC_SOURCE,
        verification: {
          vuln: 'vuln 容器：SIGSEGV，崩溃前出现 __POC_START__',
          fix: 'fix 容器：exit 0，正常返回 200',
          runs: 3, oracle: 'ASAN 未启用，core 1 份；3/3 一致', verdict: 'differential-ok', reachedPocPoint: true,
        },
      },
      {
        id: 'A-3', kind: 'report', title: 'repro-report.md', lang: 'markdown', status: 'verified', source: 'ai',
        lines: 20, bytes: 1120, sha256: '19fe2c7d4a81b6d3', content: REPORT_MD,
      },
    ],
    events: [
      e('run.started', { run_id: 2041, conversation_id: 0 }),
      e('thinking.delta', { delta: '判定节点给出 DESERIALIZATION 0.82，修复点在 XMLDecoder 类型白名单，优先构造 XML 入口。' }),
      e('tool.call', { call_id: 'r1', name: 'grep', args: { pattern: 'XMLDecoder|readObject', glob: '*.java' } }),
      e('tool.result', { call_id: 'r1', ok: true, duration_ms: 210, preview: 'InvoiceParser.java:88\nSoapClient.java:238' }),
      e('tool.call', { call_id: 'r2', name: 'run_in_vuln', args: { cmd: 'python3 poc_invoice_rce.py' } }),
      e('tool.result', { call_id: 'r2', ok: true, duration_ms: 1420, preview: '__POC_START__\nSegmentation fault (core dumped)' }),
      e('tool.call', { call_id: 'r3', name: 'run_in_fix', args: { cmd: 'python3 poc_invoice_rce.py' } }),
      e('tool.result', { call_id: 'r3', ok: true, duration_ms: 980, preview: '__POC_START__\n__POC_SENT__\nHTTP 200' }),
      e('message.delta', { role: 'assistant', delta: 'vuln 3/3 硬崩溃、fix 0/3，`__POC_START__` 均出现 → differential-ok，产出 nuclei 模板与 PoC 源码。' }),
      e('run.finished', { status: 'ok', tokens: { in: 48200, out: 6100 } }),
    ],
  },
  {
    id: 'T-1043',
    kind: 'judge',
    title: '判定 openssl a1b2c3d 是否为安全修复',
    target: 'openssl/openssl@a1b2c3d',
    status: 'ok',
    queue: 'judge',
    stage: 'security_fix',
    progress: 100,
    model: 'deepseek-chat',
    tokens: { in: 2840, out: 410 },
    cost: 0.04,
    duration: '11s',
    retries: 0,
    createdAt: '11-09 09:58',
    steps: [
      { key: 'filter', label: '噪音过滤', status: 'ok', duration: '0.1s', note: 'docs/ 与 ci/ 变更已剔除' },
      { key: 'prep', label: 'diff 切分', status: 'ok', duration: '0.4s', note: '2 hunk · 61 行' },
      {
        key: 'judge', label: '判定图', status: 'ok', duration: '9.8s', model: 'deepseek-chat', tokens: 3250, confidence: 0.82,
        output: { verdict: 'security_fix', vuln_class: 'DESERIALIZATION', evidence: 'XmlDecoderTypeFilter 白名单', reject_reasons: [] },
      },
    ],
    artifacts: [
      {
        id: 'A-4', kind: 'report', title: 'verdict-9f2e.json', lang: 'json',
        status: 'pending_review', source: 'ai', confidence: 0.82, lines: 22, bytes: 742,
        sha256: 'bf0e5a71cd9284aa', content: JUDGE_EVIDENCE,
      },
    ],
    events: [
      e('run.started', { run_id: 2040, conversation_id: 0 }),
      e('thinking.delta', { delta: '两个 hunk 都在同一函数内，新增类型白名单，符合 CWE-502 修复特征。' }),
      e('tool.call', { call_id: 'j1', name: 'read_file', args: { path: 'crypto/x509/x509_vfy.c', offset: 88, limit: 40 } }),
      e('tool.result', { call_id: 'j1', ok: true, duration_ms: 120, preview: '@@ -88,7 +88,12 @@ 新增白名单校验' }),
      e('message.delta', { role: 'assistant', delta: '判定：安全修复，置信度 0.82，证据 2 条已写入证据包。' }),
      e('run.finished', { status: 'ok', tokens: { in: 2840, out: 410 } }),
    ],
  },
  {
    id: 'T-1044',
    kind: 'repro',
    title: '复现 PHP 反序列化（POP 链候选）',
    target: 'acme/legacy-cart@77c1ab0',
    status: 'failed',
    queue: 'repro',
    stage: 'crash-before-poc-point',
    progress: 100,
    model: 'claude-sonnet-4-5',
    tokens: { in: 96300, out: 12400 },
    cost: 5.42,
    duration: '12m40s',
    retries: 2,
    createdAt: '11-09 09:31',
    failReason: {
      code: 'crash-before-poc-point',
      message: '容器在装载阶段就退出（缺 mbstring 扩展），__POC_START__ 未出现',
      advice: '按计划 §7.9 规则 2 判定为环境问题，非漏洞：检查 builder 镜像扩展清单后重试；不要压低置信度入库',
    },
    steps: [
      { key: 'prep', label: 'diff 切分 + 入口识别', status: 'ok', duration: '0.8s' },
      { key: 'judge', label: '判定：安全修复', status: 'ok', duration: '7.1s', model: 'deepseek-chat', tokens: 2900, confidence: 0.76 },
      { key: 'plan', label: '构建探测', status: 'ok', duration: '18s', note: 'composer 2.x · 无 composer.lock' },
      { key: 'image', label: '双镜像构建', status: 'ok', duration: '2m10s' },
      {
        key: 'poc', label: 'POC 生成循环', status: 'failed', duration: '9m50s', model: 'claude-sonnet-4-5', tokens: 109000,
        note: '10 轮全部 crash-before-poc-point', output: { rounds: 10, execs: 21, crash: 'Fatal error: Uncaught Error: Call to undefined function mb_strlen()' },
      },
      { key: 'oracle', label: 'Oracle 崩溃判定', status: 'failed', duration: '9s', note: '环境崩溃，不计入通过' },
      { key: 'verify', label: '四条否决', status: 'skipped', note: '前置失败，未进入否决链' },
    ],
    artifacts: [],
    events: [
      e('run.started', { run_id: 2039, conversation_id: 0 }),
      e('thinking.delta', { delta: '入口在 index.php，先确认容器内扩展是否齐全。' }),
      e('tool.call', { call_id: 'f1', name: 'run_in_vuln', args: { cmd: 'php -m' } }),
      e('tool.result', { call_id: 'f1', ok: true, duration_ms: 300, preview: 'PHP Warning:  Module "mbstring" is not loaded' }),
      e('tool.result', { call_id: 'f2', ok: false, duration_ms: 1220, preview: 'PHP Fatal error: Uncaught Error: Call to undefined function mb_strlen()' }),
      e('message.delta', { role: 'assistant', delta: '连续 10 轮均在 __POC_START__ 之前退出，判定环境缺扩展，建议修镜像而不是继续生成 POC。' }),
      e('run.finished', { status: 'error', tokens: { in: 96300, out: 12400 } }),
    ],
  },
  {
    id: 'T-1045',
    kind: 'audit',
    title: '审计 x-invoice-1.4.2.zip（skill：Java 反序列化）',
    target: 'upload/x-invoice-1.4.2.zip',
    status: 'running',
    queue: 'audit',
    stage: 'grep 检索（82/231 文件）',
    progress: 62,
    model: 'claude-sonnet-4-5',
    tokens: { in: 38600, out: 2400 },
    cost: 1.94,
    duration: '2m08s',
    retries: 0,
    createdAt: '11-09 10:06',
    steps: [
      { key: 'extract', label: '归档校验 + 解压', status: 'ok', duration: '2.1s', note: '231 文件 · 无符号链接 / 无路径穿越' },
      { key: 'scan', label: 'semgrep 预筛', status: 'ok', duration: '31s', note: '命中 14 处 sink' },
      { key: 'llm', label: 'LLM 分批审阅', status: 'running', duration: '1m30s', model: 'claude-sonnet-4-5', tokens: 41000, note: '第 6/9 批' },
      { key: 'dedupe', label: '去重 + 定级', status: 'pending' },
    ],
    artifacts: [
      {
        id: 'A-5', kind: 'report', title: 'candidate-4520.md', lang: 'markdown', status: 'draft', source: 'ai',
        confidence: 0.71, lines: 12, bytes: 480, sha256: 'e5a1c07f3b2d9e41',
        content: '# 候选：SoapClient.java:238 反序列化\n\n- sink：`new ObjectInputStream(bais).readObject()`\n- 来源：SOAP 响应体，外部可控\n- 待确认：上游是否有类型白名单（当前看无）\n- 建议：升级为高危，进入复现队列\n',
      },
    ],
    events: [
      e('file.uploaded', { name: 'x-invoice-1.4.2.zip', size: 4128000, kind: 'zip', files: 231 }),
      e('skill.loaded', { skill: 'java-deser-audit', name: 'Java 反序列化审计', version: 'v1.2', checks: 5 }),
      e('run.started', { run_id: 2042, conversation_id: 0 }),
      e('tool.call', { call_id: 'a1', name: 'semgrep', args: { rules: 'java-deser', path: '.' } }),
      e('tool.result', { call_id: 'a1', ok: true, duration_ms: 31000, preview: '14 findings (sink)' }),
    ],
  },
  {
    id: 'T-1046',
    kind: 'assess',
    title: '资产风险评估：example.com（巡航批次）',
    target: 'domain/example.com',
    status: 'queued',
    queue: 'ai',
    stage: '等待 worker（队列深度 7）',
    progress: 0,
    duration: '—',
    retries: 0,
    createdAt: '11-09 10:08',
    steps: [
      { key: 'collect', label: '聚合资产面 + 风险面', status: 'pending' },
      { key: 'llm', label: 'LLM 结构化评估', status: 'pending', model: 'deepseek-chat' },
      { key: 'notify', label: '飞书卡片下发', status: 'pending' },
    ],
    artifacts: [],
    events: [],
  },
]

/** 判定证据（对应 JUDGE_EVIDENCE 落地后的结构化形态），按任务 id 归档 */
export interface EvidenceItem {
  file: string
  hunk: string
  reason: string
}

export const TASK_EVIDENCE: Record<string, EvidenceItem[]> = {
  'T-1042': [
    {
      file: 'src/main/java/com/x/invoice/InvoiceParser.java',
      hunk: '@@ -88,7 +88,12 @@',
      reason: '新增 XmlDecoderTypeFilter，仅允许 Invoice/Lines 两类，符合修复特征',
    },
    {
      file: 'src/main/java/com/x/invoice/InvoiceParser.java',
      hunk: '@@ -101,2 +106,9 @@',
      reason: 'readObject 前增加类型校验，阻断 gadget 链入口',
    },
  ],
  'T-1043': [
    {
      file: 'crypto/x509/x509_vfy.c',
      hunk: '@@ -88,7 +88,12 @@',
      reason: '新增深度上限与类型白名单校验，两处 hunk 位于同一函数',
    },
    {
      file: 'crypto/x509/x509_vfy.c',
      hunk: '@@ -121,6 +129,8 @@',
      reason: '错误路径改为 fail-closed，符合 CWE-502 修复模式',
    },
  ],
}

export const QUEUES: { name: string; depth: number; workers: number; busy: number }[] = [
  { name: 'collect', depth: 2, workers: 4, busy: 1 },
  { name: 'judge', depth: 11, workers: 8, busy: 8 },
  { name: 'repro', depth: 3, workers: 1, busy: 1 },
  { name: 'audit', depth: 1, workers: 2, busy: 1 },
  { name: 'ai', depth: 7, workers: 2, busy: 2 },
]

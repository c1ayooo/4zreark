/**
 * CommitSentinel 对话页样例数据（demo 回放用）
 *
 * 事件协议与 docs/CommitSentinel-实现方案.md §8.5 对齐：
 * run.started / thinking.delta / message.delta / tool.call / tool.result /
 * approval.required / approval.resolved / message.done / run.finished / heartbeat
 *
 * delay 为距上一事件的播放间隔（ms），实际播放受速度倍率控制。
 */

export type RunEventType =
  | 'run.started'
  | 'file.uploaded'
  | 'skill.loaded'
  | 'thinking.delta'
  | 'message.delta'
  | 'tool.call'
  | 'tool.result'
  | 'approval.required'
  | 'approval.resolved'
  | 'message.done'
  | 'run.finished'
  | 'heartbeat'

export interface RunEvent {
  seq: number
  type: RunEventType
  payload: Record<string, unknown>
  /** 距上一事件的播放间隔 ms */
  delay: number
}

export interface Scenario {
  id: string
  title: string
  mode: 'commit' | 'audit' | 'chat' | 'asset'
  modeLabel: string
  /** 消息流顶部的用户提问 */
  question: string
  /** 注入的首个系统上下文（"问 agent" 联动） */
  context: { kind: string; label: string; summary: string }
  desc: string
  /** 本次输入携带的附件（上传分析） */
  attachments?: Attachment[]
  /** 本次输入指定的 skill */
  skill?: Skill
  events: RunEvent[]
}

/* ---------- 上传附件 / skill（前端演示模型，生产由 upload 接口与 skill 注册表提供） ---------- */

export interface Attachment {
  name: string
  size: number
  /** zip / java / go / pdf / text */
  kind: string
  /** 归档解析出的文件数，上传接口返回后回填 */
  files?: number
  status?: 'parsing' | 'ready' | 'failed'
}

export interface Skill {
  id: string
  name: string
  version: string
  desc: string
  /** 该 skill 注入的检查项数量 */
  checks: number
}

export const SKILLS: Skill[] = [
  { id: 'java-deser-audit', name: 'Java 反序列化审计', version: 'v1.2', desc: 'readObject / ObjectInputStream / XMLDecoder / gadget 链检索顺序', checks: 5 },
  { id: 'php-unserialize', name: 'PHP 反序列化审计', version: 'v1.0', desc: '__wakeup / __destruct 魔术方法可达性 + POP 链起点', checks: 4 },
  { id: 'binary-oob', name: '二进制越界定位', version: 'v2.0', desc: '结合 ASAN 输出定位越界读写点与可控输入路径', checks: 6 },
  { id: 'web-auth-bypass', name: 'Web 鉴权绕过', version: 'v1.1', desc: '中间件顺序、路径规范化、大小写/分号绕过矩阵', checks: 7 },
  { id: 'supply-chain', name: '供应链与构建脚本', version: 'v1.0', desc: '依赖版本区间、postinstall / 构建期命令、密钥硬编码', checks: 5 },
]

/** 按扩展名推断附件类型，上传后用于选图标与分流 */
export function attachmentKind(name: string): string {
  const n = name.toLowerCase()
  if (n.endsWith('.zip') || n.endsWith('.tar.gz') || n.endsWith('.tgz') || n.endsWith('.7z')) return 'zip'
  if (n.endsWith('.java')) return 'java'
  if (n.endsWith('.go')) return 'go'
  if (n.endsWith('.php')) return 'php'
  if (n.endsWith('.c') || n.endsWith('.h') || n.endsWith('.cc')) return 'c'
  if (n.endsWith('.pdf')) return 'pdf'
  if (n.endsWith('.diff') || n.endsWith('.patch')) return 'diff'
  return 'text'
}

export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${bytes} B`
}

let seq = 0
function ev(type: RunEventType, payload: Record<string, unknown>, delay = 400): RunEvent {
  seq += 1
  return { seq, type, payload, delay }
}
function resetSeq() {
  seq = 0
}

/* ================= 样例 1：判定追问 · 修复完整性分析 ================= */

function scenario1(): Scenario {
  resetSeq()
  return {
    id: 'commit-followup',
    title: 'libxml2 修复完整吗？',
    mode: 'commit',
    modeLabel: '判定追问',
    question: '这个修复完整吗？还有没有绕过路径？',
    context: {
      kind: 'commit',
      label: 'commit 9f2e1ac · src/xml/parser.c',
      summary:
        '判定：is_security_fix=true · OOB_WRITE · confidence 0.82 · severity high\n组件：src/xml/parser.c:parse_attr\n证据：@@ -142,7 +142,9 @@ 增加 UTF-8 属性长度校验',
    },
    desc: '从判定详情页"问 agent"进入，agent 只读挂载源码验证判定结论',
    events: [
      ev('run.started', { run_id: 1024, conversation_id: 7 }, 300),
      ev('thinking.delta', { delta: '用户在问修复是否完整。判定只看了 diff 的 142 行 hunk，' }, 500),
      ev('thinking.delta', { delta: '我需要先读完整函数，再找 parse_attr 的全部调用点。' }, 500),
      ev('message.delta', { role: 'assistant', delta: '我先读一遍修复函数和它的完整调用链。' }, 350),
      ev('tool.call', { call_id: 'c1', name: 'read_file', args: { path: 'src/xml/parser.c', offset: 120, limit: 80 } }, 400),
      ev('tool.result', { call_id: 'c1', ok: true, duration_ms: 380, bytes: 4821, preview: 'static void parse_attr(xmlParserCtxtPtr ctxt, ...) {\n    if (len > INT_MAX / 4) { xmlFatalErr(...); return -1; }' }, 900),
      ev('tool.call', { call_id: 'c2', name: 'grep', args: { pattern: 'parse_attr\\(', glob: '*.c' } }, 350),
      ev('tool.result', { call_id: 'c2', ok: true, duration_ms: 210, preview: 'src/xml/parser.c:142  src/xml/parser.c:317  src/xml/reader.c:88' }, 800),
      ev('thinking.delta', { delta: 'reader.c:88 是 SAX 快捷路径，直接调 parse_attr 且没有做同样校验，' }, 600),
      ev('thinking.delta', { delta: '修复只补了主入口，这是一条完整的绕过路径。' }, 500),
      ev('message.delta', { role: 'assistant', delta: '修复本身是对的：parse_attr 增加了 len > INT_MAX/4 的上限校验，堵住了 UTF-8 属性解析的整数溢出越界写。' }, 400),
      ev('message.delta', { role: 'assistant', delta: '但**不完整**——src/xml/reader.c:88 的 SAX 快捷路径同样调用 parse_attr，未经过新校验，传入超长属性仍可触发同一溢出。' }, 450),
      ev('message.delta', { role: 'assistant', delta: '建议：1) reader.c 快捷路径入口补同样校验；2) 对该路径补一条超长属性回归用例后重新下发复现。' }, 400),
      ev('message.done', { message_id: 331, usage: { in: 3120, out: 420 } }, 300),
      ev('run.finished', { status: 'ok', tokens: { in: 3120, out: 420 } }, 300),
    ],
  }
}

/* ================= 样例 2：包审计 · 反序列化专项（含 run_bash 审批） ================= */

function scenario2(): Scenario {
  resetSeq()
  return {
    id: 'audit-deser',
    title: '审计 x-invoice 工具包',
    mode: 'audit',
    modeLabel: '代码审计',
    question: '审计这个包，重点看反序列化。',
    context: {
      kind: 'audit',
      label: 'audit #86 · x-invoice-1.4.2.zip',
      summary: '231 个文件 · Java 82% · semgrep 预筛 12 条命中，其中 3 条在 deserialize/ 相关路径',
    },
    desc: '上传包审计：静态扫描给候选点，agent 复核调用链后 submit_finding',
    events: [
      ev('run.started', { run_id: 1031, conversation_id: 9 }, 300),
      ev('thinking.delta', { delta: 'semgrep 已给 12 条候选，其中 3 条涉及反序列化，先看目录结构定位这几个文件。' }, 600),
      ev('tool.call', { call_id: 'c1', name: 'list_files', args: { path: '.', depth: 2 } }, 400),
      ev('tool.result', { call_id: 'c1', ok: true, duration_ms: 260, bytes: 1940, preview: 'src/main/java/com/x/invoice/  app/  tests/  pom.xml' }, 700),
      ev('message.delta', { role: 'assistant', delta: '先用 semgrep 复扫一遍反序列化规则，确认候选点行号。' }, 350),
      ev('tool.call', { call_id: 'c2', name: 'run_bash', args: { cmd: 'semgrep --config p/serialization --json src/', timeout: 120 } }, 450),
      ev('approval.required', { call_id: 'c2', name: 'run_bash', args: { cmd: 'semgrep --config p/serialization --json src/', timeout: 120 }, reason: 'bash 白名单含 semgrep，等待审批' }, 1200),
      ev('approval.resolved', { call_id: 'c2', decision: 'approved' }, 600),
      ev('tool.result', { call_id: 'c2', ok: true, duration_ms: 4120, bytes: 8241, preview: '12 findings · 3 in SoapClient.java / InvoiceParser.java' }, 1500),
      ev('tool.call', { call_id: 'c3', name: 'read_file', args: { path: 'src/main/java/com/x/invoice/SoapClient.java', offset: 210, limit: 60 } }, 400),
      ev('tool.result', { call_id: 'c3', ok: true, duration_ms: 350, bytes: 3180, preview: 'Object o = new ObjectInputStream(bais).readObject();  // line 238' }, 800),
      ev('thinking.delta', { delta: 'bais 来自 SOAP 响应体，中间没有任何类型白名单，ObjectInputStream 直接 readObject，' }, 600),
      ev('thinking.delta', { delta: '触发路径完整：外部可控输入 → 直接反序列化。confidence 0.85。' }, 500),
      ev('tool.call', { call_id: 'c4', name: 'submit_finding', args: { vuln_class: 'DESERIALIZATION', file: 'src/main/java/com/x/invoice/SoapClient.java', line: 238, severity: 'high', desc: 'SOAP 响应体直接进入 ObjectInputStream.readObject，无类型过滤' } }, 450),
      ev('tool.result', { call_id: 'c4', ok: true, duration_ms: 180, preview: 'finding #4512 created (source=audit, confidence=0.85)' }, 700),
      ev('message.delta', { role: 'assistant', delta: '确认 1 条高危：`SoapClient.java:238` SOAP 响应体未过滤直接 readObject，可构造 payload 触发任意类加载。' }, 400),
      ev('message.delta', { role: 'assistant', delta: '已写入 finding #4512。另 2 条反序列化命中是内部固定来源（不可控输入），已降级为"待确认"。' }, 400),
      ev('message.done', { message_id: 352, usage: { in: 8640, out: 610 } }, 300),
      ev('run.finished', { status: 'ok', tokens: { in: 8640, out: 610 } }, 300),
    ],
  }
}

/* ================= 样例 3：PoC 排查 · 修复版崩溃归因 ================= */

function scenario3(): Scenario {
  resetSeq()
  return {
    id: 'poc-triage',
    title: '为什么 PoC 在修复版也崩了？',
    mode: 'commit',
    modeLabel: '复现排查',
    question: '为什么这个 PoC 在修复版也崩了？finding #4508 被判 flaky。',
    context: {
      kind: 'finding',
      label: 'finding #4508 · OOB_READ · json-c 0.17',
      summary: '差分验证结果：vuln 崩溃 ✅ fix 也崩溃 ❌ · verify 结论 fix-side-also-crashed · PoC 三次运行均崩',
    },
    desc: '差分验证失败后的归因对话：哨兵日志证明是环境问题而非漏洞误判',
    events: [
      ev('run.started', { run_id: 1042, conversation_id: 11 }, 300),
      ev('thinking.delta', { delta: 'fix 侧也崩，四条否决里命中第一条。先看哨兵日志，确认崩在哪、__POC_START__ 标记有没有出现。' }, 600),
      ev('tool.call', { call_id: 'c1', name: 'read_file', args: { path: 'artifacts/finding-4508/oracle-fix.log' } }, 400),
      ev('tool.result', { call_id: 'c1', ok: true, duration_ms: 290, bytes: 1440, preview: 'Segmentation fault (core dumped) at _dl_start...\n__POC_START__ NOT SEEN' }, 800),
      ev('tool.call', { call_id: 'c2', name: 'read_file', args: { path: 'artifacts/finding-4508/poc/main.c' } }, 350),
      ev('tool.result', { call_id: 'c2', ok: true, duration_ms: 310, bytes: 980, preview: 'int main() { char *cfg = getenv("JSON_CONF"); ... }\n// 入口依赖环境变量，容器内未设置' }, 800),
      ev('thinking.delta', { delta: '两次都崩在 _dl_start（动态装载阶段），哨兵没看到 __POC_START__，' }, 550),
      ev('thinking.delta', { delta: '这是 crash-before-poc-point：PoC 依赖的环境变量在容器里不存在，装载即崩，和漏洞无关。' }, 550),
      ev('message.delta', { role: 'assistant', delta: '不是漏洞误判，是 **PoC 装载问题**：vuln/fix 两侧都崩在动态装载阶段（`_dl_start`），哨兵日志里 `__POC_START__` 从未出现——命中"crash-before-poc-point"特征。' }, 450),
      ev('message.delta', { role: 'assistant', delta: '根因：PoC 入口依赖 `JSON_CONF` 环境变量，容器内未设置，glibc 装载配置解析直接段错误。' }, 400),
      ev('message.delta', { role: 'assistant', delta: '建议：PoC 改为显式传入配置文件路径参数（不走环境变量），重跑三次差分。我可以直接改好 PoC 重新入队。' }, 400),
      ev('message.done', { message_id: 377, usage: { in: 5210, out: 380 } }, 300),
      ev('run.finished', { status: 'ok', tokens: { in: 5210, out: 380 } }, 300),
    ],
  }
}

/* ================= 样例 4：审批被拒 · 危险命令展示拒绝路径 ================= */

function scenario4(): Scenario {
  resetSeq()
  return {
    id: 'approval-denied',
    title: '把 PoC 推到测试机验证',
    mode: 'chat',
    modeLabel: '对话',
    question: '直接把 PoC 发到 10.0.0.8 的 fuzz 服务跑一下，快一点。',
    context: {
      kind: 'finding',
      label: 'finding #4512 · DESERIALIZATION',
      summary: 'agent 默认审批模式 manual · 方案 §1.2 明确"不自动外发 PoC"· 容器 run 阶段 --network none',
    },
    desc: '展示审批拒绝路径：run_bash 被 operator 拒绝后 agent 的降级行为',
    events: [
      ev('run.started', { run_id: 1051, conversation_id: 12 }, 300),
      ev('thinking.delta', { delta: '用户要外发 PoC 到内网机器。方案约束是全流程只在本机容器执行，但用户有明确指令——按流程走审批，由 operator 决定。' }, 700),
      ev('message.delta', { role: 'assistant', delta: '好，这条命令需要审批（目标网络访问 + 外发文件）。' }, 400),
      ev('tool.call', { call_id: 'c1', name: 'run_bash', args: { cmd: 'curl -s -X POST --data-binary @poc.bin http://10.0.0.8:9000/fuzz', timeout: 30 } }, 450),
      ev('approval.required', { call_id: 'c1', name: 'run_bash', args: { cmd: 'curl -s -X POST --data-binary @poc.bin http://10.0.0.8:9000/fuzz', timeout: 30 }, reason: '网络外发 + 非白名单命令 curl' }, 1500),
      ev('approval.resolved', { call_id: 'c1', decision: 'rejected' }, 800),
      ev('tool.result', { call_id: 'c1', ok: false, duration_ms: 0, error: 'denied by operator' }, 600),
      ev('thinking.delta', { delta: '被拒绝了。不纠缠，也不换别的路径偷偷执行——给出本机替代方案。' }, 600),
      ev('message.delta', { role: 'assistant', delta: '已拒绝，命令未执行。这符合安全约束：PoC 是武器化资产，不外发。' }, 400),
      ev('message.delta', { role: 'assistant', delta: '本机替代方案：在 agent 工作容器内对 fix/vuln 双镜像各跑一次 PoC（`--network none`），差分结果一样能确认 #4512，我来重新入队。' }, 450),
      ev('message.done', { message_id: 381, usage: { in: 2140, out: 210 } }, 300),
      ev('run.finished', { status: 'ok', tokens: { in: 2140, out: 210 } }, 300),
    ],
  }
}

/* ================= 样例 5：工具降级 · 泄露命中复核（§10 资采 AI） ================= */

function scenario5(): Scenario {
  resetSeq()
  return {
    id: 'leak-review',
    title: '复核本周泄露命中',
    mode: 'asset',
    modeLabel: '资采 AI',
    question: 'GitHub 泄露监控本周命中 14 条，帮我复核一下哪些是真 key。',
    context: {
      kind: 'asset',
      label: 'githubleak · 2026-W45 命中 14 条',
      summary: '值级正则命中：AKIA* 9 条 / sk-* 3 条 / ghp_* 2 条 · AI 复核属旁路增强，fail-open',
    },
    desc: '资采智能层接入点③：展示工具超时 → 重试 → 结构化复核结论',
    events: [
      ev('run.started', { run_id: 1060, conversation_id: 15 }, 300),
      ev('thinking.delta', { delta: '14 条命中要区分真 key / 占位符 / 测试样例。先按值级模式全量拉出来看上下文。' }, 550),
      ev('tool.call', { call_id: 'c1', name: 'grep', args: { pattern: 'AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}', path: 'githubleak/hits' } }, 450),
      ev('tool.result', { call_id: 'c1', ok: false, duration_ms: 5000, error: 'ripgrep timeout after 5s (hits 目录过大)' }, 1600),
      ev('thinking.delta', { delta: '全量目录超时了。缩小到本周分片目录重试，这是降级不是失败。' }, 600),
      ev('tool.call', { call_id: 'c2', name: 'grep', args: { pattern: 'AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}', path: 'githubleak/hits/2026-W45' } }, 400),
      ev('tool.result', { call_id: 'c2', ok: true, duration_ms: 480, preview: 'hits/2026-W45/bot-3.diff:14  hits/2026-W45/web-7.diff:2  (+12 more)' }, 900),
      ev('tool.call', { call_id: 'c3', name: 'read_file', args: { path: 'githubleak/hits/2026-W45/bot-3.diff', limit: 40 } }, 350),
      ev('tool.result', { call_id: 'c3', ok: true, duration_ms: 300, bytes: 2210, preview: '- const KEY = "AKIAxxxxxxxxxxxxxxxx";  // test fixture, repo tests/' }, 800),
      ev('thinking.delta', { delta: 'bot-3 命中在 tests/ 目录且变量名是占位符；web-7 是 .env 生产配置混入提交，这条是真的。' }, 600),
      ev('message.delta', { role: 'assistant', delta: '复核完成，14 条命中分类如下：' }, 350),
      ev('message.delta', { role: 'assistant', delta: '**真 key 1 条**：web-7.diff:2 —— `.env` 生产 AWS key 混入公开提交，需立即轮换并通知仓库管理员；' }, 400),
      ev('message.delta', { role: 'assistant', delta: '**误报 13 条**：9 条在 tests/ 或 demo/ 的占位符样例（`AKIAxxxxxxxx`），4 条是文档示例。误报率 93%，建议给泄露规则加 `tests/ demo/ docs/` 路径豁免。' }, 450),
      ev('message.delta', { role: 'assistant', delta: '真 key 已转风险发现并推送飞书告警；本次复核记入 llm_usage（scene=leak_review）。' }, 400),
      ev('message.done', { message_id: 402, usage: { in: 4180, out: 290 } }, 300),
      ev('run.finished', { status: 'ok', tokens: { in: 4180, out: 290 } }, 300),
    ],
  }
}

/* ================= 样例 6：上传 zip + 指定 skill（新输入模型演示） ================= */

function scenarioUpload(): Scenario {
  resetSeq()
  return {
    id: 'upload-skill',
    title: '上传包 + 指定 skill 分析',
    mode: 'audit',
    modeLabel: '上传分析',
    question: '按 Java 反序列化 skill 审一遍这个包，只要可触发的高危点。',
    context: {
      kind: 'audit',
      label: 'x-invoice-1.4.2.zip · 4.1 MB',
      summary: '231 个文件 · Java 82% · 归档校验通过（无符号链接 / 无路径穿越）\nskill：Java 反序列化审计 v1.2 · 注入 5 项检查',
    },
    desc: '上传归档 + 指定 skill，事件流里先落附件与 skill 注入，再进工具链',
    attachments: [
      { name: 'x-invoice-1.4.2.zip', size: 4128000, kind: 'zip', files: 231, status: 'ready' },
    ],
    skill: SKILLS[0],
    events: [
      ev('file.uploaded', { name: 'x-invoice-1.4.2.zip', size: 4128000, kind: 'zip', files: 231, sha256: '9f2e…c41a', checks: 'zip 校验通过：无符号链接 / 无路径穿越 / 单文件 ≤200MB' }, 400),
      ev('skill.loaded', { skill: 'java-deser-audit', name: 'Java 反序列化审计', version: 'v1.2', checks: 5, guide_tokens: 1840 }, 600),
      ev('run.started', { run_id: 1071, conversation_id: 21 }, 400),
      ev('thinking.delta', { delta: 'skill 指定了检查顺序：先 ObjectInputStream / readObject，再 XMLDecoder，最后 gadget 可达性。' }, 700),
      ev('message.delta', { role: 'assistant', delta: '已按 skill「Java 反序列化审计 v1.2」加载 5 项检查，先解归档看目录结构。' }, 500),
      ev('tool.call', { call_id: 'u1', name: 'list_files', args: { path: '.', depth: 2 } }, 450),
      ev('tool.result', { call_id: 'u1', ok: true, duration_ms: 240, bytes: 1940, preview: 'src/main/java/com/x/invoice/  app/  tests/  pom.xml' }, 700),
      ev('tool.call', { call_id: 'u2', name: 'grep', args: { pattern: 'readObject|ObjectInputStream|XMLDecoder', glob: '*.java' } }, 450),
      ev('tool.result', { call_id: 'u2', ok: true, duration_ms: 310, preview: 'SoapClient.java:238 readObject()\nInvoiceParser.java:88 XMLDecoder\nMockRepo.java:41 (tests/)' }, 800),
      ev('tool.call', { call_id: 'u3', name: 'read_file', args: { path: 'src/main/java/com/x/invoice/SoapClient.java', offset: 210, limit: 60 } }, 450),
      ev('tool.result', { call_id: 'u3', ok: true, duration_ms: 340, bytes: 3180, preview: 'Object o = new ObjectInputStream(bais).readObject();  // line 238' }, 800),
      ev('thinking.delta', { delta: '238 行输入来自 SOAP 响应体，无类型白名单 → 检查项 1/2 命中；XMLDecoder 那处在 tests 里不可达。' }, 700),
      ev('tool.call', { call_id: 'u4', name: 'submit_finding', args: { vuln_class: 'DESERIALIZATION', file: 'src/main/java/com/x/invoice/SoapClient.java', line: 238, severity: 'high' } }, 450),
      ev('tool.result', { call_id: 'u4', ok: true, duration_ms: 160, preview: 'finding #4520 created (skill=java-deser-audit, confidence=0.86)' }, 700),
      ev('message.delta', { role: 'assistant', delta: '确认 1 条高危：`SoapClient.java:238` SOAP 响应体直接进入 `readObject`，无类型白名单，外部可控 → 已写入 finding #4520。' }, 450),
      ev('message.delta', { role: 'assistant', delta: 'skill 检查项覆盖 3/5：`XMLDecoder`（tests 内不可达）与 `gadget 链`（依赖未引入 commons-collections）判定为不适用。' }, 450),
      ev('message.done', { message_id: 421, usage: { in: 6420, out: 460 } }, 350),
      ev('run.finished', { status: 'ok', tokens: { in: 6420, out: 460 } }, 350),
    ],
  }
}

export const UPLOAD_SCENARIO: Scenario = scenarioUpload()

export const SCENARIOS: Scenario[] = [
  scenario1(),
  scenario2(),
  scenario3(),
  scenario4(),
  scenario5(),
  scenarioUpload(),
]

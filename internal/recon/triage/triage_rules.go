package triage

import (
	"regexp"
	"strings"
	"time"
)

// ============================================================================
// 常量区：所有阈值、权重、正则集中于此，调参只改这里
// ============================================================================

// ---------------- 输出档位 ----------------

// Verdict 五档判定结论
type Verdict string

const (
	VerdictMalicious Verdict = "MALICIOUS" // 疑似木马/钓鱼仓库：隔离 + 安全告警，禁止下载执行
	VerdictACT       Verdict = "ACT"       // 推送分析师
	VerdictWatch     Verdict = "WATCH"     // 漏洞监控队列，持续观察，不推送
	VerdictNoise     Verdict = "NOISE"     // 该仓库丢弃（CVE 本身可能仍有效）
	VerdictLabOnly   Verdict = "LAB_ONLY"  // 漏洞层面丢弃（实验室漏洞）
)

// ShouldAlert 仅 ACT 与 MALICIOUS 需要告警/推送
func ShouldAlert(v Verdict) bool { return v == VerdictACT || v == VerdictMalicious }

// ---------------- CVE 层权重 ----------------

const (
	ScoreKEV = 100 // CISA KEV 在册：直接 +100 并返回 ACT，永不过滤

	// EPSS 分档（30 天内被在野利用的概率）。0.1 是业界常用参考值而非权威线，可自行调整
	EPSSHigh            = 0.5
	EPSSHighScore       = 45
	EPSSMedium          = 0.1
	EPSSMediumScore     = 30
	EPSSLow             = 0.01
	EPSSLowScore        = 8
	EPSSVeryLowScore    = -5
	EPSSPercentileHigh  = 0.95
	EPSSPercentileScore = 12

	// Exploit Maturity（v4 E:A / v2·v3 E:H·E:F·E:P·E:U）
	ExploitMaturityAttacked   = 35  // E:A (v4) 已出现在野攻击
	ExploitMaturityHigh       = 35  // E:H (v2/v3) 自动化利用代码已存在
	ExploitMaturityFunctional = 25  // E:F (v2) 功能性利用代码可用
	ExploitMaturityPOC        = 15  // E:P / E:POC 概念验证已公开
	ExploitMaturityUnproven   = -10 // E:U 无可用利用代码

	AutomatableScore  = 20 // 官方标记可自动化利用
	PerfectStormScore = 40 // AV:N+AC:L+PR:N+UI:N(+AT:N) 完美风暴
	CWEHighScore      = 18
	CWELowScore       = -15
	DescKeywordScore  = 10 // 描述含高价值关键词（只加一次）

	AVAdjacentScore = -8
	ACHighScore     = -15
	ATProofScore    = -12
	UIActiveScore   = -10
	UIPassiveScore  = -4
	PRLowScore      = -8
	PRHighScore     = -25
	DoSOnlyScore    = -12
	NonDefaultScore = -18 // 软信号，不得单独判死

	// ---------------- 合并阈值 ----------------

	ACTThreshold   = 60  // total ≥ 60 → ACT
	WATCHThreshold = 20  // total ≥ 20 → WATCH；< 20 → NOISE / LAB_ONLY
	RescueRepoMax  = -20 // Repo 层得分 ≤ 此值
	RescueCVEMin   = 60  // 且 CVE 层得分 ≥ 此值 → 强制 WATCH（高危漏洞抢救线）
)

// ---------------- Repo 层权重 ----------------

const (
	PlaceholderScore = -40 // 无代码文件或代码总量 < 200B
	WeaponizedScore  = 45  // 真实利用证据 ≥ 3 条
	RealPOCScore     = 30  // 真实利用证据 1~2 条
	DetectorScore    = -20 // 仅探测/扫描特征
	AdvisoryScore    = -15 // 情报汇编/公告转载

	MinCodeBytes      = 200
	WeaponizedMinHits = 3
	SnippetFileLimit  = 20 // 内容分类最多聚合前 20 个文件的 snippet

	OneDayWonderScore = -25 // 创建与最后推送同日 + 零关注：一次性蹭热度仓库
	OneDayWindow      = 24 * time.Hour
	OneDayMaxStars    = 2

	StarsHigh      = 20
	StarsHighScore = 15
	StarsMid       = 5
	StarsMidScore  = 6

	ScannerNameScore = -15 // 仓库名为扫描器/笔记类命名模式

	AIShellScore        = -30 // AI 生成空壳特征
	AIShellMinReadmeLen = 1500
	AIShellMinEmoji     = 8
	AIShellMaxCodeBytes = 1500

	OwnerActiveMinRepos = 10
	OwnerActiveScore    = 8
	SockPuppetWindow    = 7 * 24 * time.Hour // 作者注册距建仓 < 7 天 → 马甲号
	SockPuppetScore     = -12
	TrustedOrgScore     = 25
	ForkScore           = -10
	ArchivedScore       = -5

	MaliciousMinHits = 2 // 恶意特征命中 ≥2 条 → MALICIOUS（或 ≥1 条 + 预编译二进制）
)

// TrustedOrgs 可信组织白名单（小写 login），命中 +25。按需追加：triage.AddTrustedOrgs("xxx")
var TrustedOrgs = map[string]struct{}{
	"projectdiscovery": {}, "rapid7": {}, "jfrog": {}, "tenable": {}, "vulncheck": {},
	"synacktiv": {}, "googleprojectzero": {}, "unit42": {}, "cisagov": {}, "nsacyber": {},
	"offsec": {}, "exploit-db": {}, "metasploit": {}, "paloaltonetworks": {}, "crowdstrike": {},
	"returntocorp": {}, "watchtowr": {}, "horizon3ai": {}, "assetnote": {}, "bishopfox": {},
}

// AddTrustedOrgs 追加可信组织
func AddTrustedOrgs(names ...string) {
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			TrustedOrgs[n] = struct{}{}
		}
	}
}

// ---------------- 正则表 ----------------

// labeledPattern 带中文说明的正则条目，说明用于生成人类可读理由
type labeledPattern struct{ label, re string }

type compiledPattern struct {
	label string
	re    *regexp.Regexp
}

// CVE 描述实验室措辞（硬否决，忽略大小写）
var labPhraseTable = []labeledPattern{
	{"仅停留在理论层面", `theoretical(?:ly)?\b`},
	{"官方明确不可利用", `not (?:known to be )?exploitable`},
	{"尚无已知利用", `no known exploit`},
	{"需要本地/物理访问", `requires? (?:local|physical) access`},
	{"需要物理接触设备", `physical(?:ly)? (?:access|present|attached)`},
	{"依赖调试口/调试接口", `debug (?:port|interface|access|shell)`},
	{"依赖硬件调试总线(JTAG/UART/SWD)", `(?:JTAG|UART|SWD|serial console)`},
	{"明示实验室专属场景", `lab(?:oratory)?[- ](?:only|environment|setting|condition)`},
	{"仅限受控环境", `controlled (?:lab )?environment`},
	{"依赖非默认配置", `non-?default (?:configuration|setting|option|build)`},
	{"默认安装不受影响", `default (?:installation|configuration) is not affected`},
	{"攻击者需预先持有等价权限", `attacker must already (?:have|possess)`},
	{"要求已处于认证状态", `already (?:be )?authenticated`},
	{"利用时间窗极窄", `narrow (?:timing )?window`},
	{"依赖竞态时序", `race (?:condition|window)`},
	{"需先致瘫内存防护(ASLR/DEP等)", `(?:ASLR|DEP|CFG|CET|stack canary|SMAP|SMEP)[\s\S]{0,40}(?:disabled|bypass|defeat)`},
	{"需先致瘫内存防护(ASLR/DEP等)", `(?:disabled|bypass|defeat)[\s\S]{0,40}(?:ASLR|DEP|CFG|CET|stack canary|SMAP|SMEP)`},
	{"仅限演示/教学/研究用途", `(?:demonstration|educational|research) purposes only`},
	{"厂商否认其为安全问题", `not a (?:security )?(?:issue|vulnerability|bug)`},
	{"厂商拒绝修复/按设计处理", `(?:won'?t fix|will not fix|by design|working as intended)`},
	{"争议漏洞(有厂商异议)", `\bdisputed\b`},
	{"仅停留在理论层面", `仅理论上`},
	{"需要物理/本地接触", `需要(?:物理|本地)(?:接触|访问)`},
	{"实验室/受控环境", `实验室环境|受控环境`},
	{"依赖非默认配置", `非默认配置`},
}

// 厂商处置黑名单（vendor_disposition 子串，忽略大小写）→ 硬否决
var vendorBadDispositions = []string{
	"not exploitable", "won't fix", "wontfix", "will not fix",
	"by design", "working as intended", "disputed",
}

// 描述高价值关键词（+10，只加一次）
var descKeywordTable = []labeledPattern{
	{"remote code execution", `remote code execution`},
	{"arbitrary code execution", `arbitrary code execution`},
	{"command injection", `command injection`},
	{"sql injection", `sql injection`},
	{"unauthenticated", `unauthenticated`},
}

// 高影响关键词：用于判定「影响仅为 DoS」——命中任一即不算纯 DoS
var highImpactTerms = []string{
	"code execution", "remote code execution", "command injection", "code injection",
	"sql injection", "privilege escalation", "arbitrary code", "arbitrary command",
	"arbitrary file", "information disclosure", "sensitive information", "sandbox escape",
	"authentication bypass", "server-side request forgery", "xml external entity",
	"deserialization", "file upload", "security bypass",
}

// 仅调试/测试/非生产环境可触发（软信号 -18，不单独判死）
var nonDefaultTable = []labeledPattern{
	{"仅调试/测试/预发模式可触发", `(?:only|just)[^.]{0,40}(?:debug|test|development|staging|non-?production)`},
	{"默认部署不暴露/不启用", `(?:not (?:exposed|enabled|installed)|disabled) by default`},
	{"仅存在于调试/测试构建", `(?:debug|test|development|staging)[ -]?(?:mode|build|environment)`},
}

// Repo 恶意代码特征：命中 ≥ MaliciousMinHits 条，或 ≥1 条且含预编译二进制 → MALICIOUS
var maliciousTable = []labeledPattern{
	{"base64 动态解码", `base64\.b64decode`},
	{"frombase64 解码", `frombase64`},
	{"exec() 动态执行", `\bexec\(`},
	{"eval() 动态执行", `\beval\(`},
	{"chr() 数值拼接混淆", `chr\(\d+\)\s*\+`},
	{"连续十六进制转义(≥16)", `(?:\\x[0-9a-fA-F]{2}){16,}`},
	{"pastebin 外联", `pastebin\.com`},
	{"Discord Webhook 外联", `discord(?:app)?\.com/api/webhooks`},
	{"带外隧道平台(ngrok等)", `(?:ngrok|serveo|localtunnel|burpcollaborator|oastify)`},
	{"加密货币钱包诱饵", `(?:btc|bitcoin|ethereum|xmr|monero)[\s\S]{0,60}(?:wallet|address|donate|payment)`},
	{"加密货币钱包诱饵(反向)", `(?:wallet|address|donate|payment)[\s\S]{0,60}(?:btc|bitcoin|ethereum|xmr|monero)`},
	{"比特币收款地址", `[13][a-km-zA-HJ-NP-Z1-9]{26,33}`},
	{"以太坊收款地址", `0x[a-fA-F0-9]{40}`},
	{"PowerShell 绕过执行策略", `set-executionpolicy bypass`},
	{"PowerShell IEX 下载执行", `iex\s*\(\s*new-object`},
	{"subprocess 拉取外部程序", `subprocess\.(?:run|popen|call)\([\s\S]{0,80}(?:curl|wget|certutil|powershell)`},
}

// 真实利用证据（内容形态分类用）
var weaponizedTable = []labeledPattern{
	{"reverse shell", `reverse[-_ ]?shell`},
	{"bind shell", `bind[-_ ]?shell`},
	{"interactive shell", `interactive shell`},
	{"whoami 验证", `\bwhoami\b`},
	{"ifconfig 验证", `\bifconfig\b`},
	{"读取 passwd/shadow", `cat /etc/(?:passwd|shadow)`},
	{"calc 弹窗验证", `\bcalc(?:\.exe)?\b`},
	{"nc 起shell", `\bnc -[a-z]*e?\b`},
	{"bash -i 反弹", `bash -i`},
	{"os.popen 执行", `os\.popen`},
	{"os.system 执行", `os\.system`},
	{"subprocess 调用", `subprocess\.(?:run|popen|call)`},
	{"Java Runtime.exec", `runtime\.getruntime\(`},
	{"exec() 执行", `\bexec\(`},
	{"__import__ 动态导入", `__import__\(['"]os['"]\)`},
	{"命令执行描述", `command execution`},
	{"任意代码/命令执行描述", `arbitrary (?:code|command) execution`},
	{"pwntools 利用框架", `pwntools`},
	{"interact() 交互", `interact\(`},
	{"sendline() 交互", `sendline\(`},
	{"ROP 利用链", `\brop\b`},
	{"gadget 链", `\bgadget`},
	{"RCE 实证描述", `proof of (?:rce|exploitation)`},
	{"getshell 实证描述", `shell (?:obtained|received|spawned)`},
}

// 探测/扫描特征（只匹配 readme + description）
var detectorTable = []labeledPattern{
	{"checks if/whether", `checks? (?:if|whether)`},
	{"version check/detect", `version (?:check|detect|detection)`},
	{"determine the version", `determine the version`},
	{"vulnerable version", `vulnerable version`},
	{"scan/扫描", `\bscan(?:s|ner|ning)?\b`},
	{"mass scan/check", `mass[-_ ]?(?:scan|check)`},
	{"fingerprint 指纹识别", `fingerprint`},
	{"banner grab/check", `banner (?:grab|check)`},
}

// 仓库名批量扫描器命名模式 → -15
var scannerNameTable = []labeledPattern{
	{"mass scan/check", `mass[-_ ]?(?:scan|check)`},
	{"batch scan", `batch[-_ ]?scan`},
	{"multi scan/check", `multi[-_ ]?(?:scan|check)`},
	{"auto scan/poc", `auto[-_ ]?(?:scan|poc)`},
	{"检查器/笔记类后缀", `(?:[-_](?:checker|detector|scanner|verifier|nuclei|info|advisory|notes|research|writeup))$`},
}

// 预编译二进制扩展名（触发「恶意特征≥1条+二进制」判死线；.ps1 按规范视同）
var maliciousBinaryExts = map[string]struct{}{
	".exe": {}, ".dll": {}, ".scr": {}, ".bin": {}, ".so": {}, ".dylib": {}, ".jar": {}, ".ps1": {},
}

// 代码文件扩展名（内容形态分类用）
var codeFileExts = map[string]struct{}{
	".py": {}, ".go": {}, ".c": {}, ".cpp": {}, ".cc": {}, ".h": {}, ".rb": {}, ".java": {},
	".js": {}, ".ts": {}, ".sh": {}, ".pl": {}, ".php": {}, ".rs": {}, ".cs": {},
	".yaml": {}, ".yml": {},
}

// CWE 分档（未列出的不计分）
var cweHighValue = map[int]struct{}{
	78: {}, 88: {}, 89: {}, 91: {}, 94: {}, 917: {}, 1321: {}, 22: {}, 23: {}, 36: {},
	502: {}, 611: {}, 918: {}, 269: {}, 284: {}, 285: {}, 287: {}, 306: {}, 862: {},
	798: {}, 1392: {}, 640: {}, 121: {}, 122: {}, 787: {}, 125: {}, 416: {}, 415: {},
}
var cweLowValue = map[int]struct{}{
	476: {}, 824: {}, 908: {}, 665: {}, 457: {}, 400: {}, 770: {}, 835: {}, 674: {},
	409: {}, 776: {}, 362: {}, 366: {}, 367: {}, 59: {}, 427: {}, 426: {}, 200: {},
	209: {}, 532: {}, 79: {}, 601: {},
}

// Exploit Maturity 分值与理由（v4 E:A / v2·v3 E:H·E:F·E:P·E:POC·E:U）
var exploitMaturityScores = map[string]int{
	"A": ExploitMaturityAttacked, "H": ExploitMaturityHigh, "F": ExploitMaturityFunctional,
	"P": ExploitMaturityPOC, "POC": ExploitMaturityPOC, "U": ExploitMaturityUnproven,
}
var exploitMaturityReasons = map[string]string{
	"A":   "CVSS v4 攻击成熟度确认已出现在野攻击",
	"H":   "已有自动化利用代码（成熟度高）",
	"F":   "已有可用功能性利用代码",
	"P":   "已有公开概念验证 PoC",
	"POC": "已有公开概念验证 PoC",
	"U":   "尚无可用利用代码",
}

var emojiRe = compileStrict(`[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}]`)

// 预编译（静态表，编译失败直接 panic 暴露问题）
var (
	compiledLabPhrase  = compileAll(labPhraseTable)
	compiledDescKw     = compileAll(descKeywordTable)
	compiledNonDefault = compileAll(nonDefaultTable)
	compiledMalicious  = compileAll(maliciousTable)
	compiledWeaponized = compileAll(weaponizedTable)
	compiledDetector   = compileAll(detectorTable)
	compiledScannerNm  = compileAll(scannerNameTable)
)

func compileStrict(re string) *regexp.Regexp { return regexp.MustCompile(re) }

func compileAll(table []labeledPattern) []compiledPattern {
	out := make([]compiledPattern, 0, len(table))
	for _, p := range table {
		out = append(out, compiledPattern{label: p.label, re: regexp.MustCompile(`(?i)` + p.re)})
	}
	return out
}

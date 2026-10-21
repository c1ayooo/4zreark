// Package triage 「实验室漏洞」两层过滤器。
//
// 核心思想是把两类性质不同的噪声拆开判定：
//   - 层 1（CVE 层）：这个漏洞现实中打不打得到、值不值得打。技术成立但需要物理接触、
//     本地管理员、非默认配置、竞态时序、仅有 DoS 影响、厂商拒不修复等 → 实验室漏洞（LAB_ONLY）。
//   - 层 2（Repo 层）：这个 GitHub 仓库是不是真的利用代码。识别恶意仓库（木马/钓鱼）、
//     AI 生成空壳、批量扫描器、情报转载与真实 PoC。
//
// 两层独立打分、独立判定，最终合并为五档结论：
// MALICIOUS（隔离+告警）/ ACT（推送）/ WATCH（观察）/ NOISE（丢仓库）/ LAB_ONLY（丢漏洞）。
// 「高危漏洞 + 暂时只有垃圾 PoC」会被抢救进 WATCH，绝不误杀。
//
// 纯规则实现：无网络调用、无第三方依赖、无 ML。
// 所有阈值 / 白名单 / 正则集中在文件顶部常量区，便于调参。
package triage

import (
	"fmt"
	"path"
	"strings"
	"time"
)

// ============================================================================
// 输入结构：字段能拿多少算多少，缺失即该信号不贡献分数
// ============================================================================

// FileEntry 仓库内单个文件（content_snippet 可为空）
type FileEntry struct {
	Path           string
	Size           int64
	ContentSnippet string
}

// CVEMeta CVE 元数据（指针/空串 = 数据源没给）
type CVEMeta struct {
	CVEID             string
	CVSSVector        string // v2/v3.x/v4.0 原始向量串
	CVSSScore         float64
	CWE               []int // 兼容单值与列表，调用方自行展开
	Description       string
	InKEV             *bool // nil = 未知（不参与 KEV 判定）
	EPSS              *float64
	EPSSPercentile    *float64
	Automatable       *bool
	VendorDisposition string
	ImpactType        string
}

// RepoMeta GitHub 仓库元数据
type RepoMeta struct {
	FullName         string
	Description      string
	Stars            int
	Forks            int
	Watchers         int
	CreatedAt        string // RFC3339 或 2006-01-02；空 = 未知
	PushedAt         string
	IsFork           *bool
	Archived         *bool
	OwnerCreatedAt   string
	OwnerPublicRepos *int
	Readme           string
	Files            []FileEntry
}

// ============================================================================
// 对外入口
// ============================================================================

// Triage 两层体检合并判定。返回 (结论, 总分, 人类可读理由列表)。
func Triage(cve CVEMeta, repo RepoMeta) (Verdict, int, []string) {
	cveScore, cveReasons, ev := scoreCVE(cve)
	repoScore, repoReasons, malicious := scoreRepo(repo)

	reasons := make([]string, 0, len(cveReasons)+len(repoReasons)+2)
	reasons = append(reasons, cveReasons...)
	reasons = append(reasons, repoReasons...)
	total := cveScore + repoScore

	switch {
	case malicious:
		reasons = append(reasons, "[!] 处置：疑似恶意仓库，隔离并触发安全告警，禁止克隆/下载/执行")
		return VerdictMalicious, total, reasons
	case ev.kev:
		return VerdictACT, total, reasons
	case ev.veto:
		return VerdictLabOnly, total, reasons
	case repoScore <= RescueRepoMax && cveScore >= RescueCVEMin:
		reasons = append(reasons, fmt.Sprintf(
			"[!] 高危漏洞 + 暂时没有可信 PoC（CVE 层 %d 分 / Repo 层 %d 分），转入监控队列持续观察，不要丢弃",
			cveScore, repoScore))
		return VerdictWatch, total, reasons
	case total >= ACTThreshold:
		return VerdictACT, total, reasons
	case total >= WATCHThreshold:
		return VerdictWatch, total, reasons
	default:
		// 总分不足：区分丢弃层级——仓库是主因 → NOISE（丢仓库，CVE 可能仍有效）；
		// 仓库不背锅 → 说明是 CVE 本身吸引力不足 → LAB_ONLY（漏洞层面丢弃）
		if repoScore < 0 {
			return VerdictNoise, total, reasons
		}
		return VerdictLabOnly, total, reasons
	}
}

// ============================================================================
// 层 1：CVE 层
// ============================================================================

type cveEval struct {
	kev  bool // KEV 在册，强制 ACT
	veto bool // 硬否决，LAB_ONLY
}

func scoreCVE(c CVEMeta) (int, []string, cveEval) {
	var ev cveEval
	score := 0
	reasons := []string{}
	m := ParseCVSS(c.CVSSVector)

	// KEV 最高优先：在册即在野，永不过滤（与 EPSS 冲突时听 KEV 的）
	if c.InKEV != nil && *c.InKEV {
		ev.kev = true
		score += ScoreKEV
		return score, append(reasons, fmt.Sprintf(
			"[!] CISA KEV 在野利用名单在册 (+%d) —— 已确认被真实攻击者利用，最高优先级，永不过滤", ScoreKEV)), ev
	}

	// 硬否决：命中任一 → LAB_ONLY，不再计算任何分数
	if vetoes := labVetoes(c, m); len(vetoes) > 0 {
		ev.veto = true
		return score, append(reasons, vetoes...), ev
	}

	// ---- 正分 ----
	if c.EPSS != nil {
		e := *c.EPSS
		switch {
		case e >= EPSSHigh:
			score += EPSSHighScore
			reasons = append(reasons, fmt.Sprintf("[+] EPSS %.2f ≥ %.2f (+%d) —— 未来 30 天被在野利用概率很高，攻击者大概率已持有可用利用代码", e, EPSSHigh, EPSSHighScore))
		case e >= EPSSMedium:
			score += EPSSMediumScore
			reasons = append(reasons, fmt.Sprintf("[+] EPSS %.2f ≥ %.2f (+%d) —— 存在现实利用概率，值得重点关注", e, EPSSMedium, EPSSMediumScore))
		case e >= EPSSLow:
			score += EPSSLowScore
			reasons = append(reasons, fmt.Sprintf("[+] EPSS %.4f ≥ %.2f (+%d) —— 有少量利用观测", e, EPSSLow, EPSSLowScore))
		default:
			score += EPSSVeryLowScore
			reasons = append(reasons, fmt.Sprintf("[+] EPSS %.4f < %.2f (%+d) —— 几乎无利用观测，属冷门漏洞", e, EPSSLow, EPSSVeryLowScore))
		}
	}
	if c.EPSSPercentile != nil && *c.EPSSPercentile >= EPSSPercentileHigh {
		score += EPSSPercentileScore
		reasons = append(reasons, fmt.Sprintf("[+] EPSS 百分位 %.2f ≥ %.2f (+%d) —— 利用概率超过 95%% 的同类 CVE", *c.EPSSPercentile, EPSSPercentileHigh, EPSSPercentileScore))
	}

	if em := m.Get("E"); em != "" {
		if s, ok := exploitMaturityScores[em]; ok {
			score += s
			sign := "+"
			if s < 0 {
				sign = ""
			}
			reasons = append(reasons, fmt.Sprintf("[%s] CVSS E:%s (%s%d) —— %s", signOf(s), em, sign, s, exploitMaturityReasons[em]))
		}
	}

	if c.Automatable != nil && *c.Automatable {
		score += AutomatableScore
		reasons = append(reasons, fmt.Sprintf("[+] automatable:true (+%d) —— 可被自动化利用，适合无差别大规模武器化", AutomatableScore))
	}

	if perfectStorm(m) {
		score += PerfectStormScore
		reasons = append(reasons, fmt.Sprintf("[+] 完美风暴向量 AV:N/AC:L/PR:N/UI:N(+AT:N) (+%d) —— 无需认证、无交互、低复杂度远程利用，武器化成本最低", PerfectStormScore))
	}

	if hasAnyCWE(c.CWE, cweHighValue) {
		score += CWEHighScore
		reasons = append(reasons, fmt.Sprintf("[+] CWE 属高收益类别 (+%d) —— 直接通向代码执行/注入/越权，攻击 ROI 高", CWEHighScore))
	} else if hasAnyCWE(c.CWE, cweLowValue) {
		score += CWELowScore
		reasons = append(reasons, fmt.Sprintf("[-] CWE 属低收益类别 (%d) —— 多为崩溃/信息泄露/自限性缺陷，攻击 ROI 低", CWELowScore))
	}

	if hits := matchLabels(compiledDescKw, c.Description); len(hits) > 0 {
		score += DescKeywordScore
		reasons = append(reasons, fmt.Sprintf("[+] 描述含高价值关键词「%s」(+%d) —— 直接指向可武器化的利用效果", strings.Join(hits, "、"), DescKeywordScore))
	}

	// ---- 负分 ----
	if m.Get("AV") == "A" {
		score += AVAdjacentScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS AV:A (%d) —— 需接入相邻网络，公网攻击者无法直接触达", AVAdjacentScore))
	}
	if m.Get("AC") == "H" {
		score += ACHighScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS AC:H (%d) —— 攻击条件苛刻或依赖精确时序，成功率不稳定", ACHighScore))
	}
	if m.Get("AT") == "P" {
		score += ATProofScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS AT:P (%d) —— 依赖特定部署条件才能得手", ATProofScore))
	}
	if m.Get("UI") == "A" {
		score += UIActiveScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS UI:A (%d) —— 需要用户主动交互配合", UIActiveScore))
	} else if m.Get("UI") == "P" {
		score += UIPassiveScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS UI:P (%d) —— 需要少量用户交互", UIPassiveScore))
	}
	if m.Get("PR") == "L" {
		score += PRLowScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS PR:L (%d) —— 需要先拿到普通权限账号", PRLowScore))
	} else if m.Get("PR") == "H" {
		score += PRHighScore
		reasons = append(reasons, fmt.Sprintf("[-] CVSS PR:H (%d) —— 需要管理员级权限，等于已被攻陷才有利用前提", PRHighScore))
	}
	if isDoSOnly(c) {
		score += DoSOnlyScore
		reasons = append(reasons, fmt.Sprintf("[-] 影响仅为拒绝服务 (%d) —— 打下来除了打崩服务没有进一步收益，攻击优先级极低", DoSOnlyScore))
	}
	if hits := matchLabels(compiledNonDefault, c.Description); len(hits) > 0 {
		score += NonDefaultScore
		reasons = append(reasons, fmt.Sprintf("[-] 默认配置下不暴露（%s）(%d) —— 仅调试/测试/非生产环境可触发（软信号，不单独判死）", strings.Join(dedupe(hits), "、"), NonDefaultScore))
	}

	return score, reasons, ev
}

// labVetoes 硬否决清单，返回命中的理由（空 = 未命中）
func labVetoes(c CVEMeta, m CVSSMetrics) []string {
	var out []string

	if m.Get("AV") == "P" {
		out = append(out, fmt.Sprintf("[x] CVSS AV:P —— 需要物理接触目标设备，远程攻击者根本打不到"))
	}
	if m.Get("AV") == "L" && m.Get("PR") == "H" {
		out = append(out, "[x] CVSS AV:L + PR:H —— 需要本地管理员权限，能利用它就说明主机已经沦陷")
	}
	if m.Get("AV") == "L" && isDoSOnly(c) {
		out = append(out, "[x] CVSS AV:L 且影响仅为 DoS —— 本地可达 + 只能打崩进程，现实收益为零")
	}

	seen := map[string]bool{}
	for _, p := range compiledLabPhrase {
		if p.re.MatchString(c.Description) && !seen[p.label] {
			seen[p.label] = true
			out = append(out, fmt.Sprintf("[x] 描述命中实验室措辞「%s」—— 技术上成立但现实场景打不到/打不划算", p.label))
		}
	}

	d := strings.ToLower(c.VendorDisposition)
	for _, bad := range vendorBadDispositions {
		if d != "" && strings.Contains(d, bad) {
			out = append(out, fmt.Sprintf("[x] 厂商处置「%s」—— 官方判定不可利用/不予修复/按设计如此/存在争议", c.VendorDisposition))
			break
		}
	}

	// CVSS v4 专属：AT:P + AC:H（依赖特定部署条件且需攻克竞态/精确时序）
	if m.Get("AT") == "P" && m.Get("AC") == "H" {
		out = append(out, "[x] CVSS v4 AT:P + AC:H —— 攻击依赖特定部署条件，且需攻克竞态/精确时序，实战成功率极低")
	}
	return out
}

// isDoSOnly 判断影响是否仅为拒绝服务：
// 优先信 impact_type；否则看描述——提到 denial of service 且不含任何高影响词才算
func isDoSOnly(c CVEMeta) bool {
	it := strings.ToLower(c.ImpactType)
	if it != "" {
		dos := strings.Contains(it, "dos") || strings.Contains(it, "availability") || strings.Contains(it, "denial")
		high := containsAny(it, highImpactTerms) || strings.Contains(it, "integrity") ||
			strings.Contains(it, "confidentiality") || strings.Contains(it, "escalation") ||
			strings.Contains(it, "bypass") || strings.Contains(it, "disclosure")
		return dos && !high
	}
	desc := strings.ToLower(c.Description)
	if !strings.Contains(desc, "denial of service") {
		return false
	}
	return !containsAny(desc, highImpactTerms)
}

// ============================================================================
// 层 2：Repo 层
// ============================================================================

// scoreRepo 返回 (分数, 理由, 是否恶意)
func scoreRepo(r RepoMeta) (int, []string, bool) {
	score := 0
	reasons := []string{}

	name := r.FullName
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.ToLower(name)
	readmeDesc := r.Readme + "\n" + r.Description

	// 聚合待检测文本：readme + description + 前 20 个文件的 snippet
	codeBytes := int64(0)
	codeFiles := 0
	hasBinary := false
	snippetCount := 0
	var agg strings.Builder
	agg.WriteString(readmeDesc)
	for _, f := range r.Files {
		ext := strings.ToLower(path.Ext(f.Path))
		if _, bad := maliciousBinaryExts[ext]; bad {
			hasBinary = true
		}
		if _, ok := codeFileExts[ext]; ok {
			sz := f.Size
			if sz <= 0 {
				sz = int64(len(f.ContentSnippet))
			}
			codeBytes += sz
			codeFiles++
		}
		if f.ContentSnippet != "" && snippetCount < SnippetFileLimit {
			agg.WriteString("\n")
			agg.WriteString(f.ContentSnippet)
			snippetCount++
		}
	}
	aggText := agg.String()

	// ---- 2.1 恶意代码优先拦截（最高优先级）----
	malHits := matchLabels(compiledMalicious, aggText)
	malHits = filterHexHashBTC(aggText, malHits)
	malicious := len(malHits) >= MaliciousMinHits || (len(malHits) >= 1 && hasBinary)
	if len(malHits) > 0 || hasBinary {
		msg := fmt.Sprintf("[!] 恶意代码特征命中 %d 条（%s）", len(malHits), strings.Join(malHits, "、"))
		if hasBinary {
			msg += "；仓库含预编译二进制"
		}
		if malicious {
			reasons = append(reasons, msg+" —— 疑似木马/钓鱼仓库，隔离处置，禁止下载执行")
		} else {
			reasons = append(reasons, msg+" —— 未达恶意判定线，继续内容评估")
		}
	}

	// ---- 2.2 内容形态分类 ----
	switch {
	case codeFiles == 0 || codeBytes < MinCodeBytes:
		score += PlaceholderScore
		reasons = append(reasons, fmt.Sprintf("[-] 无有效代码文件或代码总量 < %dB (%d) —— 占位/纯文档仓库，没有可运行的 PoC", MinCodeBytes, PlaceholderScore))
	default:
		realHits := matchLabels(compiledWeaponized, aggText)
		detHits := matchLabels(compiledDetector, readmeDesc)
		switch {
		case len(realHits) >= maxInt(1, len(detHits)) && len(realHits) >= WeaponizedMinHits:
			score += WeaponizedScore
			reasons = append(reasons, fmt.Sprintf("[+] 命中 %d 条真实利用证据（%s）(+%d) —— 判定为武器化利用代码",
				len(realHits), truncateJoin(realHits, 5), WeaponizedScore))
		case len(realHits) >= maxInt(1, len(detHits)):
			score += RealPOCScore
			reasons = append(reasons, fmt.Sprintf("[+] 命中 %d 条真实利用证据（%s）(+%d) —— 判定为真实 PoC",
				len(realHits), truncateJoin(realHits, 5), RealPOCScore))
		case len(detHits) > 0:
			score += DetectorScore
			reasons = append(reasons, fmt.Sprintf("[-] 仅命中探测/扫描特征（%s）(%d) —— 版本检查/批量扫描器，不是利用代码",
				truncateJoin(detHits, 5), DetectorScore))
		default:
			score += AdvisoryScore
			reasons = append(reasons, fmt.Sprintf("[-] 无利用代码特征 (%d) —— 情报汇编/公告转载类仓库", AdvisoryScore))
		}
	}

	// ---- 2.3 其余信号 ----
	created, okC := parseFlexTime(r.CreatedAt)
	pushed, okP := parseFlexTime(r.PushedAt)
	if okC && okP {
		d := pushed.Sub(created)
		if d >= 0 && d <= OneDayWindow && r.Stars <= OneDayMaxStars && r.Forks == 0 {
			score += OneDayWonderScore
			reasons = append(reasons, fmt.Sprintf("[-] 一次性蹭热度仓库 (%d) —— 创建与最后提交相隔不足 1 天、几乎零关注零 fork", OneDayWonderScore))
		}
	}

	switch {
	case r.Stars >= StarsHigh:
		score += StarsHighScore
		reasons = append(reasons, fmt.Sprintf("[+] stars ≥ %d (+%d) —— 社区关注度较高，可信度加分", StarsHigh, StarsHighScore))
	case r.Stars >= StarsMid:
		score += StarsMidScore
		reasons = append(reasons, fmt.Sprintf("[+] stars ≥ %d (+%d) —— 有一定社区关注", StarsMid, StarsMidScore))
	}

	if hits := matchLabels(compiledScannerNm, name); len(hits) > 0 {
		score += ScannerNameScore
		reasons = append(reasons, fmt.Sprintf("[-] 仓库名为扫描器/笔记命名模式（%s）(%d) —— 更像检测规则/记录而非利用代码", strings.Join(hits, "、"), ScannerNameScore))
	}

	if len([]rune(r.Readme)) > AIShellMinReadmeLen && countEmoji(r.Readme) > AIShellMinEmoji && codeBytes < AIShellMaxCodeBytes {
		score += AIShellScore
		reasons = append(reasons, fmt.Sprintf("[-] AI 生成空壳特征 (%d) —— 超长 README + 大量 emoji + 几乎无实质代码，内容营销号", AIShellScore))
	}

	if r.OwnerPublicRepos != nil && *r.OwnerPublicRepos >= OwnerActiveMinRepos {
		score += OwnerActiveScore
		reasons = append(reasons, fmt.Sprintf("[+] 作者公开仓库 ≥ %d (+%d) —— 非一次性马甲账号", OwnerActiveMinRepos, OwnerActiveScore))
	}
	ownerCreated, okO := parseFlexTime(r.OwnerCreatedAt)
	if okC && okO {
		d := created.Sub(ownerCreated)
		if d >= 0 && d < SockPuppetWindow {
			score += SockPuppetScore
			reasons = append(reasons, fmt.Sprintf("[-] 疑似马甲号 (%d) —— 作者账号注册距仓库创建不足 7 天", SockPuppetScore))
		}
	}
	owner := r.FullName
	if i := strings.Index(owner, "/"); i > 0 {
		owner = owner[:i]
	}
	if _, ok := TrustedOrgs[strings.ToLower(owner)]; ok {
		score += TrustedOrgScore
		reasons = append(reasons, fmt.Sprintf("[+] 可信组织仓库（%s）(+%d) —— 知名安全研究机构出品，可信度大幅加分", owner, TrustedOrgScore))
	}
	if r.IsFork != nil && *r.IsFork {
		score += ForkScore
		reasons = append(reasons, fmt.Sprintf("[-] fork 仓库 (%d) —— 非原创内容", ForkScore))
	}
	if r.Archived != nil && *r.Archived {
		score += ArchivedScore
		reasons = append(reasons, fmt.Sprintf("[-] 已归档 (%d) —— 作者已停止维护", ArchivedScore))
	}

	return score, reasons, malicious
}

// filterHexHashBTC 比特币地址正则的降噪：纯十六进制长串更像 git sha1/shellcode，
// 不是 base58 比特币地址——仅在命中「比特币收款地址」且匹配串全是 hex 时剔除该误报。
func filterHexHashBTC(aggText string, hits []string) []string {
	out := hits[:0:0]
	btcRe := compileStrict(`[13][a-km-zA-HJ-NP-Z1-9]{26,33}`)
	for _, h := range hits {
		if h == "比特币收款地址" {
			realBTC := false
			for _, m := range btcRe.FindAllString(aggText, -1) {
				if !isAllHex(m) {
					realBTC = true
					break
				}
			}
			if !realBTC {
				continue
			}
		}
		out = append(out, h)
	}
	return out
}

func isAllHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

// ============================================================================
// 工具函数
// ============================================================================

func matchLabels(compiled []compiledPattern, text string) []string {
	var out []string
	for _, p := range compiled {
		if p.re.MatchString(text) {
			out = append(out, p.label)
		}
	}
	return out
}

func hasAnyCWE(cwes []int, set map[int]struct{}) bool {
	for _, c := range cwes {
		if _, ok := set[c]; ok {
			return true
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func dedupe(in []string) []string {
	// 重复清单收敛：按出现顺序保留首次出现。
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func signOf(s int) string {
	if s < 0 {
		return "-"
	}
	return "+"
}

func countEmoji(s string) int { return len(emojiRe.FindAllString(s, -1)) }

func truncateJoin(in []string, n int) string {
	if len(in) > n {
		return strings.Join(in[:n], "、") + " 等"
	}
	return strings.Join(in, "、")
}

// parseFlexTime 兼容 RFC3339 与纯日期，失败返回 false（该信号不参与）
func parseFlexTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

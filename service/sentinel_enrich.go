package service

// 发现富化流水线（enrichment）。
//
// 目标：判定命中/人工确认之后，产物链不再只是 patch，而是自动补齐三类知识：
//  1. POC 库复用 —— 按 vuln_class 关键词与 CVE 检索既有 nuclei 模板，命中即
//     挂为 kind=poc 的 draft 产物（铁律不变：人工 verified 后才可复现/下载）；
//  2. 复现指南 —— 依据判定（攻击路径/影响/修复证据/摘录）+ 提交信息 + POC 命中，
//     确定性拼装 kind=report、title=repro-guide 产物，不依赖模型调用；
//  3. 自动转 nuclei —— finding 确认时（或 S 级命中时）若尚无 nuclei 产物，
//     自动草拟模板落 draft，复用 GenerateNucleiTemplate 与人工审核闸门。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// sentinelClassPocKeywords 把 Sentinel 漏洞类别映射到 POC 库检索关键词
// （关键词命中 name/description/cve_id 的 ilike 检索，见 POCFilter.Keyword）。
var sentinelClassPocKeywords = map[string][]string{
	"SQLI":             {"sqli", "sql injection", "sql注入"},
	"CMDI":             {"command injection", "命令注入", "rce"},
	"RCE":              {"rce", "remote code execution", "代码执行"},
	"INJECTION":        {"injection", "ssti", "注入"},
	"SSRF":             {"ssrf"},
	"XXE":              {"xxe"},
	"PATH_TRAVERSAL":   {"path traversal", "directory traversal", "任意文件", "lfi"},
	"DESERIALIZATION":  {"deserialization", "反序列化", "unserialize"},
	"AUTH_BYPASS":      {"auth bypass", "authentication bypass", "未授权", "鉴权绕过"},
	"PRIV_ESC":         {"privilege escalation", "提权"},
	"INFO_LEAK":        {"information disclosure", "信息泄露"},
	"DOS":              {"dos", "denial of service", "拒绝服务"},
	"OOB_READ":         {"out of bounds", "越界"},
	"OOB_WRITE":        {"out of bounds", "越界写"},
	"BUFFER_OVERFLOW":  {"buffer overflow", "缓冲区溢出", "overflow"},
	"INTEGER_OVERFLOW": {"integer overflow", "整数溢出"},
	"NULL_DEREF":       {"null dereference", "空指针"},
	"TYPE_CONFUSION":   {"type confusion", "类型混淆"},
	"UAF":              {"use after free", "uaf"},
	"DOUBLE_FREE":      {"double free"},
	"RACE":             {"race condition", "竞态"},
	"OTHER":            {},
}

// sentinelClassReproTips 是各类别的复现观察点提示，进 repro-guide。
var sentinelClassReproTips = map[string]string{
	"SQLI":             "观察注入点的报错回显/布尔差异/延时差异；时间盲注与 UNION 回显是最直接的确认手段。",
	"CMDI":             "观察命令拼接点的执行效果（sleep、回显、DNS/HTTP 外带）；注意确认不是参数注入误判。",
	"RCE":              "观察代码/表达式求值点的执行效果；优先用无副作用的求值（如算术表达式）确认可达性。",
	"INJECTION":        "观察模板/表达式引擎的求值行为，用引擎特征payload确认注入面。",
	"SSRF":             "观察服务端是否向受控地址发起请求（DNS/HTTP 外带回连）；区分 302 跳转与直接请求。",
	"XXE":              "观察 XML 解析器是否处理外部实体（文件读回显或外带 DTD）。",
	"PATH_TRAVERSAL":   "观察路径归一化前的原始拼接；用目录跳跃读已知文件确认穿越成功。",
	"DESERIALIZATION":  "观察反序列化入口的 gadget 链触发痕迹；先用无害 marker 类确认反序列化可达。",
	"AUTH_BYPASS":      "对比携带/不携带凭证的请求差异，确认绕过路径稳定可复现而非缓存残留。",
	"PRIV_ESC":         "以低权限身份触发提权路径，核对权限前后的能力差异。",
	"INFO_LEAK":        "确认敏感字段在响应/日志/错误页中的出现位置与是否受开关控制。",
	"DOS":              "用最小输入复现资源放大效应（内存/CPU/慢请求），计量放大比即可，勿打满目标。",
	"OOB_READ":         "构造刚好越界一元素的输入，观察未初始化/相邻内存内容泄出。",
	"OOB_WRITE":        "构造越界写并观察相邻内存破坏迹象（崩溃地址、被覆写对象）。",
	"BUFFER_OVERFLOW":  "用超长输入触发边界，观察栈/堆崩溃地址是否落在输入可控范围。",
	"INTEGER_OVERFLOW": "用接近整数边界的输入触发回绕，观察下游长度/索引是否失真。",
	"NULL_DEREF":       "构造使前置条件失败、指针未赋值的输入，观察空指针崩溃。",
	"TYPE_CONFUSION":   "跨类型访问同一对象，观察字段解释错位引发的异常。",
	"UAF":              "先释放目标对象再触发悬垂引用，观察崩溃或逻辑异常；堆风水稳定化可选。",
	"DOUBLE_FREE":      "重复释放同一对象，观察分配器断言/崩溃。",
	"RACE":             "并发打满窗口期（线程数×重试），统计命中频率确认竞态窗口存在。",
	"OTHER":            "依据攻击路径选择最直接的可观测副作用作为确认信号。",
}

var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// enrichFinding 是发现富化的同步入口：POC 库命中 → 复现指南 → （可选）自动转
// nuclei。所有步骤只记日志、绝不向上抛错——富化失败不影响判定/确认主流程。
func enrichFinding(ctx context.Context, findingID int64, autoNuclei bool) {
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		log.Printf("[Sentinel] 富化跳过：finding=%d 不存在: %v", findingID, err)
		return
	}

	// 1. POC 库命中并挂为 draft 产物（复用既有模板，不再从零造轮子）。
	matched := matchPocLibrary(ctx, f, 3)
	if n := attachMatchedPocArtifacts(ctx, store, f, matched); n > 0 {
		log.Printf("[Sentinel] POC 库命中挂载 finding=%d 命中=%d", f.ID, n)
	}

	// 2. 复现指南（确定性拼装，零模型调用）。
	if err := ensureReproGuide(ctx, store, f, matched); err != nil {
		log.Printf("[Sentinel] 复现指南生成失败 finding=%d: %v", f.ID, err)
	}

	// 3. 自动转 nuclei：仅在尚无 nuclei 产物时草拟，落 draft 待人工审核。
	if autoNuclei {
		arts, err := store.ListArtifacts(ctx, f.ID)
		if err != nil {
			log.Printf("[Sentinel] 富化查询产物失败 finding=%d: %v", f.ID, err)
			return
		}
		for _, a := range arts {
			if a.Kind == "nuclei" {
				return
			}
		}
		a, err := GenerateNucleiTemplate(ctx, f.ID)
		if err != nil {
			log.Printf("[Sentinel] 自动生成 nuclei 失败 finding=%d: %v", f.ID, err)
			return
		}
		log.Printf("[Sentinel] 自动生成 nuclei 完成 finding=%d artifact=%d (%s)", f.ID, a.ID, a.Title)
	}
}

// enrichFindingAsync 在后台执行富化：LLM 调用（nuclei 草拟）耗时可观，
// 不应阻塞确认接口或判定 worker。富化永不重试——产物可随时人工补齐。
func enrichFindingAsync(findingID int64, autoNuclei bool) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		enrichFinding(ctx, findingID, autoNuclei)
	}()
}

// matchPocLibrary 按 vuln_class 关键词与提交/判定中的 CVE 检索 POC 库，
// 返回去重后的命中列表（最多 limit 条）。检索失败只降级为「无命中」。
func matchPocLibrary(ctx context.Context, f *repo.CommitFinding, limit int) []*models.POC {
	store := repo.Default().Sentinel()
	commit, err := store.GetCommit(ctx, f.CommitID)
	if err != nil {
		log.Printf("[Sentinel] POC 检索取提交失败 finding=%d: %v", f.ID, err)
		commit = &repo.GitCommit{}
	}
	reasoning := ""
	if judgment, err := store.GetJudgment(ctx, f.CommitID); err == nil && judgment != nil {
		reasoning = judgment.Reasoning
	}

	// 关键词队列：类别映射在前，CVE 编号在后（CVE 命中最精确，放后面兜底去重）。
	keywords := append([]string{}, sentinelClassPocKeywords[f.VulnClass]...)
	seenCVE := map[string]bool{}
	for _, cve := range cvePattern.FindAllString(commit.Subject+" "+commit.Message+" "+reasoning, 5) {
		cve = strings.ToUpper(cve)
		if !seenCVE[cve] {
			seenCVE[cve] = true
			keywords = append(keywords, cve)
		}
	}

	enabled := true
	pocs := repo.Default().Pocs()
	seen := map[string]bool{}
	var out []*models.POC
	for _, kw := range keywords {
		if len(out) >= limit {
			break
		}
		items, _, err := pocs.List(ctx, repo.POCFilter{
			Type: "nuclei", Keyword: kw, Enabled: &enabled, Page: 1, PageSize: limit * 2,
		})
		if err != nil {
			log.Printf("[Sentinel] POC 库检索失败 finding=%d keyword=%q: %v", f.ID, kw, err)
			continue
		}
		for _, p := range items {
			key := p.ID.Hex()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, p)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

// attachMatchedPocArtifacts 把命中的 POC 挂为 finding 下 kind=poc 的 draft
// 产物（标题注明来源模板，幂等：同标题不重复挂载）。返回实际挂载数。
func attachMatchedPocArtifacts(ctx context.Context, store *repo.Sentinel, f *repo.CommitFinding, matched []*models.POC) int {
	if len(matched) == 0 {
		return 0
	}
	arts, err := store.ListArtifacts(ctx, f.ID)
	if err != nil {
		log.Printf("[Sentinel] POC 挂载查询产物失败 finding=%d: %v", f.ID, err)
		return 0
	}
	existing := make(map[string]bool, len(arts))
	for _, a := range arts {
		existing[a.Title] = true
	}
	attached := 0
	for _, p := range matched {
		title := fmt.Sprintf("poc: %s（POC 库命中: %s）", p.TemplateID, p.Name)
		if existing[title] || strings.TrimSpace(p.Content) == "" {
			continue
		}
		if _, err := store.InsertArtifact(ctx, &repo.CommitArtifact{
			FindingID: f.ID,
			Kind:      "poc",
			Title:     title,
			Status:    "draft",
			Content:   p.Content,
		}); err != nil {
			log.Printf("[Sentinel] POC 挂载失败 finding=%d template=%s: %v", f.ID, p.TemplateID, err)
			continue
		}
		attached++
	}
	return attached
}

// ensureReproGuide 幂等生成 kind=report、title=repro-guide 的复现指南产物。
func ensureReproGuide(ctx context.Context, store *repo.Sentinel, f *repo.CommitFinding, matched []*models.POC) error {
	arts, err := store.ListArtifacts(ctx, f.ID)
	if err != nil {
		return err
	}
	for _, a := range arts {
		if a.Kind == "report" && strings.EqualFold(a.Title, "repro-guide") {
			return nil
		}
	}
	commit, err := store.GetCommit(ctx, f.CommitID)
	if err != nil {
		return err
	}
	judgment, _ := store.GetJudgment(ctx, f.CommitID)

	content := buildReproGuide(f, commit, judgment, matched)
	_, err = store.InsertArtifact(ctx, &repo.CommitArtifact{
		FindingID: f.ID,
		Kind:      "report",
		Title:     "repro-guide",
		Status:    "draft",
		Content:   content,
	})
	return err
}

// buildReproGuide 从判定与提交信息确定性拼装复现指南（Markdown）。
// 全部内容来自判定落库字段与提交元数据，不引入任何模型生成文本。
func buildReproGuide(f *repo.CommitFinding, commit *repo.GitCommit, judgment *repo.CommitJudgment, matched []*models.POC) string {
	short := commit.SHA
	if len(short) > 10 {
		short = short[:10]
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# 复现指南：%s\n\n", f.Title)
	fmt.Fprintf(&b, "> 本指南由 Sentinel 依据修复提交 `%s` 的判定结论自动拼装，供授权环境复现使用。\n\n", short)

	b.WriteString("## 漏洞概要\n\n")
	fmt.Fprintf(&b, "- **漏洞类别**：%s\n- **严重度**：%s\n", f.VulnClass, f.Severity)
	fmt.Fprintf(&b, "- **仓库**：%s\n- **修复提交**：`%s`（%s）\n", commit.RepoFullName, short, commit.Subject)
	if judgment != nil {
		fmt.Fprintf(&b, "- **判定模型**：%s\n- **置信度**：%.2f\n", judgment.Model, judgment.Confidence)
	}

	attackPath, impact, fixEvidence := "判定未提供", "判定未提供", "判定未提供"
	if judgment != nil {
		if s := strings.TrimSpace(judgment.AttackPath); s != "" {
			attackPath = s
		}
		if s := strings.TrimSpace(judgment.Impact); s != "" {
			impact = s
		}
		if s := strings.TrimSpace(judgment.FixEvidence); s != "" {
			fixEvidence = s
		}
	}
	fmt.Fprintf(&b, "\n## 攻击路径\n\n%s\n\n", attackPath)
	fmt.Fprintf(&b, "## 影响与前置条件\n\n%s\n\n", impact)
	fmt.Fprintf(&b, "## 修复证据（diff 消除的攻击链环节）\n\n%s\n\n", fixEvidence)

	if snippets := decodeSnippets(judgment); len(snippets) > 0 {
		b.WriteString("## 关键代码摘录\n\n```diff\n")
		for _, s := range snippets {
			b.WriteString(s)
			b.WriteString("\n")
		}
		b.WriteString("```\n\n")
	}

	fmt.Fprintf(&b, "## 复现步骤\n\n")
	fmt.Fprintf(&b, "1. **检出漏洞版本**：`git clone <仓库地址> && git checkout %s~1`（修复提交的父提交，即漏洞存在版本）。\n", short)
	fmt.Fprintf(&b, "2. **定位攻击面**：按上述攻击路径找到外部入口与危险汇聚点（文件:函数）。\n")
	fmt.Fprintf(&b, "3. **触发漏洞**：优先使用下方「POC 库命中」或产物中心 verified 的 kind=poc 产物；没有现成 PoC 时，按攻击路径手写最小触发请求。\n")
	fmt.Fprintf(&b, "4. **观察点**：%s\n", firstNonEmptyString(sentinelClassReproTips[f.VulnClass], sentinelClassReproTips["OTHER"]))
	fmt.Fprintf(&b, "5. **验证修复**：`git checkout %s`（修复版本）重放同一 PoC，确认不再触发。\n\n", short)

	b.WriteString("## POC 库命中\n\n")
	if len(matched) == 0 {
		b.WriteString("POC 库中没有该类别的现成模板；可让产物中心的 nuclei 草稿经人工审核后补位。\n\n")
	} else {
		for _, p := range matched {
			fmt.Fprintf(&b, "- `%s` %s（%s，已挂为 draft 产物，人工 verified 后可用于复现）\n", p.TemplateID, p.Name, p.Severity)
		}
		b.WriteString("\n")
	}

	b.WriteString("## 差分复现（pocsmith）\n\n")
	b.WriteString("1. 在产物中心准备两份产物：\n")
	b.WriteString("   - kind=poc、status=verified 的 PoC 文件（标题可用 `path=<文件名>` 声明容器内路径）；\n")
	b.WriteString("   - kind=report、title=repro-plan 的构建计划 JSON。\n")
	b.WriteString("2. repro-plan 格式：\n\n```json\n")
	b.WriteString("{\"vuln_image\":\"<修复前镜像>\",\"fix_image\":\"<修复后镜像>\",\"poc_path\":\"poc.txt\",\"poc_cmd\":[\"/poc/poc.txt\"]}\n")
	b.WriteString("```\n\n")
	b.WriteString("3. 同一 PoC 在 vuln/fix 双镜像分别执行：vuln 稳定硬崩溃且日志含 `__POC_START__`、fix 正常 → `differential-ok`，机器证据落 repro_log。\n\n")

	b.WriteString("## nuclei 验证\n\n")
	b.WriteString("产物中心的 nuclei 模板（LLM 依修复 diff 草拟）人工 verified 后，可发布进 PoC 库，对目标站点验证：\n\n```bash\nnuclei -t <模板.yaml> -u <目标>\n```\n\n")
	b.WriteString("目标不确定时模板用 `{{BaseURL}}` 占位；matcher 从保守配置起步，宁可漏报不误报。\n\n")
	b.WriteString("---\n*仅供授权安全测试与漏洞回归验证使用。*\n")
	return b.String()
}

// decodeSnippets 把判定的 evidence_snippets JSON 数组展开成纯文本列表。
func decodeSnippets(judgment *repo.CommitJudgment) []string {
	if judgment == nil || len(judgment.Snippets) == 0 {
		return nil
	}
	var snippets []string
	if err := json.Unmarshal(judgment.Snippets, &snippets); err != nil {
		return nil
	}
	out := snippets[:0]
	for _, s := range snippets {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

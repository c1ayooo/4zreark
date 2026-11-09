package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// CommitSentinel 判定层（v0.3 §7.4）。
//
// 编排交给 eino 的 compose.Graph（service/sentinel_judge_graph.go），模型交给
// eino-ext 的 openai ChatModel（internal/llm）。本文件只负责：
//   - 判定 prompt 与装箱输入；
//   - 输出解析与 vuln_class 枚举校验（decode 回调，图内会拿错误重试）；
//   - evidence/evidence_snippets 对 diff 的防幻觉校验与置信度打折；
//   - 落库幂等（judgment 表 UNIQUE(commit_id, model)）与 finding 生成。

// SentinelVulnClasses 是判定输出的漏洞类型枚举。
//
// INJECTION 拆分历史：SQL 注入 / 命令注入 / 远程代码执行原先全部挤在 INJECTION
// 一个桶里，前端没法按「SQL 注入」「RCE」筛选。拆出 SQLI / CMDI / RCE 三个
// 枚举后，INJECTION 保留给 SSTI / LDAP / 表达式注入等其余注入形态。
// 历史数据不回填：筛选 SQLI/CMDI 时后端自动把 INJECTION 一并算进（见 repo 层）。
var SentinelVulnClasses = []string{
	"OOB_READ", "OOB_WRITE", "UAF", "DOUBLE_FREE", "BUFFER_OVERFLOW", "INTEGER_OVERFLOW",
	"NULL_DEREF", "TYPE_CONFUSION", "RACE", "SQLI", "CMDI", "RCE", "INJECTION",
	"SSRF", "XXE", "PATH_TRAVERSAL", "DESERIALIZATION", "AUTH_BYPASS", "PRIV_ESC",
	"INFO_LEAK", "DOS", "OTHER",
}

var sentinelVulnClassSet = func() map[string]bool {
	m := make(map[string]bool, len(SentinelVulnClasses))
	for _, v := range SentinelVulnClasses {
		m[v] = true
	}
	return m
}()

var sentinelSeveritySet = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

const sentinelJudgeSystemPrompt = `你是资深安全研究员，任务是审计一个 Git 提交：判断它是否在修复安全漏洞，并给出可复核、可交付的结论。

只输出一个 JSON 对象，不要解释，不要 markdown 代码块。字段：
{
  "is_security_fix": true/false,
  "vuln_class": 枚举值,
  "severity": "info|low|medium|high|critical",
  "confidence": 0~1 的小数,
  "title": "描述性漏洞标题",
  "attack_path": "攻击路径：入口 → 传播 → 汇聚点",
  "impact": "影响与可利用条件",
  "fix_evidence": "修复 diff 消除了攻击链哪一环",
  "reasoning": "2~4 句结论与关键依据",
  "evidence": ["@@ -142,7 +142,9 @@ ..."],
  "evidence_snippets": ["+ \tif (attacker_len > sizeof(buf)) { ... }"]
}

规则：
1. vuln_class 只能取以下之一：OOB_READ OOB_WRITE UAF DOUBLE_FREE BUFFER_OVERFLOW
   INTEGER_OVERFLOW NULL_DEREF TYPE_CONFUSION RACE SQLI CMDI RCE INJECTION SSRF XXE
   PATH_TRAVERSAL DESERIALIZATION AUTH_BYPASS PRIV_ESC INFO_LEAK DOS OTHER。
   SQLI=SQL 注入；CMDI=命令注入；RCE=远程代码/命令执行（含反序列化、模板注入等
   直接落到代码执行的形态）；INJECTION=其余注入（SSTI、LDAP、表达式注入等）。
2. severity 按可利用性判定，不要凭感觉：
   critical=远程可达且直接 RCE 或完整认证绕过；high=远程可利用的注入/反序列化/
   越界写/SSRF 打内网；medium=需要特定前置条件或影响有限（越界读、信息泄露、DoS）；
   low/info=防御性问题或实际几乎不可利用。
3. is_security_fix=true 时必须完整给出：
   - title：一句可读的漏洞标题（组件 + 后果），不要只写「文件:函数」；
   - attack_path：从外部入口到危险 sink 的完整路径，标注文件/函数；
   - impact：攻击者在什么条件下能造成什么后果；
   - fix_evidence：说明 diff 到底修掉了攻击链哪一环（校验/过滤/白名单/边界检查）；
   - evidence_snippets：从 diff 原样摘录 2~4 段关键 +/- 代码行，每段不超过 5 行，
     逐字复制，不许改写、缩写或编造。
   is_security_fix=false 时上述五个字段分别返回空字符串/空数组，reasoning 一句话即可。
4. evidence 必须逐字复制 diff 中真实的 hunk 头（以 @@ 开头的那一行）；
   抄不出真实 hunk 头、或摘录的代码行在 diff 里不存在，结论会被降权。
5. 普通重构、加日志、改注释、性能优化、依赖升级都不算安全修复。
6. 只依据给出的 diff 判断，不要臆测未展示的代码；证据不足时降低 confidence，
   不要编造细节来凑完整度。`

// SentinelJudge 负责单条提交的判定与落库。
// 判定编排本身在 SentinelEvaluator（filter → prep → eino graph），这里只管持久化。
type SentinelJudge struct {
	store   *repo.Sentinel
	usage   *repo.LLMUsageRepo
	eval    *SentinelEvaluator
	evalErr error
	llmCfg  config.LLMConfig
	sentCfg config.SentinelConfig

	// 模型配置可热更（设置 → 模型接入）：fingerprint 变了就重建 evaluator。
	mu          sync.Mutex
	fingerprint string
}

// NewSentinelJudge 构造判定服务：真实模型 → eino ChatModel；无密钥 → 桩模型。
// 启动配置只作为兜底，实际每次判定读「设置 → 模型接入」（DB 优先）。
func NewSentinelJudge(cfg config.SentinelConfig, llmCfg config.LLMConfig) *SentinelJudge {
	j := &SentinelJudge{
		store:   repo.Default().Sentinel(),
		usage:   repo.Default().LLMUsage(),
		llmCfg:  llmCfg,
		sentCfg: cfg,
	}
	live := EffectiveLLMConfig(context.Background(), llmCfg)
	j.fingerprint = llmFingerprint(live)
	eval, err := NewSentinelEvaluator(cfg, live)
	if err != nil {
		j.evalErr = err
		return j
	}
	j.eval = eval
	return j
}

// llmFingerprint 是模型配置的身份：只有终结点/模型/密钥变化才值得重建图。
func llmFingerprint(cfg config.LLMConfig) string {
	return fmt.Sprintf("%s|%s|%d", cfg.BaseURL, cfg.Model, len(cfg.APIKey))
}

// currentEvaluator 返回当前配置对应的评测器；配置变了就地重建。
func (j *SentinelJudge) currentEvaluator(ctx context.Context) (*SentinelEvaluator, error) {
	live := EffectiveLLMConfig(ctx, j.llmCfg)
	fp := llmFingerprint(live)

	j.mu.Lock()
	defer j.mu.Unlock()
	if fp == j.fingerprint && j.eval != nil {
		return j.eval, j.evalErr
	}

	eval, err := NewSentinelEvaluator(j.sentCfg, live)
	j.fingerprint = fp
	if err != nil {
		log.Printf("[Sentinel] 判定模型切换失败，沿用当前模型: %v", err)
		if j.eval == nil {
			j.evalErr = err
			return nil, err
		}
		return j.eval, nil
	}
	j.eval, j.evalErr = eval, nil
	log.Printf("[Sentinel] 判定模型已切换为 %s（来源：设置 → 模型接入）", eval.ModelName())
	return j.eval, nil
}

// Judge 判定一条提交并落库；已判定过时直接返回已有记录（永不重判）。
// 每次判定建一个 run_type=judge 的批次并写 judge_start/done/skipped/failed 事件，
// 前端批次视图据此回放判定过程；命中安全修复时旁路发一条 IM 通知。
func (j *SentinelJudge) Judge(ctx context.Context, commitID int64) (judgment *repo.CommitJudgment, err error) {
	commit, err := j.store.GetCommit(ctx, commitID)
	if err != nil {
		return nil, err
	}
	// 「永不重判」按模型维度判断：外部 agent 经 MCP 提交的判定（model=agent:*）
	// 与内部判定在 UNIQUE(commit_id, model) 下并列共存，谁也不能把谁顶掉或挡住。
	if eval, evalErr := j.currentEvaluator(ctx); evalErr == nil {
		if existing, err := j.store.GetJudgmentByModel(ctx, commit.ID, eval.ModelName()); err == nil && existing != nil {
			return existing, nil
		}
	}

	runID, runErr := j.store.CreateRun(ctx, &repo.SentinelRun{
		RunType: "judge", RepoID: &commit.RepoID, Status: "running", Total: 1,
	})
	if runErr != nil {
		log.Printf("[Sentinel] 创建判定批次失败 commit=%d: %v", commit.ID, runErr)
	} else {
		_ = j.store.UpdateRun(ctx, runID, map[string]interface{}{"started_at": time.Now()})
	}
	emit := func(level, kind, message string, payload map[string]interface{}) {
		if runErr != nil {
			return
		}
		p, _ := json.Marshal(payload)
		if _, err := j.store.AppendRunEvent(ctx, &repo.SentinelRunEvent{
			RunID: runID, Level: level, Kind: kind, Message: message, Payload: p,
		}); err != nil {
			log.Printf("[Sentinel] 写判定事件失败 run=%d: %v", runID, err)
		}
	}
	finishRun := func(status string, processed int, runErrMsg string) {
		if runErr != nil {
			return
		}
		fields := map[string]interface{}{"status": status, "processed": processed, "finished_at": time.Now()}
		if runErrMsg != "" {
			fields["error"] = runErrMsg
		}
		if err := j.store.UpdateRun(ctx, runID, fields); err != nil {
			log.Printf("[Sentinel] 收尾判定批次失败 run=%d: %v", runID, err)
		}
	}
	short := commit.SHA
	if len(short) > 10 {
		short = short[:10]
	}
	emit("info", "judge_start", fmt.Sprintf("%s %s", short, commit.Subject), map[string]interface{}{
		"repo": commit.RepoFullName, "sha": commit.SHA,
	})
	// 出错路径统一在这里收尾批次；成功路径显式 finishRun，不会走到这里。
	defer func() {
		if err != nil {
			emit("error", "judge_failed", err.Error(), nil)
			finishRun("failed", 0, err.Error())
		}
	}()

	eval, evalErr := j.currentEvaluator(ctx)
	if evalErr != nil {
		return nil, evalErr
	}

	outcome, err := eval.Evaluate(ctx, commit)
	if err != nil {
		return nil, err
	}
	if outcome.Skipped {
		if err := j.store.MarkCommitStatus(ctx, commit.ID, "skipped", outcome.SkipReason); err != nil {
			return nil, err
		}
		emit("info", "judge_skipped", fmt.Sprintf("跳过判定: %s", outcome.SkipReason), nil)
		finishRun("completed", 0, "")
		return nil, nil
	}

	if outcome.Verdict == nil || outcome.Run == nil {
		return nil, errors.New("判定结果为空")
	}
	verdict := outcome.Verdict
	out := outcome.Run
	partial := outcome.Partial

	evidenceJSON, _ := json.Marshal(verdict.Evidence)
	snippetsJSON, _ := json.Marshal(verdict.Snippets)
	judgment = &repo.CommitJudgment{
		CommitID:         commit.ID,
		Model:            eval.ModelName(),
		IsSecurityFix:    verdict.IsSecurityFix,
		VulnClass:        verdict.VulnClass,
		Severity:         verdict.Severity,
		Confidence:       verdict.Confidence,
		Title:            verdict.Title,
		Reasoning:        verdict.Reasoning,
		Evidence:         evidenceJSON,
		AttackPath:       verdict.AttackPath,
		Impact:           verdict.Impact,
		FixEvidence:      verdict.FixEvidence,
		Snippets:         snippetsJSON,
		Partial:          partial,
		PromptTokens:     out.PromptTokens,
		CompletionTokens: out.CompletionTokens,
	}

	id, inserted, err := j.store.InsertJudgment(ctx, judgment)
	if err != nil {
		return nil, err
	}
	if !inserted {
		// 并发下另一个 worker 已经写入：以库里该模型那条为准。
		emit("info", "judge_skipped", "并发重复判定，以库里记录为准", nil)
		finishRun("completed", 0, "")
		return j.store.GetJudgmentByModel(ctx, commit.ID, eval.ModelName())
	}
	judgment.ID = id

	status := "judged"
	if partial {
		status = "failed"
	}
	if err := j.store.MarkCommitStatus(ctx, commit.ID, status, ""); err != nil {
		log.Printf("[Sentinel] 更新提交状态失败 commit=%d: %v", commit.ID, err)
	}

	if verdict.IsSecurityFix {
		grade := gradeForVerdict(verdict.IsSecurityFix, verdict.VulnClass, verdict.Severity)
		findingID, err := j.store.CreateFinding(ctx, &repo.CommitFinding{
			CommitID:   commit.ID,
			JudgmentID: &judgment.ID,
			VulnClass:  verdict.VulnClass,
			Severity:   verdict.Severity,
			Status:     "open",
			Title:      verdict.Title,
			Detail:     verdict.Reasoning,
			Grade:      grade,
		})
		if err != nil {
			log.Printf("[Sentinel] 写入发现失败 commit=%d: %v", commit.ID, err)
		}
		// S 级（critical + 注入/SSRF/反序列化形态）：自动草拟 nuclei 候选落 draft，
		// 人工 verified 后才可发布/复现——铁律不自动越过。
		if err == nil && grade == "S" {
			if a, gerr := GenerateNucleiTemplate(ctx, findingID); gerr != nil {
				log.Printf("[Sentinel] S 级自动生成 nuclei 失败 finding=%d: %v", findingID, gerr)
			} else {
				log.Printf("[Sentinel] S 级自动生成 nuclei 完成 finding=%d artifact=%d (%s)",
					findingID, a.ID, a.Title)
			}
		}
		// 命中即通知：级别随 severity，渠道侧可用 MinLevel 过滤降级噪音。
		notifyJudgeHit(commit, verdict, judgment.ID)
	}

	emit("info", "judge_done", fmt.Sprintf("判定完成: %s（%s/%s）",
		map[bool]string{true: "安全修复", false: "非安全修复"}[verdict.IsSecurityFix],
		verdict.VulnClass, verdict.Severity), map[string]interface{}{
		"is_security_fix":   verdict.IsSecurityFix,
		"vuln_class":        verdict.VulnClass,
		"severity":          verdict.Severity,
		"confidence":        verdict.Confidence,
		"title":             verdict.Title,
		"partial":           partial,
		"prompt_tokens":     out.PromptTokens,
		"completion_tokens": out.CompletionTokens,
	})
	finishRun("completed", 1, "")

	j.recordUsage(ctx, out)
	return judgment, nil
}

// decodeJudgeVerdict 是判定图的 decode 回调：解析 + 枚举校验。
// 返回的错误会被图回灌给模型，触发一次重试。
func decodeJudgeVerdict(content string) (*JudgeVerdict, error) {
	var raw struct {
		IsSecurityFix    bool     `json:"is_security_fix"`
		VulnClass        string   `json:"vuln_class"`
		Confidence       float64  `json:"confidence"`
		Severity         string   `json:"severity"`
		Title            string   `json:"title"`
		Component        string   `json:"component"`
		AttackPath       string   `json:"attack_path"`
		Impact           string   `json:"impact"`
		FixEvidence      string   `json:"fix_evidence"`
		Reasoning        string   `json:"reasoning"`
		Evidence         []string `json:"evidence"`
		EvidenceSnippets []string `json:"evidence_snippets"`
	}
	if err := json.Unmarshal([]byte(stripJSONFence(content)), &raw); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %v", err)
	}

	vulnClass := strings.ToUpper(strings.TrimSpace(raw.VulnClass))
	if vulnClass == "" {
		vulnClass = "OTHER"
	}
	if !sentinelVulnClassSet[vulnClass] {
		return nil, fmt.Errorf("vuln_class %q 不在枚举内", raw.VulnClass)
	}

	severity := strings.ToLower(strings.TrimSpace(raw.Severity))
	if severity == "" {
		severity = "info"
	}
	if !sentinelSeveritySet[severity] {
		return nil, fmt.Errorf("severity %q 不合法", raw.Severity)
	}

	confidence := raw.Confidence
	if math.IsNaN(confidence) || confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	evidence := raw.Evidence
	if evidence == nil {
		evidence = []string{}
	}
	snippets := raw.EvidenceSnippets
	if snippets == nil {
		snippets = []string{}
	}

	// 旧 prompt 时代用 component 当标题；新 prompt 直接给 title，两者兼容。
	title := strings.TrimSpace(raw.Title)
	if title == "" {
		title = strings.TrimSpace(raw.Component)
	}
	if title == "" {
		title = vulnClass
	}

	v := &JudgeVerdict{
		IsSecurityFix: raw.IsSecurityFix,
		VulnClass:     vulnClass,
		Severity:      severity,
		Confidence:    confidence,
		Title:         title,
		Reasoning:     strings.TrimSpace(raw.Reasoning),
		Evidence:      evidence,
	}
	if raw.IsSecurityFix {
		// 三段式说明只在命中时保留；未命中时模型可能仍抄了 diff 细节，丢弃以免误导。
		v.AttackPath = strings.TrimSpace(raw.AttackPath)
		v.Impact = strings.TrimSpace(raw.Impact)
		v.FixEvidence = strings.TrimSpace(raw.FixEvidence)
		v.Snippets = snippets
	}
	return v, nil
}

// applyEvidenceCheck 校验证据是否真的对得上 diff：
//   - evidence 必须能对上真实 hunk 头；
//   - evidence_snippets 摘录的代码行必须在 diff 里逐字存在。
//
// 任一项全军覆没则置信度减半，防止模型编造"看起来很像"的证据。
func applyEvidenceCheck(v *JudgeVerdict, hunkHeaders []string, diffLines []string) *JudgeVerdict {
	if v == nil || !v.IsSecurityFix || len(hunkHeaders) == 0 {
		return v
	}
	diminish := func(reason string) {
		v.Confidence = math.Round(v.Confidence*0.5*1000) / 1000
		v.Reasoning = strings.TrimSpace(v.Reasoning + "（" + reason + "，置信度已减半）")
	}

	matched := 0
	for _, ev := range v.Evidence {
		if evidenceMatches(ev, hunkHeaders) {
			matched++
		}
	}
	if matched == 0 {
		diminish("evidence 无法对上真实 hunk")
	}

	// snippets 为空不算作弊（旧判定没有该字段）；给了但全部对不上才算编造。
	if len(v.Snippets) > 0 && !snippetsMatchDiff(v.Snippets, diffLines) {
		diminish("evidence_snippets 摘录的代码行不在 diff 中")
	}
	return v
}

// evidenceMatches 归一化空白后做包含/前缀匹配，容忍模型复制时的空格差异。
func evidenceMatches(evidence string, hunkHeaders []string) bool {
	ev := normalizeSpace(evidence)
	if ev == "" {
		return false
	}
	for _, h := range hunkHeaders {
		hh := normalizeSpace(h)
		if ev == hh || strings.Contains(hh, ev) || strings.HasPrefix(hh, ev) {
			return true
		}
	}
	return false
}

// snippetsMatchDiff 判断摘录片段是否至少有一条能在 diff 中逐字找到。
// 多行片段折叠成一行（空白归一）后做子串匹配：模型常把相邻行合并摘录。
func snippetsMatchDiff(snippets, diffLines []string) bool {
	hay := normalizeSpace(strings.Join(diffLines, " "))
	if hay == "" {
		return false
	}
	for _, snip := range snippets {
		needle := normalizeSpace(snip)
		if needle != "" && strings.Contains(hay, needle) {
			return true
		}
	}
	return false
}

// DiffLines 取出 diff 中全部 +/- 变更行（含前缀符号），供 evidence_snippets 防幻觉校验。
func DiffLines(files []FileChange) []string {
	lines := make([]string, 0, 64)
	for _, f := range files {
		for _, h := range f.Hunks {
			for _, l := range h.Lines {
				if strings.HasPrefix(l, "+") || strings.HasPrefix(l, "-") {
					lines = append(lines, l)
				}
			}
		}
	}
	return lines
}

func normalizeSpace(s string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(s)), " ")
}

// HunkHeaders 取出全部 hunk 头（@@ ... @@），供判定与评测复用。
func HunkHeaders(files []FileChange) []string {
	headers := make([]string, 0, 16)
	for _, f := range files {
		for _, h := range f.Hunks {
			if strings.HasPrefix(h.Header, "@@") {
				headers = append(headers, h.Header)
			}
		}
	}
	return headers
}

// stripJSONFence 去掉模型偶尔包裹的 ```json ... ```。
func stripJSONFence(content string) string {
	s := strings.TrimSpace(content)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimPrefix(s, "json")
	if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// timeSeconds 把秒数换成 time.Duration，0 交给下游默认值。
func timeSeconds(sec int) time.Duration {
	if sec <= 0 {
		return 0
	}
	return time.Duration(sec) * time.Second
}

// recordUsage 记一次调用量；失败只打日志，绝不影响判定主流程。
func (j *SentinelJudge) recordUsage(ctx context.Context, out *JudgeRunOutput) {
	if out == nil || (out.PromptTokens == 0 && out.CompletionTokens == 0) {
		return
	}
	cost := float64(out.PromptTokens)/1000*j.llmCfg.PromptCostPer1K +
		float64(out.CompletionTokens)/1000*j.llmCfg.CompletionCostPer1K
	modelName := j.eval.ModelName()
	if err := j.usage.Insert(ctx, &repo.LLMUsage{
		Model:            modelName,
		Purpose:          "sentinel_judge",
		PromptTokens:     out.PromptTokens,
		CompletionTokens: out.CompletionTokens,
		CostUSD:          cost,
	}); err != nil {
		log.Printf("[Sentinel] 记录 LLM 用量失败: %v", err)
	}
}

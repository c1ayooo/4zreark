package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/sentinelsandbox"
	"github.com/c1ayooo/4zreark/repo"
)

// POC 靶场验证（Tier 3b）：python-poc 人工 verified 后，docker 拉公开靶场镜像
// 起隔离内网（--internal，无外网出口）靶场，PoC 在网络内打靶场，按脚本输出的
// VULNERABLE / NOT VULNERABLE / ERROR 判定可行性。
//
// 分工：AI 只负责「选哪个靶场、什么参数」（sentinel_env 方案，受镜像白名单与
// URL/环境变量校验约束）；docker 编排、就绪探测、执行、判定、清理全部是本文件
// 的确定性代码。worker 在 pocsmith 进程（与差分复现同进程不同队列）。

const pocVerifyTitle = "poc-verify"

// errSentinelPocVerifyInput 是输入/环境类错误：重试也不会好，worker 端直接 JobCancel。
var errSentinelPocVerifyInput = errors.New("poc-verify 输入或环境错误")

// pocVerifyEnvPlan 是 AI 生成的环境方案。
type pocVerifyEnvPlan struct {
	Image       string   `json:"image"`        // 靶场镜像（必须在白名单前缀内）
	Env         []string `json:"env"`          // 靶场容器 -e 参数（KEY=VALUE）
	Port        int      `json:"port"`         // 服务在容器内的端口
	ProbePath   string   `json:"probe_path"`   // 就绪探测路径（默认 /）
	WaitSeconds int      `json:"wait_seconds"` // 就绪等待秒数（受配置封顶）
	TargetURL   string   `json:"target_url"`   // POC 的 TARGET，host 必须是 pocverify-target
	Notes       string   `json:"notes"`
}

// PocVerifyVerdict 是一次靶场验证的结论。
type PocVerifyVerdict struct {
	Passed     bool           `json:"passed"`      // verdict == vulnerable
	Verdict    string         `json:"verdict"`     // vulnerable / not_vulnerable / error
	Reason     string         `json:"reason"`      // 判定依据摘要
	Env        map[string]any `json:"env"`         // 环境方案与参数（供审计）
	ExitCode   int            `json:"exit_code"`   // PoC 容器退出码
	ExecDetail string         `json:"exec_detail"` // 执行过程摘要（耗时/事件）
}

// PocVerifyService 执行单条发现的靶场验证。
type PocVerifyService struct {
	store   *repo.Sentinel
	sandbox *sentinelsandbox.VerifySandbox
}

// NewPocVerifyService 构造靶场验证服务；workdir 与差分复现共用（PoC 目录布局一致）。
func NewPocVerifyService(workdir string) *PocVerifyService {
	return &PocVerifyService{
		store:   repo.Default().Sentinel(),
		sandbox: &sentinelsandbox.VerifySandbox{Workdir: workdir},
	}
}

// pocVerifyCfg 读配置并补齐默认值。
func pocVerifyCfg() config.SentinelPocVerifyConfig {
	var cfg config.SentinelPocVerifyConfig
	if c := config.Loaded(); c != nil {
		cfg = c.Sentinel.PocVerify
	}
	cfg.Normalize()
	return cfg
}

// pocVerifyEnabled 读总开关，未配置默认开启。
func pocVerifyEnabled() bool {
	if c := config.Loaded(); c != nil && c.Sentinel.PocVerify.Enabled != nil {
		return *c.Sentinel.PocVerify.Enabled
	}
	return true
}

// Verify 执行靶场验证。river job 入口；force=true 时忽略已有的 poc-verify 产物重跑。
func (s *PocVerifyService) Verify(ctx context.Context, findingID int64, force bool) error {
	cfg := pocVerifyCfg()
	store := s.store
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		return err
	}

	runID, runErr := store.CreateRun(ctx, &repo.SentinelRun{
		RunType: "poc_verify", Status: "running", Total: 1,
	})
	if runErr != nil {
		log.Printf("[pocverify] 创建验证批次失败 finding=%d: %v", findingID, runErr)
	} else {
		_ = store.UpdateRun(ctx, runID, map[string]interface{}{"started_at": time.Now()})
	}
	emit := func(level, kind, message string, payload map[string]interface{}) {
		if runErr != nil {
			return
		}
		p, _ := json.Marshal(payload)
		if _, err := store.AppendRunEvent(ctx, &repo.SentinelRunEvent{
			RunID: runID, Level: level, Kind: kind, Message: message, Payload: p,
		}); err != nil {
			log.Printf("[pocverify] 写验证事件失败 run=%d: %v", runID, err)
		}
	}
	finishRun := func(status string, errMsg string) {
		if runErr != nil {
			return
		}
		fields := map[string]interface{}{"status": status, "processed": 1, "finished_at": time.Now()}
		if errMsg != "" {
			fields["error"] = errMsg
		}
		_ = store.UpdateRun(ctx, runID, fields)
	}
	emit("info", "poc_verify_start", fmt.Sprintf("finding=%d %s [%s/%s]", f.ID, f.Title, f.VulnClass, f.Severity),
		map[string]interface{}{"finding_id": f.ID})
	defer func() {
		if err := recover(); err != nil {
			emit("error", "poc_verify_failed", fmt.Sprintf("panic: %v", err), nil)
			finishRun("failed", fmt.Sprintf("panic: %v", err))
		}
	}()

	// ---- 0. 前置检查 ----
	if !pocVerifyEnabled() {
		emit("info", "poc_verify_skipped", "poc_verify 未开启（sentinel.poc_verify.enabled=false）", nil)
		finishRun("completed", "")
		return nil
	}
	if err := sentinelsandbox.Available(ctx); err != nil {
		emit("error", "poc_verify_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return errSentinelPocVerifyInput
	}
	// 已有同等级机器验证（差分复现或靶场验证）通过：跳过。
	if f.VerifiedAt != nil {
		emit("info", "poc_verify_skipped", "finding 已机器验证通过（verified_at 非空）", nil)
		finishRun("completed", "")
		return nil
	}

	// 验证输入二选一：verified 的 python-poc（python 引擎）或 verified 的 nuclei
	// 模板（nuclei 引擎）——有哪样用哪样，不必等另一条流水线补齐。
	pocContent := ""
	nucleiContent := ""
	var arts []*repo.CommitArtifact
	if got, err := store.ListArtifacts(ctx, findingID); err == nil {
		arts = got
		for _, a := range arts {
			switch {
			case a.Kind == "poc" && a.Title == pythonPocTitle && a.Status == "verified" && pocContent == "":
				pocContent = a.Content
			case a.Kind == "nuclei" && a.Status == "verified" && nucleiContent == "":
				nucleiContent = a.Content
			}
		}
		if !force {
			for _, a := range arts {
				if a.Kind == "repro_log" && a.Title == pocVerifyTitle {
					emit("info", "poc_verify_skipped", "已有 poc-verify 产物（force=true 可重跑）", nil)
					finishRun("completed", "")
					return nil
				}
			}
		}
	}

	// 利用方法 Markdown（exploit-guide / repro-guide / deep-analysis）：此前是
	// 只展示的死数据，现在解析成前置条件、步骤、请求示例与 URL 路径，作为选靶场
	// 与核对 target_url 的确定性依据，并随验证结论一起落证据。
	guide := parseExploitArtifacts(arts)
	if guide.IsEmpty() {
		emit("info", "poc_verify_guide", "未找到可解析的利用方法 Markdown（exploit-guide / repro-guide / deep-analysis）", nil)
	} else {
		emit("info", "poc_verify_guide",
			fmt.Sprintf("已解析 %d 份利用方法 Markdown（步骤 %d / 请求示例 %d / 路径 %d）",
				len(guide.Sources), len(guide.Steps), len(guide.Requests), len(guide.Paths)),
			map[string]interface{}{"exploit_guide": guide})
	}

	engine := "python"
	pocInput := pocContent
	pocLabel := "python-poc"
	if pocContent == "" && nucleiContent != "" {
		engine = "nuclei"
		pocInput = nucleiContent
		pocLabel = "nuclei 模板"
	}
	if pocInput == "" {
		msg := "缺少 verified 的 python-poc 或 nuclei 模板产物：任一审核通过后即可发起验证"
		if !guide.IsEmpty() {
			msg += fmt.Sprintf("（已解析 %d 份利用方法 Markdown，可作为生成/审核 PoC 的依据）", len(guide.Sources))
		}
		emit("info", "poc_verify_skipped", msg, nil)
		finishRun("completed", "")
		return nil
	}

	// ---- 1. AI 出环境方案（受白名单与 URL/环境变量校验约束）----
	emit("info", "poc_verify_plan", "生成靶场环境方案（LLM，输入 "+pocLabel+" + 利用方法 Markdown）", nil)
	plan, err := s.planEnv(ctx, f, pocInput, pocLabel, guide)
	if err != nil {
		emit("error", "poc_verify_failed", "环境方案生成失败: "+err.Error(), nil)
		finishRun("failed", err.Error())
		return err // LLM 可重试
	}
	emit("info", "poc_verify_plan_ok", fmt.Sprintf("image=%s port=%d target=%s", plan.Image, plan.Port, plan.TargetURL),
		map[string]interface{}{"image": plan.Image, "notes": plan.Notes})

	// ---- 2. 编排执行：隔离网络 → 拉镜像 → 起靶场 → 就绪探测 → 跑 PoC → 清理 ----
	network := fmt.Sprintf("pocverify-net-%d-%d", findingID, time.Now().Unix())
	started := time.Now()
	defer func() {
		_ = s.sandbox.StopService(ctx)
		if err := s.sandbox.RemoveNetwork(ctx, network); err != nil {
			log.Printf("[pocverify] 清理网络失败 %s: %v", network, err)
		}
	}()
	if err := s.sandbox.CreateNetwork(ctx, network); err != nil {
		emit("error", "poc_verify_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return err
	}
	emit("info", "poc_verify_pull", "拉取靶场镜像: "+plan.Image, nil)
	if err := s.sandbox.Pull(ctx, plan.Image); err != nil {
		emit("error", "poc_verify_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return err
	}
	if _, err := s.sandbox.StartService(ctx, network, plan.Image, plan.Env); err != nil {
		emit("error", "poc_verify_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return err
	}
	emit("info", "poc_verify_probe", fmt.Sprintf("等待靶场就绪: %s%s", plan.TargetURL, plan.ProbePath), nil)
	probeURL := strings.TrimSuffix(plan.TargetURL, "/") + plan.ProbePath
	probeCtx, probeCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer probeCancel()
	if err := s.sandbox.ProbeHTTP(probeCtx, network, cfg.PythonImage, probeURL, time.Duration(plan.WaitSeconds)*time.Second); err != nil {
		emit("error", "poc_verify_failed", "靶场未就绪: "+err.Error(), nil)
		finishRun("failed", err.Error())
		return nil // 环境问题重试意义有限，落证据收尾
	}

	var res *sentinelsandbox.ExecResult
	var verdict *PocVerifyVerdict
	if engine == "nuclei" {
		// nuclei 用项目内部二进制（只读挂载进网络内容器），目标环境才是 docker。
		nucleiBin, err := s.sandbox.EnsureNucleiBinary(sentinelsandbox.FindNucleiBinary())
		if err != nil {
			emit("error", "poc_verify_failed", err.Error(), nil)
			finishRun("failed", err.Error())
			return errSentinelPocVerifyInput
		}
		if err := s.sandbox.WritePoc("poc_verify.yaml", pocInput); err != nil {
			emit("error", "poc_verify_failed", "写入模板失败: "+err.Error(), nil)
			finishRun("failed", err.Error())
			return errSentinelPocVerifyInput
		}
		emit("info", "poc_verify_run", "执行 nuclei（项目内部二进制）: -t /poc/poc_verify.yaml -u "+plan.TargetURL, nil)
		res, err = s.sandbox.RunPoC(ctx, network, cfg.PythonImage,
			[]string{nucleiBin, "-u", plan.TargetURL, "-t", "/poc/poc_verify.yaml", "-json", "-silent", "-duc"},
			[]string{"TARGET=" + plan.TargetURL})
		if err != nil {
			emit("error", "poc_verify_failed", err.Error(), nil)
			finishRun("failed", err.Error())
			return err
		}
		verdict = classifyNucleiVerdict(res)
	} else {
		if err := s.sandbox.WritePoc("poc_verify.py", pocInput); err != nil {
			emit("error", "poc_verify_failed", "写入 PoC 失败: "+err.Error(), nil)
			finishRun("failed", err.Error())
			return errSentinelPocVerifyInput
		}
		emit("info", "poc_verify_run", "执行 PoC: python /poc/poc_verify.py", nil)
		res, err = s.sandbox.RunPoC(ctx, network, cfg.PythonImage,
			[]string{"python", "/poc/poc_verify.py"},
			[]string{"TARGET=" + plan.TargetURL})
		if err != nil {
			emit("error", "poc_verify_failed", err.Error(), nil)
			finishRun("failed", err.Error())
			return err
		}
		verdict = classifyPocVerdict(res)
	}

	// ---- 3. 判定 + 落证据 ----
	verdict.Env = map[string]any{
		"image": plan.Image, "env": plan.Env, "port": plan.Port,
		"probe_path": plan.ProbePath, "target_url": plan.TargetURL,
		"engine": engine, "network": "docker --internal（无外网出口）",
		"notes": plan.Notes,
	}
	if !guide.IsEmpty() {
		verdict.Env["exploit_guide"] = guide
	}
	verdict.ExecDetail = fmt.Sprintf("耗时 %s，PoC 容器退出码 %d，超时 %v", time.Since(started).Round(time.Second), res.ExitCode, res.TimedOut)

	content, _ := json.MarshalIndent(verdict, "", "  ")
	content = append(content, []byte("\n\n==== PoC 执行日志 ====\n"+truncateRunLog(res.Log, 20000))...)
	if _, err := store.InsertArtifact(ctx, &repo.CommitArtifact{
		FindingID: findingID,
		Kind:      "repro_log",
		Title:     pocVerifyTitle,
		Status:    "verified",
		Content:   string(content),
	}); err != nil {
		emit("error", "poc_verify_failed", "落验证产物失败: "+err.Error(), nil)
		finishRun("failed", err.Error())
		return err
	}
	if verdict.Passed {
		if err := store.MarkFindingVerified(ctx, findingID, "poc-verify"); err != nil {
			log.Printf("[pocverify] 标记 finding=%d 已验证失败: %v", findingID, err)
		}
		emit("info", "poc_verify_passed", "靶场验证通过: PoC 在靶场上确认漏洞（"+verdict.Reason+"）", nil)
		log.Printf("[pocverify] 验证通过 finding=%d image=%s", findingID, plan.Image)
	} else {
		emit("info", "poc_verify_not_passed", "靶场验证未确认: "+verdict.Reason, nil)
		log.Printf("[pocverify] 验证未确认 finding=%d verdict=%s", findingID, verdict.Verdict)
	}
	finishRun("completed", "")
	return nil
}

// planEnv 让 LLM 生成环境方案并做安全校验。guide 是 Markdown 利用方法解析结果，
// 作为「选哪个靶场/版本、target_url 该用什么路径」的可核对依据。
func (s *PocVerifyService) planEnv(ctx context.Context, f *repo.CommitFinding, pocInput, pocLabel string, guide ExploitGuide) (*pocVerifyEnvPlan, error) {
	cfg := pocVerifyCfg()
	g, err := loadFindingGenContext(ctx, f.ID)
	if err != nil {
		return nil, err
	}
	live := effectiveDeepLLMConfig(ctx)
	if live.cfg.MaxTokens < 4096 {
		live.cfg.MaxTokens = 4096
	}
	poc := pocInput
	if len(poc) > 8000 {
		poc = poc[:8000] + "\n…（超长截断）"
	}
	user := fmt.Sprintf(
		"仓库: %s\n漏洞类别: %s\n严重度: %s\n发现标题: %s\n\n## 待验证输入（%s）\n```\n%s\n```\n",
		g.commit.RepoFullName, f.VulnClass, f.Severity, f.Title, pocLabel, poc)
	if parsed := guide.LLMContext(); parsed != "" {
		user += "\n" + parsed + "\n"
	}
	user += "\n请为该验证输入生成靶场环境方案（JSON）。"
	raw, err := llmArtifactCall(ctx, live, pocVerifyEnvSystemPrompt, user)
	if err != nil {
		return nil, err
	}
	raw = stripCodeFence(raw)
	// 容错：模型可能带前后缀文字，取第一个 { 到最后一个 }。
	if i := strings.IndexByte(raw, '{'); i > 0 {
		raw = raw[i:]
	}
	if j := strings.LastIndexByte(raw, '}'); j >= 0 {
		raw = raw[:j+1]
	}
	var plan pocVerifyEnvPlan
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return nil, fmt.Errorf("环境方案 JSON 解析失败: %w", err)
	}
	if err := validateEnvPlan(&plan, cfg); err != nil {
		return nil, err
	}
	return &plan, nil
}

var reImageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$`)

// validateEnvPlan 是 AI 方案的安全闸：镜像白名单、端口/URL 收敛到靶场主机名、
// env 逐项校验。AI 只能选「打哪个靶场」，拿不到任何越界参数。
func validateEnvPlan(plan *pocVerifyEnvPlan, cfg config.SentinelPocVerifyConfig) error {
	plan.Image = strings.TrimSpace(plan.Image)
	if !reImageName.MatchString(plan.Image) {
		return fmt.Errorf("镜像名非法: %q", plan.Image)
	}
	allowed := false
	for _, prefix := range cfg.ImageAllow {
		if strings.HasPrefix(plan.Image, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("镜像 %q 不在白名单内（允许前缀: %s）", plan.Image, strings.Join(cfg.ImageAllow, ", "))
	}
	if plan.Port < 1 || plan.Port > 65535 {
		return fmt.Errorf("端口非法: %d", plan.Port)
	}
	u, err := url.Parse(strings.TrimSpace(plan.TargetURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("target_url 非法: %q", plan.TargetURL)
	}
	if host := u.Hostname(); host != sentinelsandbox.TargetHostName {
		return fmt.Errorf("target_url 的 host 必须是 %s（隔离网络内靶场），收到 %q", sentinelsandbox.TargetHostName, host)
	}
	if plan.ProbePath == "" {
		plan.ProbePath = "/"
	}
	if !strings.HasPrefix(plan.ProbePath, "/") {
		plan.ProbePath = "/" + plan.ProbePath
	}
	if plan.WaitSeconds <= 0 {
		plan.WaitSeconds = 30
	}
	if plan.WaitSeconds > cfg.MaxWaitSeconds {
		plan.WaitSeconds = cfg.MaxWaitSeconds
	}
	for _, e := range plan.Env {
		if !sentinelsandbox.ValidEnv(e) {
			return fmt.Errorf("非法 env 项: %q", e)
		}
	}
	if len(plan.Env) > 20 {
		return errors.New("env 项数过多")
	}
	return nil
}

// classifyPocVerdict 按 PoC 约定的三态输出判定。约定见 python-poc 的生成
// prompt：脚本结尾必须输出 VULNERABLE / NOT VULNERABLE / ERROR。
// classifyNucleiVerdict 按 nuclei -json 输出判定：JSONL 里出现
// matcher-status=true 即命中。退出码非 0 且无任何 JSON 行视为执行失败。
func classifyNucleiVerdict(res *sentinelsandbox.ExecResult) *PocVerifyVerdict {
	matched := strings.Contains(res.Log, `"matcher-status":true`) ||
		strings.Contains(res.Log, `"matcher-status": true`)
	switch {
	case matched:
		return &PocVerifyVerdict{
			Verdict: "vulnerable", Passed: true,
			Reason: "nuclei 模板在靶场上命中（matcher-status=true）",
		}
	case res.ExitCode == 0 && strings.TrimSpace(res.Log) != "":
		return &PocVerifyVerdict{
			Verdict: "not_vulnerable", Passed: false,
			Reason: "nuclei 执行完成但无匹配（靶场版本可能不受影响或模板条件不满足）",
		}
	default:
		return &PocVerifyVerdict{
			Verdict: "error", Passed: false,
			Reason: fmt.Sprintf("nuclei 执行异常（退出码 %d，无有效输出）", res.ExitCode),
		}
	}
}

func classifyPocVerdict(res *sentinelsandbox.ExecResult) *PocVerifyVerdict {
	logText := res.Log
	switch {
	case strings.Contains(logText, "NOT VULNERABLE"):
		return &PocVerifyVerdict{
			Verdict: "not_vulnerable", Passed: false,
			Reason: "PoC 自判 NOT VULNERABLE（靶场版本可能不受影响或触发条件不满足）",
		}
	case strings.Contains(logText, "VULNERABLE") && (res.ExitCode == 0 || res.TimedOut):
		return &PocVerifyVerdict{
			Verdict: "vulnerable", Passed: true,
			Reason: fmt.Sprintf("PoC 自判 VULNERABLE（退出码 %d，日志含漏洞判定标记）", res.ExitCode),
		}
	case strings.Contains(logText, "ERROR"):
		return &PocVerifyVerdict{
			Verdict: "error", Passed: false,
			Reason: fmt.Sprintf("PoC 自判 ERROR（退出码 %d），需检查环境方案或 PoC 前置条件", res.ExitCode),
		}
	case res.TimedOut:
		return &PocVerifyVerdict{Verdict: "error", Passed: false, Reason: "PoC 执行超时"}
	case res.ExitCode != 0:
		return &PocVerifyVerdict{
			Verdict: "error", Passed: false,
			Reason: fmt.Sprintf("PoC 非零退出（%d）且无三态判定标记", res.ExitCode),
		}
	default:
		return &PocVerifyVerdict{Verdict: "error", Passed: false, Reason: "退出码 0 但无 VULNERABLE/NOT VULNERABLE 标记，判定不可信"}
	}
}

func truncateRunLog(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…（超长截断）"
	}
	return s
}

// ---- 发现级靶场验证状态与触发（前端高危漏洞工作台 / 详情卡数据源）----

// PocVerifyStep 是验证时间线上的一步。
type PocVerifyStep struct {
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
	State  string    `json:"state"` // done / fail / info
	Time   time.Time `json:"time"`
}

// PocVerifyStatus 是一条发现的靶场验证完整状态（方案 B 卡片数据）。
type PocVerifyStatus struct {
	FindingID int64             `json:"finding_id"`
	HasPoc    bool              `json:"has_poc"`            // 已有 verified 的 python-poc（可发起验证）
	HasNuclei bool              `json:"has_nuclei"`         // 已有 verified 的 nuclei 模板（同样可发起验证）
	HasGuide  bool              `json:"has_guide"`          // 已解析到利用方法 Markdown
	Exploit   *ExploitGuide     `json:"exploit,omitempty"`   // 利用方法解析结果（步骤/路径/请求示例）
	Verified  bool              `json:"verified"`           // finding 已机器验证（verified_at 非空）
	Running   bool              `json:"running"`            // 最近一次验证仍在执行
	Verify    *PocVerifyVerdict `json:"verify,omitempty"`   // 机器结论（有 poc-verify 产物时）
	Timeline  []PocVerifyStep   `json:"timeline,omitempty"` // 最近一次执行的步骤时间线
}

// pocVerifyStepTitles 把事件 kind 映射成时间线标题。
var pocVerifyStepTitles = map[string]string{
	"poc_verify_guide":      "解析利用方法 Markdown",
	"poc_verify_plan":       "生成环境方案（LLM）",
	"poc_verify_plan_ok":    "环境方案校验通过",
	"poc_verify_pull":       "拉取靶场镜像",
	"poc_verify_probe":      "等待靶场就绪",
	"poc_verify_run":        "执行 PoC",
	"poc_verify_passed":     "验证通过",
	"poc_verify_not_passed": "验证未确认",
	"poc_verify_failed":     "执行失败",
	"poc_verify_skipped":    "跳过",
}

// GetPocVerifyStatus 组装一条发现的验证状态：
// 结论与输入看产物，过程看最近一次 poc_verify 批次的事件流。
func GetPocVerifyStatus(ctx context.Context, findingID int64) (*PocVerifyStatus, error) {
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	st := &PocVerifyStatus{FindingID: findingID, Verified: f.VerifiedAt != nil}

	arts, err := store.ListArtifacts(ctx, findingID)
	if err != nil {
		return nil, err
	}
	for _, a := range arts {
		switch {
		case a.Kind == "poc" && a.Title == pythonPocTitle && a.Status == "verified":
			st.HasPoc = true
		case a.Kind == "nuclei" && a.Status == "verified":
			st.HasNuclei = true
		case a.Kind == "repro_log" && a.Title == pocVerifyTitle:
			if v, err := parsePocVerifyContent(a.Content); err == nil {
				st.Verify = v
			}
		}
	}
	if guide := parseExploitArtifacts(arts); !guide.IsEmpty() {
		st.HasGuide = true
		st.Exploit = &guide
	}

	// 时间线：事件按 id 倒序取回，取最近一个 run 的顺序回放。
	events, err := store.ListPocVerifyEvents(ctx, findingID, 100)
	if err != nil {
		return nil, err
	}
	var curRun int64 = -1
	for _, e := range events {
		if curRun == -1 {
			curRun = e.RunID
		}
		if e.RunID != curRun {
			break // 只回放最近一次执行
		}
		step := PocVerifyStep{
			Title: pocVerifyStepTitles[e.Kind],
			State: "done",
			Time:  e.CreatedAt,
		}
		if e.Message != "" && e.Kind != "poc_verify_start" {
			step.Detail = e.Message
		}
		switch e.Level {
		case "error":
			step.State = "fail"
		case "info":
			if strings.Contains(e.Kind, "start") {
				step.State = "info"
				st.Running = true
			}
		}
		if step.Title != "" {
			st.Timeline = append(st.Timeline, step)
		}
	}
	// 事件是倒序取的，回放需正序。
	for i, j := 0, len(st.Timeline)-1; i < j; i, j = i+1, j-1 {
		st.Timeline[i], st.Timeline[j] = st.Timeline[j], st.Timeline[i]
	}
	return st, nil
}

// TriggerPocVerify 把一条发现排入靶场验证队列（API 入口，与 MCP 工具同一闸）。
func TriggerPocVerify(ctx context.Context, findingID int64, force bool) error {
	if !pocVerifyEnabled() {
		return errors.New("靶场验证未开启（sentinel.poc_verify.enabled=false）")
	}
	q := DefaultSentinelQueue()
	if q == nil {
		return errors.New("提交哨兵未启用（sentinel.enabled=false）")
	}
	store := repo.Default().Sentinel()
	if _, err := store.GetFinding(ctx, findingID); err != nil {
		return err
	}
	return q.EnqueuePocVerify(ctx, findingID, force)
}

const pocVerifyEnvSystemPrompt = `你是漏洞靶场环境工程师。给定一条漏洞发现和待验证的 Python PoC 脚本，
请选择一个公开可拉的漏洞靶场镜像让 PoC 在上面打出漏洞。硬性要求：
1. 只输出一个 JSON 对象，字段：image（靶场镜像）、env（镜像环境变量数组，KEY=VALUE）、
   port（服务在容器内的端口）、probe_path（就绪探测路径）、wait_seconds（就绪等待秒数，≤120）、
   target_url（PoC 的 TARGET，host 固定为 pocverify-target，如 http://pocverify-target:8080/vulnerable/path）、
   notes（一句话说明为什么选这个靶场）。
2. image 必须是公开镜像仓库里的漏洞靶场，优先 vulhub（如 vulhub/log4j2:CVE-2021-44228）；
   禁止自建镜像名、禁止带 dockerfile/构建语义。
3. target_url 的路径必须与 PoC 脚本里请求的路径一致；port 与靶场服务端口一致。
4. 不确定选哪个靶场时，选 notes 里说明理由的最接近版本；禁止编造不存在的 CVE 镜像标签，
   标签不确定时用该镜像的 latest。
5. env 只放镜像文档明确要求的环境变量。
6. 若给出了「利用方法（Markdown 解析结果）」：target_url 的 path 必须优先取其中的
   请求路径，image/标签优先按其影响范围与明确写出的 CVE 选择；不得因为文档里
   出现其它域名就把 target_url 的 host 改成非 pocverify-target。
7. 文档里的 curl / HTTP 报文只是路径与参数依据，不要据此新增 env 或 docker 参数。`

package service

// pocsmith 差分复现服务（v0.3 §7.6-7.9）。
//
// 定位：把「判定命中 → 人工确认」的发现交给 Docker 双环境差分验证——
// 同一 PoC 分别跑 vuln（修复前）与 fix（修复后）镜像，oracle 按 §7.8
// 判硬崩溃，§7.9 四条否决把环境问题/不稳定复现挡在门外。
//
// 编排仍是固定流程（不是 agent）：输入输出必须可复现。
// PoC 与构建计划都来自产物库：
//   - PoC       = finding 下 kind=poc 且 verified 的产物（铁律：未审核不下发）
//   - 构建计划  = kind=report、title=repro-plan 的产物，JSON：
//     {"vuln_image":"...","fix_image":"...","poc_path":"poc.txt","poc_cmd":["/poc/poc.txt"]}
//     MVP 只支持预构建镜像剧本；Maven 源码构建剧本（§7.6 同 Dockerfile 异 ref）留接口。
//
// 复现通过的证据落 repro_log 产物（机器证据，直接 verified），finding 打
// verified_at/by=pocsmith；status 是否 confirmed 仍归人工。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/sentinelsandbox"
	"github.com/c1ayooo/4zreark/repo"

	"github.com/c1ayooo/4zreark/service/notify"
)

// reproPlan 是 repro-plan 产物的 JSON 结构（预构建镜像剧本）。
type reproPlan struct {
	VulnImage string   `json:"vuln_image"`
	FixImage  string   `json:"fix_image"`
	PocPath   string   `json:"poc_path"` // 沙箱 /poc 内的文件名
	PocCmd    []string `json:"poc_cmd"`  // 容器内执行命令（PoC 入口）
}

// ReproVerdict 是一次差分复现的结论。
type ReproVerdict struct {
	Passed     bool   `json:"passed"`
	Veto       string `json:"veto,omitempty"` // differential-ok 或四否决之一
	VulnCrash  int    `json:"vuln_crash"`     // 硬崩溃次数
	VulnRuns   int    `json:"vuln_runs"`
	FixCrash   bool   `json:"fix_crash"`
	ExecDetail string `json:"exec_detail"`
}

// ReproService 负责单条发现的差分复现与落库。
type ReproService struct {
	store   *repo.Sentinel
	sandbox *sentinelsandbox.Sandbox
	// MaxAttemptsPerRun 是 §7.9 flaky 判定的 vuln 侧执行次数。
	MaxAttemptsPerRun int
}

// NewReproService 构造复现服务；docker 不可用时 Work 会失败并写明原因。
// mountSource 是可选参数：pocsmith 以容器方式（DooD）运行时传 docker -v 的
// 挂载源（命名卷名），宿主机直跑时留空即可。
func NewReproService(workdir string, timeoutSeconds int, mountSource ...string) *ReproService {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}
	src := ""
	if len(mountSource) > 0 {
		src = mountSource[0]
	}
	return &ReproService{
		store:             repo.Default().Sentinel(),
		sandbox:           &sentinelsandbox.Sandbox{Workdir: workdir, MountSource: src, TimeoutSeconds: timeoutSeconds},
		MaxAttemptsPerRun: 3,
	}
}

// Repro 执行一条发现的差分复现。river job 入口；已验证过的发现直接跳过。
func (s *ReproService) Repro(ctx context.Context, findingID int64) error {
	// 一次只验证一个：差分复现与靶场验证共用 docker 编排闸门，两个队列的
	// worker 同时取到作业时后者会等前者跑完再进容器。
	gateRelease, gateErr := acquireSentinelVerifyGate(ctx)
	if gateErr != nil {
		return gateErr
	}
	defer gateRelease()

	store := s.store
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		return err
	}

	runID, runErr := store.CreateRun(ctx, &repo.SentinelRun{
		RunType: "repro", Status: "running", Total: 1,
	})
	if runErr != nil {
		log.Printf("[pocsmith] 创建复现批次失败 finding=%d: %v", findingID, runErr)
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
			log.Printf("[pocsmith] 写复现事件失败 run=%d: %v", runID, err)
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
		if err := store.UpdateRun(ctx, runID, fields); err != nil {
			log.Printf("[pocsmith] 收尾复现批次失败 run=%d: %v", runID, err)
		}
	}
	emit("info", "repro_start", fmt.Sprintf("finding=%d %s [%s/%s]", f.ID, f.Title, f.VulnClass, f.Severity),
		map[string]interface{}{"finding_id": f.ID})
	defer func() {
		if err := recover(); err != nil {
			emit("error", "repro_failed", fmt.Sprintf("panic: %v", err), nil)
			finishRun("failed", fmt.Sprintf("panic: %v", err))
		}
	}()

	if f.VerifiedAt != nil {
		emit("info", "repro_skipped", "机器复现已通过（verified_at 非空），永不重复复现", nil)
		finishRun("completed", "")
		return nil
	}

	// ---- 1. 取材料：verified PoC + repro-plan 构建计划 ----
	pocContent, pocPath, plan, err := s.loadMaterials(ctx, f.ID)
	if err != nil {
		emit("error", "repro_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return errSentinelReproInput
	}
	if pocContent == "" {
		msg := "缺少 verified 的 poc 产物：先在产物中心审核通过一份 kind=poc（或 AI 生成后人工 verified），再发起复现"
		emit("info", "repro_skipped", msg, nil)
		finishRun("completed", "")
		return nil
	}
	if plan == nil {
		msg := "缺少构建计划：需要一份 title=repro-plan 的产物（JSON：vuln_image/fix_image/poc_path/poc_cmd）"
		emit("info", "repro_skipped", msg, nil)
		finishRun("completed", "")
		return nil
	}

	if err := sentinelsandbox.Available(ctx); err != nil {
		emit("error", "repro_failed", err.Error(), nil)
		finishRun("failed", err.Error())
		return errSentinelReproInput
	}

	// ---- 2. PoC 下沙箱（只读挂载 /poc）----
	if err := s.sandbox.WritePoc(pocPath, pocContent); err != nil {
		emit("error", "repro_failed", "写入 PoC 失败: "+err.Error(), nil)
		finishRun("failed", err.Error())
		return errSentinelReproInput
	}

	// ---- 3. 差分执行 + oracle + 四条否决（§7.9）----
	verdict := s.differential(ctx, plan, pocPath)
	verdictMsg := "复现未通过: " + verdict.Veto
	if verdict.Passed {
		verdictMsg = "复现通过: differential-ok（vuln " + strconv.Itoa(verdict.VulnCrash) + "/" + strconv.Itoa(verdict.VulnRuns) + " 硬崩溃，fix 正常）"
	}
	emit("info", "repro_verdict", verdictMsg,
		map[string]interface{}{"veto": verdict.Veto, "vuln_crash": verdict.VulnCrash, "vuln_runs": verdict.VulnRuns, "fix_crash": verdict.FixCrash})

	// ---- 4. 证据与结论落库 ----
	report, _ := json.MarshalIndent(map[string]interface{}{
		"finding_id": f.ID, "verdict": verdict, "plan": plan,
		"poc_sha_note": "PoC 以只读挂载进入两个镜像，内容一致由挂载保证",
	}, "", "  ")
	if _, err := store.InsertArtifact(ctx, &repo.CommitArtifact{
		FindingID: f.ID,
		Kind:      "repro_log",
		Title:     "repro: " + verdict.Veto,
		Status:    "verified",
		Content:   string(report) + "\n\n==== 执行日志 ====\n" + verdict.ExecDetail,
	}); err != nil {
		log.Printf("[pocsmith] 写 repro_log 失败 finding=%d: %v", f.ID, err)
	}

	if verdict.Passed {
		if err := store.MarkFindingVerified(ctx, f.ID, "pocsmith"); err != nil {
			log.Printf("[pocsmith] 标记 verified 失败 finding=%d: %v", f.ID, err)
		}
		notifyReproResult(f, true, verdict.Veto)
	} else {
		notifyReproResult(f, false, verdict.Veto)
	}
	finishRun("completed", "")
	return nil
}

// errSentinelReproInput 区分「输入/环境问题」（不重试）与瞬时错误（交 River 重试）。
var errSentinelReproInput = errors.New("repro input error")

// loadMaterials 从产物库取 verified PoC 与 repro-plan。
func (s *ReproService) loadMaterials(ctx context.Context, findingID int64) (poc, pocPath string, plan *reproPlan, err error) {
	arts, err := s.store.ListArtifacts(ctx, findingID)
	if err != nil {
		return "", "", nil, err
	}
	for _, a := range arts {
		switch {
		case a.Kind == "poc" && a.Status == "verified" && poc == "":
			poc = a.Content
			if p := pocPathFromPlanTitle(a.Title); p != "" {
				pocPath = p
			}
		case a.Kind == "report" && strings.EqualFold(a.Title, "repro-plan") && plan == nil:
			plan = &reproPlan{}
			if jerr := json.Unmarshal([]byte(a.Content), plan); jerr != nil {
				return "", "", nil, fmt.Errorf("repro-plan 不是合法 JSON: %w", jerr)
			}
			if plan.VulnImage == "" || plan.FixImage == "" {
				return "", "", nil, errors.New("repro-plan 缺字段：需要 vuln_image / fix_image（poc_cmd 可省略，镜像自带入口时）")
			}
			if plan.PocPath != "" {
				pocPath = plan.PocPath
			}
		}
	}
	if pocPath == "" {
		pocPath = "poc.txt"
	}
	return poc, pocPath, plan, nil
}

// pocPathFromPlanTitle 允许 PoC 产物标题以 "path=<file>" 后缀声明容器内文件名。
func pocPathFromPlanTitle(title string) string {
	for _, part := range strings.Fields(title) {
		if strings.HasPrefix(part, "path=") {
			return strings.TrimPrefix(part, "path=")
		}
	}
	return ""
}

// differential 跑 vuln×N / fix×1 并套用 §7.9 否决链（顺序照文档）：
//
//	fix 硬崩溃            → fix-side-also-crashed
//	vuln 崩溃但无 PoC 标记 → crash-before-poc-point（崩在装载/初始化，环境问题）
//	vuln 硬崩溃不稳定      → flaky
//	vuln 从不硬崩溃       → vuln-not-crashed
//	全部通过              → differential-ok
//
// poc-mismatch：MVP 的 PoC 是同一只读挂载进入两个镜像，内容一致性由挂载
// 语义保证，此否决预留判定结构（将来 PoC 由 LLM 轮次重生成时才可能失配）。
func (s *ReproService) differential(ctx context.Context, plan *reproPlan, pocPath string) *ReproVerdict {
	v := &ReproVerdict{Veto: "differential-ok"}

	fixRes, err := s.sandbox.Run(ctx, plan.FixImage, plan.PocCmd)
	if err != nil {
		v.Veto = "fix-run-error: " + err.Error()
		return v
	}
	v.FixCrash = fixRes.HardCrash
	v.ExecDetail += fmt.Sprintf("---- fix run (exit=%d hard=%s) ----\n%s\n",
		fixRes.ExitCode, map[bool]string{true: "yes", false: "no"}[fixRes.HardCrash], fixRes.Log)
	if fixRes.HardCrash {
		v.Veto = "fix-side-also-crashed"
		return v
	}

	sawPocPoint := false
	for i := 0; i < s.MaxAttemptsPerRun; i++ {
		res, err := s.sandbox.Run(ctx, plan.VulnImage, plan.PocCmd)
		if err != nil {
			v.Veto = "vuln-run-error: " + err.Error()
			return v
		}
		v.VulnRuns++
		v.ExecDetail += fmt.Sprintf("---- vuln run %d (exit=%d hard=%s reached_poc=%v) ----\n%s\n",
			i+1, res.ExitCode, map[bool]string{true: "yes", false: "no"}[res.HardCrash], res.ReachedPocPoint, res.Log)
		if res.ReachedPocPoint {
			sawPocPoint = true
		}
		if res.HardCrash {
			v.VulnCrash++
			if !res.ReachedPocPoint {
				v.Veto = "crash-before-poc-point（崩溃日志无 __POC_START__：崩在装载/初始化，是环境问题不是漏洞）"
				return v
			}
		}
	}

	if v.VulnCrash == 0 {
		if !sawPocPoint {
			v.Veto = "crash-before-poc-point（日志无 __POC_START__：PoC 没跑到入口，先修 PoC/环境）"
		} else {
			v.Veto = "vuln-not-crashed"
		}
		return v
	}
	if v.VulnCrash < s.MaxAttemptsPerRun {
		v.Veto = "flaky"
		return v
	}
	v.Passed = true
	return v
}

// notifyReproResult 复现结论 → IM 旁路（通过 critical，未通过 warning）。
func notifyReproResult(f *repo.CommitFinding, passed bool, detail string) {
	mgr := notify.GetGlobalManager()
	if mgr == nil {
		return
	}
	level := notify.NotifyLevelWarning
	verb := "复现未通过"
	if passed {
		level = notify.NotifyLevelCritical
		verb = "复现通过"
	}
	msg := &notify.NotifyMessage{
		Level:   level,
		Title:   fmt.Sprintf("pocsmith: %s %s[%s] %s", f.Title, f.VulnClass, f.Severity, verb),
		Content: fmt.Sprintf("**发现**: %s\n**类别**: %s / %s\n**结论**: %s", f.Title, f.VulnClass, f.Severity, detail),
		Source:  "pocsmith",
		Extra:   map[string]interface{}{"link": "/sentinel/audit/artifacts"},
	}
	mgr.SendAsync(msg)
}

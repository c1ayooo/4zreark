package vulnverify

// 任务执行：召回 → scope 校验 → nuclei 最小验证（限流/超时）→ JSONL 解析 →
// 命中回调。单任务全链路失败只标 failed，不拖垮 worker。

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 默认资源上限（配置只能调小，不能放大——见 buildNucleiArgs 的 rate 硬顶）。
const (
	jobTimeoutBase   = 8 * time.Minute // 单任务硬超时
	probeTimeoutSecs = 8               // nuclei -timeout（单请求秒数）
	maxRateLimit     = 50              // -rl 硬上限：自动链路不允许高打
)

// process 单任务全流程。
func (s *Service) process(ctx context.Context, task Task) {
	finish := func(status, vulnID, errMsg string, templateIDs []string) {
		if s.opts.Store != nil {
			_ = s.opts.Store.FinishJob(task, status, vulnID, errMsg, templateIDs)
		}
		if s.opts.OnJobDone != nil {
			s.opts.OnJobDone(taskKey(task), status)
		}
		log.Printf("[vulnverify] 任务完结 target=%s product=%s status=%s vuln=%s err=%s", task.Target, task.Product, status, vulnID, errMsg)
	}

	cfg := s.config()
	if !cfg.EnabledOrDefault() {
		finish("skipped_disabled", "", "", nil)
		return
	}
	// scope 硬校验：fail-closed（nil 校验器 = 无 scope 能力，不自动打）。
	if s.opts.ScopeCheck == nil {
		finish("skipped_out_of_scope", "", "scope 校验器未注入", nil)
		return
	}
	if err := s.opts.ScopeCheck(ctx, task.ProjectID, task.Target); err != nil {
		log.Printf("[vulnverify] 目标出界，跳过 target=%s: %v", task.Target, err)
		finish("skipped_out_of_scope", "", err.Error(), nil)
		return
	}
	binPath := ""
	if s.opts.BinPath != nil {
		binPath = strings.TrimSpace(s.opts.BinPath())
	}
	if binPath == "" {
		finish("failed", "", "nuclei 二进制不可用", nil)
		return
	}
	refs, err := s.recall(ctx, task)
	if err != nil {
		finish("failed", "", err.Error(), nil)
		return
	}
	if len(refs) == 0 {
		finish("miss", "", "", nil) // 无召回：无已知模板可验证
		return
	}
	root := ""
	if s.opts.TemplatesRoot != nil {
		root = s.opts.TemplatesRoot()
	}
	// -t 双目录（知识库分域方案 P2）：官方根在前、自定义根在后，模板文件按序解析。
	roots := []string{}
	if root != "" {
		roots = append(roots, root)
	}
	if s.opts.CustomTemplatesRoot != nil {
		if custom := strings.TrimSpace(s.opts.CustomTemplatesRoot()); custom != "" {
			roots = append(roots, custom)
		}
	}

	jsonFlag := "-json"
	if s.opts.JSONFlagFunc != nil {
		jsonFlag = s.opts.JSONFlagFunc(binPath)
	}
	args, templatePaths := buildNucleiArgsRoots(task.Target, roots, refs, s.severities(), cfg.RateLimitEffective(), jsonFlag)
	if len(templatePaths) == 0 {
		finish("miss", "", "", nil) // 召回的模板文件全部缺失（模板目录未同步？）
		return
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.ID)
	}

	runCtx := ctx
	if s.opts.Runner == nil {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, jobTimeoutBase)
		defer cancel()
	}
	stdout, runErr := s.run(runCtx, binPath, args)
	if runErr != nil {
		// nuclei 对「无命中」正常退出；非 0 退出视为执行失败（模板路径缺失等）
		finish("failed", "", fmt.Sprintf("nuclei 执行失败: %v", runErr), ids)
		return
	}
	matches := ParseNucleiJSONL(stdout)
	if len(matches) == 0 {
		finish("miss", "", "", ids)
		return
	}

	// 命中：逐模板回调（同模板多行只取第一条），任一落库失败不影响其余
	hitVulnID := ""
	var hitErrs []string
	for _, m := range matches {
		if s.opts.RecordHit == nil {
			break
		}
		hit := HitResult{
			Severity:            m.Severity,
			ProjectID:           task.ProjectID,
			Target:              task.Target,
			Product:             task.Product,
			TemplateID:          m.TemplateID,
			TemplateName:        m.TemplateName,
			TemplateDescription: m.TemplateDescription,
			MatchedAt:           m.MatchedAt,
			Host:                m.Host,
			ExtractedResults:    m.Extracted,
			Request:             m.Request,
			Response:            m.Response,
			CurlCommand:         m.CurlCommand,
			RawOutput:           clipText(stdout, 256<<10),
			Command:             binPath + " " + strings.Join(args, " "),
		}
		for _, r := range refs {
			if r.ID == m.TemplateID {
				hit.TemplateSeverity = r.Severity
				break
			}
		}
		// 标题带组件/漏洞名（模板 info.name），比裸模板 id 可检索（F9：与人工记录链标题规范对齐）
		if name := strings.TrimSpace(m.TemplateName); name != "" {
			hit.VulnTitle = fmt.Sprintf("nuclei 自动验证命中：%s（%s）", name, m.TemplateID)
		} else {
			hit.VulnTitle = "nuclei 自动验证命中：" + m.TemplateID
		}
		if vID, rerr := s.recordHit(ctx, hit); rerr != nil {
			hitErrs = append(hitErrs, rerr.Error())
			log.Printf("[vulnverify] 命中落库失败 template=%s: %v", m.TemplateID, rerr)
		} else if hitVulnID == "" {
			hitVulnID = vID
		}
	}
	if hitVulnID != "" {
		finish("hit", hitVulnID, strings.Join(hitErrs, "; "), ids)
		return
	}
	if len(hitErrs) > 0 {
		finish("failed", "", strings.Join(hitErrs, "; "), ids)
		return
	}
	finish("miss", "", "", ids)
}

func (s *Service) config() Config {
	if s.opts.Cfg != nil {
		return s.opts.Cfg()
	}
	return Config{}
}

// severities 参与验证的严重级集合（动态读取，空回落 critical/high/medium）。
func (s *Service) severities() []string {
	if s.opts.Severities != nil {
		if out := s.opts.Severities(); len(out) > 0 {
			return out
		}
	}
	return []string{"critical", "high", "medium"}
}

func (s *Service) recall(ctx context.Context, task Task) ([]TemplateRef, error) {
	if s.opts.Recall == nil {
		return nil, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.opts.Recall(rctx, task.ProjectID, task.Product)
}

func (s *Service) run(ctx context.Context, binPath string, args []string) (string, error) {
	if s.opts.Runner != nil {
		return s.opts.Runner(ctx, binPath, args, jobTimeoutBase)
	}
	proxyURL := ""
	if s.opts.ProxyURLFunc != nil {
		proxyURL = strings.TrimSpace(s.opts.ProxyURLFunc())
	}
	return execRunner(ctx, binPath, args, jobTimeoutBase, proxyURL)
}

func (s *Service) recordHit(ctx context.Context, hit HitResult) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.opts.RecordHit(rctx, hit)
}

// buildNucleiArgs 组装最小验证命令（单官方模板根；多根见 buildNucleiArgsRoots）：
//
//	nuclei -u <target> -t <path1> -t <path2> ... -severity critical,high,medium
//	-json -silent -no-color -duc -rl <rate> -timeout 8 -retries 1
//
// 「最小」由三处保证：-t 只挂召回的具体模板文件（拒绝目录——目录会跑全库）、
// severity 复核一遍（召回侧漏网兜底）、资源参数硬上限。
// 返回 (args, 模板绝对路径列表)；模板文件缺失的条目跳过，全缺失返回空列表。
func buildNucleiArgs(target, templatesRoot string, refs []TemplateRef, severities []string, rateLimit int, jsonFlag string) (args []string, templatePaths []string) {
	var roots []string
	if templatesRoot != "" {
		roots = append(roots, templatesRoot)
	}
	return buildNucleiArgsRoots(target, roots, refs, severities, rateLimit, jsonFlag)
}

// buildNucleiArgsRoots 同 buildNucleiArgs，但模板根按序多份（官方在前、自定义在后，
// 知识库分域方案 P2 的 -t 双目录语义）：每个模板文件按序在根下解析，首个命中者生效。
// 导入期已阻断自定义 id 与官方冲突，因此不存在同 id 双根歧义。
func buildNucleiArgsRoots(target string, templatesRoots []string, refs []TemplateRef, severities []string, rateLimit int, jsonFlag string) (args []string, templatePaths []string) {
	if jsonFlag == "" {
		jsonFlag = "-json"
	}
	roots := templatesRoots
	if len(roots) == 0 {
		roots = []string{""} // 无根配置：按相对路径直查（保留旧行为）
	}
	args = []string{"-u", target}
	for _, r := range refs {
		if !strings.HasPrefix(r.Path, "http/") {
			continue // 只允许 http 类模板（双保险：Recall 侧已过滤）
		}
		p := ""
		for _, root := range roots {
			candidate := r.Path
			if root != "" {
				candidate = filepath.Join(root, filepath.FromSlash(r.Path))
			}
			if _, err := os.Stat(candidate); err != nil {
				continue // 该根下缺失，尝试下一个根
			}
			p = candidate
			break
		}
		if p == "" {
			continue // 所有根下都缺失：跳过
		}
		args = append(args, "-t", p)
		templatePaths = append(templatePaths, p)
	}
	if len(templatePaths) == 0 {
		return nil, nil
	}
	// severity 复核：只保留合法值（召回侧漏网兜底）
	sevSet := map[string]bool{}
	for _, sv := range severities {
		sevSet[strings.ToLower(strings.TrimSpace(sv))] = true
	}
	var sevs []string
	for _, sv := range []string{"critical", "high", "medium", "low", "info"} {
		if sevSet[sv] {
			sevs = append(sevs, sv)
		}
	}
	if len(sevs) > 0 && len(sevs) < 5 {
		args = append(args, "-severity", strings.Join(sevs, ","))
	}
	rate := rateLimit
	if rate <= 0 {
		rate = 10
	}
	if rate > maxRateLimit {
		rate = maxRateLimit
	}
	args = append(args,
		// -ni 禁 Interactsh：后台无人值守链路不向外部 OOB 服务回呼（盲打类模板
		// 因此可能漏报——取舍见方案文档 4.4，宁可漏报不做计划外出网）
		jsonFlag, "-silent", "-no-color", "-duc", "-ni",
		"-rl", fmt.Sprintf("%d", rate),
		"-timeout", fmt.Sprintf("%d", probeTimeoutSecs),
		"-retries", "1",
	)
	return args, templatePaths
}

func taskKey(t Task) string { return t.Target + "|" + t.Product }

func clipText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// ── nuclei JSONL 输出解析 ──

// NucleiMatch JSONL 里的单条命中。
type NucleiMatch struct {
	TemplateID          string
	TemplateName        string
	TemplateDescription string
	Severity            string
	MatchedAt           string
	Host                string
	IP                  string
	Extracted           []string
	Request             string // nuclei JSONL 原始请求报文（提取链原料）
	Response            string // nuclei JSONL 原始响应报文（提取链原料，如 phpinfo HTML）
	CurlCommand         string // nuclei JSONL curl 复现命令（备份文件复现下载用）
}

// ParseNucleiJSONL 解析 nuclei -json 输出：只收 matcher-status=true 的行
// （host 错误/模板错误/信息行全部忽略）；同模板多行只留首条；解析失败跳过。
// request/response/curl-command 为原始报文，超长裁剪（提取链按需再取全文）。
func ParseNucleiJSONL(stdout string) []NucleiMatch {
	var out []NucleiMatch
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var payload struct {
			TemplateID    string `json:"template-id"`
			MatchedAt     string `json:"matched-at"`
			Host          string `json:"host"`
			IP            string `json:"ip"`
			MatcherStatus bool   `json:"matcher-status"`
			Info          struct {
				Severity    string `json:"severity"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"info"`
			ExtractedResults []string `json:"extracted-results"`
			Request          string   `json:"request"`
			Response         string   `json:"response"`
			CurlCommand      string   `json:"curl-command"`
		}
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		if !payload.MatcherStatus || payload.TemplateID == "" || seen[payload.TemplateID] {
			continue
		}
		seen[payload.TemplateID] = true
		out = append(out, NucleiMatch{
			TemplateID:          payload.TemplateID,
			TemplateName:        payload.Info.Name,
			TemplateDescription: payload.Info.Description,
			Severity:            strings.ToLower(payload.Info.Severity),
			MatchedAt:           payload.MatchedAt,
			Host:                payload.Host,
			IP:                  payload.IP,
			Extracted:           payload.ExtractedResults,
			Request:             clipText(payload.Request, 64<<10),
			Response:            clipText(payload.Response, 64<<10),
			CurlCommand:         clipText(payload.CurlCommand, 8<<10),
		})
	}
	return out
}

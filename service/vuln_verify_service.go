package service

import (
	"context"
	"encoding/json"
	"regexp"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/extractor"
	"github.com/c1ayooo/4zreark/internal/vulnverify"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

// VulnVerifyService 指纹命中后的自动 nuclei 最小验证。
//
// 默认关闭：自动验证会真实发请求，必须在配置里显式打开
// （auto_verify.enabled=true）。scope fail-closed，只允许项目种子覆盖的目标。
type VulnVerifyService struct {
	svc *vulnverify.Service
}

var (
	vulnVerifyOnce sync.Once
	vulnVerifySvc  *VulnVerifyService
)

func GetVulnVerifyService() *VulnVerifyService {
	vulnVerifyOnce.Do(func() {
		vulnVerifySvc = &VulnVerifyService{}
		vulnVerifySvc.init()
	})
	return vulnVerifySvc
}

func NewVulnVerifyService() *VulnVerifyService { return GetVulnVerifyService() }

func (s *VulnVerifyService) init() {
	r := repo.Default()
	if r == nil {
		return
	}
	cacheDir := filepath.Join("data", "nuclei", "poc-cache")
	_ = os.MkdirAll(cacheDir, 0o750)

	runtime := GetNucleiRuntimeService()
	cfgFn := func() vulnverify.Config {
		cfg := config.Loaded()
		if cfg == nil {
			return vulnverify.Config{}
		}
		return vulnverify.Config{
			Configured:  true,
			Enabled:     cfg.AutoVerify.Enabled,
			RecheckDays: cfg.AutoVerify.RecheckDays,
			Concurrency: cfg.AutoVerify.Concurrency,
			RateLimit:   cfg.AutoVerify.RateLimit,
		}
	}
	s.svc = vulnverify.New(vulnverify.Options{
		Store: newPGVulnVerifyStore(r),
		Cfg:   cfgFn,
		BinPath: func() string {
			if p := runtime.BinaryPath(); p != "" {
				return p
			}
			return "nuclei"
		},
		TemplatesRoot: func() string { return cacheDir },
		CustomTemplatesRoot: func() string {
			return runtime.CustomTemplatesDir()
		},
		Severities: func() []string { return []string{"critical", "high", "medium"} },
		ScopeCheck: checkProjectScope,
		Recall:     recallTemplates(cacheDir),
		RecordHit:  recordAutoVerifyHit,
	})
}

// Start 启动 worker。未启用时也会启动（入队侧还是会拦），但不会真的执行。
func (s *VulnVerifyService) Start(ctx context.Context) {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.Start(ctx)
}

func (s *VulnVerifyService) Stop() {
	if s != nil && s.svc != nil {
		s.svc.Stop()
	}
}

// Enqueue 投递一次自动验证；未启用/出 scope 时由服务内部跳过。
func (s *VulnVerifyService) Enqueue(projectID, target, product string) {
	if s == nil || s.svc == nil {
		return
	}
	s.svc.Enqueue(vulnverify.Task{ProjectID: projectID, Target: target, Product: product})
}

// checkProjectScope 用项目种子作为授权边界；查不到种子时拒绝（fail-closed）。
func checkProjectScope(ctx context.Context, projectID, target string) error {
	id, err := parseInt64(projectID)
	if err != nil || id <= 0 {
		return fmt.Errorf("项目 ID 无效: %s", projectID)
	}
	return checkTargetScope(ctx, id, target)
}

// recallTemplates 按产品名从 POC 库召回模板，物化成 nuclei 可执行的文件。
// 只回 http/ 模板；severity 由 vulnverify 侧再复核一遍。
func recallTemplates(cacheDir string) func(ctx context.Context, projectID, product string) ([]vulnverify.TemplateRef, error) {
	return func(ctx context.Context, projectID, product string) ([]vulnverify.TemplateRef, error) {
		r := repo.Default()
		if r == nil {
			return nil, errors.New("数据库未就绪")
		}
		product = strings.TrimSpace(product)
		if product == "" {
			return nil, nil
		}
		enabled := true
		list, _, err := r.Pocs().List(ctx, repo.POCFilter{
			Type: "nuclei", Enabled: &enabled, Keyword: product, Page: 1, PageSize: 20,
		})
		if err != nil {
			return nil, err
		}
		out := make([]vulnverify.TemplateRef, 0, len(list))
		for _, p := range list {
			if p == nil || strings.TrimSpace(p.Content) == "" {
				continue
			}
			if !strings.Contains(strings.ToLower(p.Content), "http:") {
				continue // 只允许 http 类模板
			}
			rel := filepath.ToSlash(filepath.Join("http", safeTemplateFilename(p.TemplateID)+".yaml"))
			dst := filepath.Join(cacheDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
				continue
			}
			if err := os.WriteFile(dst, []byte(p.Content), 0o600); err != nil {
				log.Printf("[VulnVerify] 物化模板 %s 失败: %v", p.TemplateID, err)
				continue
			}
			out = append(out, vulnverify.TemplateRef{
				ID: p.TemplateID, Path: rel, Severity: string(p.Severity),
			})
		}
		return out, nil
	}
}

// recordAutoVerifyHit 把命中写入 4zreark 的漏洞库。完全重复（exact 指纹）时
// 复用已有漏洞 ID，不重复建行。
func recordAutoVerifyHit(ctx context.Context, hit vulnverify.HitResult) (string, error) {
	vuln := &models.Vulnerability{
		Name:       hit.VulnTitle,
		Severity:   models.VulnSeverity(normalizeSeverity(hit.Severity)),
		Type:       hit.Product,
		TemplateID: hit.TemplateID,
		Target:     firstNonEmptyStr(hit.MatchedAt, hit.Target),
		Method:     "GET",
		Evidence:   hit.MatchedAt,
		// 审计 H4：原始报文面向所有登录用户可读，落库前对凭据模式统一脱敏
		//（Authorization/Cookie/口令参数），研判需要明文的场景走后续的秘密
		// 读取授权（产品决策项）。
		Request:    maskRawTraffic(hit.Request),
		Response:   maskRawTraffic(hit.Response),
		Scanner:    "nuclei-auto",
		Tags:       []string{"auto-verify", hit.Product},
	}
	if hit.TemplateDescription != "" {
		vuln.Description = hit.TemplateDescription
	}
	// 命中报文 -> 结构化提取（备份/git/phpinfo/SFTP 配置）。
	// 只解析已有报文，不额外下载；失败不影响漏洞落库。
	if ex := extractor.ForTemplate(hit.TemplateID); ex != nil {
		if f, ferr := ex.Extract(ctx, &extractor.Ctx{
			Target: hit.Target, MatchURL: hit.MatchedAt, TemplateID: hit.TemplateID,
			Severity: hit.Severity, Request: hit.Request, Response: hit.Response,
			CurlCommand: hit.CurlCommand, Extracted: hit.ExtractedResults,
		}); ferr == nil && f != nil {
			// 审计 H4：描述面向所有登录用户可读，提取出的凭据（SFTP 密码、
			// git config 口令）必须先掩码；路径/标题类信息保留研判价值。
			vuln.Description += fmt.Sprintf("\n\n[自动提取] %s/%s: %s", f.Category, f.Kind, maskExtractedData(f.Kind, f.Data))
		}
	}
	vulnSvc := NewVulnService()
	if dups, err := vulnSvc.FindDuplicates(ctx, vuln); err == nil {
		for _, d := range dups {
			if d.Kind == "exact" {
				return d.VulnID, nil
			}
		}
	}
	if err := vulnSvc.CreateVulnerability(vuln); err != nil {
		return "", err
	}
	return vuln.ID.Hex(), nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "info"
	}
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func safeTemplateFilename(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "template"
	}
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func parseInt64(s string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	return n, err
}

// pgVulnVerifyStore 是 vulnverify.JobStore 的 PG 实现。
type pgVulnVerifyStore struct{ r *repo.Repo }

func newPGVulnVerifyStore(r *repo.Repo) vulnverify.JobStore { return &pgVulnVerifyStore{r: r} }

func (s *pgVulnVerifyStore) EnqueueJob(ctx context.Context, task vulnverify.Task, recheckDays int) (bool, error) {
	if s == nil || s.r == nil {
		return true, nil
	}
	var exists bool
	err := s.r.Pool().QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM vulnverify_jobs
		WHERE target=$1 AND product=$2 AND (
			status IN ('queued','running')
			OR (status IN ('hit','miss') AND finished_at > now() - make_interval(days => $3))
		))`, task.Target, task.Product, recheckDays).Scan(&exists)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	_, err = s.r.Pool().Exec(ctx, `INSERT INTO vulnverify_jobs(id, project_id, target, product, status)
		VALUES($1, $2, $3, $4, 'queued')`,
		"vv_"+oid.NewObjectID().Hex(), task.ProjectID, task.Target, task.Product)
	if err != nil {
		// 并发同目标撞部分唯一索引：视为已排队
		return false, nil
	}
	return true, nil
}

func (s *pgVulnVerifyStore) FinishJob(task vulnverify.Task, status, vulnID, errMsg string, templateIDs []string) error {
	if s == nil || s.r == nil {
		return nil
	}
	if templateIDs == nil {
		templateIDs = []string{}
	}
	idsJSON, _ := json.Marshal(templateIDs)
	if len(errMsg) > 2000 {
		errMsg = errMsg[:2000]
	}
	_, err := s.r.Pool().Exec(context.Background(), `UPDATE vulnverify_jobs
		SET status=$3, result_vuln_id=$4, error=$5, template_ids=$6::jsonb, finished_at=now()
		WHERE target=$1 AND product=$2 AND status IN ('queued','running')`,
		task.Target, task.Product, status, vulnID, errMsg, string(idsJSON))
	if err != nil {
		return fmt.Errorf("更新验证任务台账失败: %w", err)
	}
	return nil
}

// VerifyStats 自动验证近 N 天执行统计。
type VerifyStats struct {
	WindowDays int              `json:"window_days"`
	Finished   int64            `json:"finished"`
	Hits       int64            `json:"hits"`
	Misses     int64            `json:"misses"`
	Failures   int64            `json:"failures"`
	Skipped    int64            `json:"skipped"`
	ByStatus   map[string]int64 `json:"by_status"`
}

// Stats 聚合 vulnverify_jobs 台账。
func (s *VulnVerifyService) Stats(ctx context.Context, days int) (*VerifyStats, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	if days <= 0 {
		days = 30
	}
	rows, err := r.Pool().Query(ctx, `SELECT status, COUNT(*) FROM vulnverify_jobs
		WHERE finished_at IS NOT NULL AND finished_at > now() - make_interval(days => $1)
		GROUP BY status`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &VerifyStats{WindowDays: days, ByStatus: map[string]int64{}}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out.ByStatus[status] = n
		out.Finished += n
		switch {
		case status == "hit":
			out.Hits = n
		case status == "miss":
			out.Misses = n
		case status == "failed":
			out.Failures = n
		case strings.HasPrefix(status, "skipped"):
			out.Skipped += n
		}
	}
	return out, rows.Err()
}

// maskExtractedData 对自动验证提取出的结构化数据按类别脱敏（审计 H4）：
// sftp JSON 的 password 与 git config 的口令行缩成首末 2 字符锚点；
// 备份文件路径、phpinfo 标题等非凭据信息原样保留。
func maskExtractedData(kind, data string) string {
	maskValue := func(v string) string {
		r := []rune(v)
		if len(r) <= 4 {
			return strings.Repeat("*", len(r))
		}
		return string(r[:2]) + "…" + string(r[len(r)-2:])
	}
	switch kind {
	case "sftp":
		trimmed := strings.TrimSpace(data)
		if strings.HasPrefix(trimmed, "{") {
			var m map[string]any
			if err := json.Unmarshal([]byte(trimmed), &m); err == nil {
				for _, key := range []string{"password", "private_key"} {
					if v, ok := m[key].(string); ok && v != "" {
						m[key] = maskValue(v)
					}
				}
				if out, jerr := json.Marshal(m); jerr == nil {
					return string(out)
				}
			}
		}
		return maskValue(trimmed)
	case "git_config":
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			lower := strings.ToLower(line)
			for _, field := range []string{"password", "passwd", "pwd", "token", "secret"} {
				if idx := strings.Index(lower, field+" = "); idx >= 0 {
					val := strings.TrimSpace(line[idx+len(field)+3:])
					lines[i] = line[:idx+len(field)+3] + maskValue(val)
					break
				}
			}
		}
		return strings.Join(lines, "\n")
	default:
		return data
	}
}

// rawTrafficSecretPatterns 是原始报文里常见的凭据携带模式（审计 H4）：
// 认证头、Cookie、口令参数——值统一替换为 [REDACTED]，模式名保留可读。
var rawTrafficSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic|token)\s+)[^\r\n" ]+`),
	regexp.MustCompile(`(?i)(set-cookie:\s*[^=\r\n]+=\s*)[^\r\n;]+`),
	regexp.MustCompile(`(?i)(cookie:\s*[^=\r\n]+=\s*)[^\r\n;]+`),
	regexp.MustCompile(`(?i)(password|passwd|pwd|pass|token|api[_-]?key|access[_-]?key|secret)(=|: ?|": ?")([^"\r\n& ]{1,})`),
}

// maskRawTraffic 对原始请求/响应报文做凭据模式掩码。多次应用幂等：
// 已是 [REDACTED] 的值不再命中（模式里排除方括号段）。
func maskRawTraffic(raw string) string {
	if raw == "" {
		return ""
	}
	for _, re := range rawTrafficSecretPatterns {
		raw = re.ReplaceAllString(raw, "${1}[REDACTED]")
	}
	return raw
}

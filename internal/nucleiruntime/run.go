package nucleiruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// RunOptions 是一次 nuclei 扫描的参数。选择器（Templates/Tags/Severity/Type/
// AutomaticScan）至少给一个，避免 agent 无意中全量扫描。
type RunOptions struct {
	Targets      []string
	Templates    []string
	Tags         []string
	Severity     []string
	ExcludeTags  []string
	TemplateType string
	Automatic    bool

	Headers        map[string]string
	Proxy          string
	RateLimit      int
	BulkSize       int
	Concurrency    int
	RequestTimeout int
	Retries        int
	Interactsh     bool
	MaxDuration    time.Duration

	// ResultDir 仅测试/内部使用；生产默认 <root>/scans。
	ResultDir string
}

// Result 是一条结构化的 nuclei 命中。
type Result struct {
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	Host        string   `json:"host,omitempty"`
	MatchedAt   string   `json:"matched_at,omitempty"`
	URL         string   `json:"url,omitempty"`
	MatcherName string   `json:"matcher_name,omitempty"`
	Extracted   []string `json:"extracted,omitempty"`
	CurlCommand string   `json:"curl_command,omitempty"`
	Timestamp   string   `json:"timestamp,omitempty"`
	Request     string   `json:"request,omitempty"`
	Response    string   `json:"response,omitempty"`
}

// RunResult 是一次扫描的汇总。完整 JSONL 永远落在 ResultFile。
type RunResult struct {
	Results    []Result      `json:"results"`
	Total      int           `json:"total"`
	Targets    int           `json:"targets"`
	Templates  int           `json:"templates"`
	Duration   time.Duration `json:"duration"`
	ResultFile string        `json:"result_file"`
	Warnings   []string      `json:"warnings,omitempty"`
}

// Run 执行一次 nuclei 扫描并解析 JSONL 输出。
func (m *Manager) Run(ctx context.Context, opts RunOptions) (*RunResult, error) {
	if m == nil {
		return nil, fmt.Errorf("nuclei 管理器未初始化")
	}
	if !m.Enabled() {
		return nil, ErrDisabled
	}
	targets, err := normalizeTargets(opts.Targets)
	if err != nil {
		return nil, err
	}
	selectors := len(opts.Templates) > 0 || len(opts.Tags) > 0 || len(opts.Severity) > 0 ||
		strings.TrimSpace(opts.TemplateType) != "" || opts.Automatic
	if !selectors {
		return nil, fmt.Errorf("必须指定 templates、tags、severity、type 或 automatic 之一；" +
			"避免无选择器全量扫描（先用 nuclei_template_search 找模板）")
	}

	m.runMu.RLock()
	defer m.runMu.RUnlock()

	binary := m.BinaryPath()
	if !fileExists(binary) {
		return nil, ErrBinaryMissing
	}
	var templatePaths []string
	if len(opts.Templates) > 0 {
		templatePaths, err = m.Index().Resolve(opts.Templates)
		if err != nil {
			return nil, err
		}
	}

	scanDir := opts.ResultDir
	if strings.TrimSpace(scanDir) == "" {
		scanDir = m.ScansDir()
	}
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		return nil, fmt.Errorf("创建扫描目录失败: %w", err)
	}
	targetFile, err := os.CreateTemp(scanDir, "targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("创建目标文件失败: %w", err)
	}
	targetName := targetFile.Name()
	defer os.Remove(targetName)
	for _, t := range targets {
		if _, err := targetFile.WriteString(t + "\n"); err != nil {
			targetFile.Close()
			return nil, fmt.Errorf("写入目标文件失败: %w", err)
		}
	}
	if err := targetFile.Close(); err != nil {
		return nil, fmt.Errorf("写入目标文件失败: %w", err)
	}

	resultFile, err := os.CreateTemp(scanDir, "nuclei-*.jsonl")
	if err != nil {
		return nil, fmt.Errorf("创建结果文件失败: %w", err)
	}
	resultName := resultFile.Name()
	resultFile.Close()
	_ = os.Chmod(resultName, 0o600)
	// ResultFile 在 Run 返回后仍要可读（调用方/测试会 os.Stat），本次不删；
	// 历史文件由 cleanupOldScans 限龄清理，否则无限累积且 retention 服务不管这个目录。
	defer m.cleanupOldScans(scanDir)

	maxDur := m.MaxScanDuration()
	if opts.MaxDuration > 0 {
		maxDur = opts.MaxDuration
		if maxDur > maxMaxScan {
			maxDur = maxMaxScan
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, maxDur)
	defer cancel()

	args := m.buildArgs(opts, targetName, resultName, templatePaths)
	start := time.Now()
	cmd := exec.CommandContext(runCtx, binary, args...)
	cmd.Dir = m.root
	cmd.Env = m.env()
	var out tailBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()
	elapsed := time.Since(start)

	results, parseErr := parseResultFile(resultName)
	if parseErr != nil {
		return nil, fmt.Errorf("解析 nuclei 输出失败: %w", parseErr)
	}
	res := &RunResult{
		Results:    results,
		Total:      len(results),
		Targets:    len(targets),
		Templates:  len(templatePaths),
		Duration:   elapsed,
		ResultFile: resultName,
	}
	if runCtx.Err() != nil {
		if len(results) > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("扫描在 %s 后超时，以下为部分结果", maxDur))
			return res, nil
		}
		return nil, fmt.Errorf("nuclei 扫描超时（%s）: %s", maxDur, tail(out.String()))
	}
	if runErr != nil {
		if len(results) > 0 {
			res.Warnings = append(res.Warnings, "nuclei 退出码非 0，但已解析到部分结果: "+tail(out.String()))
			return res, nil
		}
		return nil, fmt.Errorf("nuclei 执行失败: %w: %s", runErr, tail(out.String()))
	}
	return res, nil
}

func (m *Manager) buildArgs(opts RunOptions, targetFile, resultFile string, templates []string) []string {
	rate, bulk, conc := opts.RateLimit, opts.BulkSize, opts.Concurrency
	if rate <= 0 {
		rate = 50
	}
	if bulk <= 0 {
		bulk = 25
	}
	if conc <= 0 {
		conc = 25
	}
	reqTimeout := opts.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = 10
	}
	retries := opts.Retries
	if retries < 0 {
		retries = 0
	} else if retries == 0 {
		retries = 1
	}

	args := []string{
		"-jsonl", "-silent", "-nc", "-duc", "-irr",
		"-l", targetFile, "-o", resultFile,
		"-rate-limit", fmt.Sprint(rate),
		"-bulk-size", fmt.Sprint(bulk),
		"-concurrency", fmt.Sprint(conc),
		"-timeout", fmt.Sprint(reqTimeout),
		"-retries", fmt.Sprint(retries),
		"-max-host-error", "30",
	}
	if !opts.Interactsh && !m.Interactsh() {
		// 默认不启用 interactsh：避免把目标流量引到公共 OAST 服务。
		args = append(args, "-ni")
	}
	for _, t := range templates {
		args = append(args, "-t", t)
	}
	if len(templates) == 0 {
		// 没有显式选模板时，tags/severity/type 要同时覆盖官方和自定义目录。
		if hasTemplates(m.TemplatesDir()) {
			args = append(args, "-t", m.TemplatesDir())
		}
		if hasTemplates(m.CustomTemplatesDir()) {
			args = append(args, "-t", m.CustomTemplatesDir())
		}
	}
	if len(opts.Tags) > 0 {
		args = append(args, "-tags", strings.Join(opts.Tags, ","))
	}
	if len(opts.Severity) > 0 {
		args = append(args, "-severity", strings.Join(opts.Severity, ","))
	}
	if len(opts.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(opts.ExcludeTags, ","))
	}
	if strings.TrimSpace(opts.TemplateType) != "" {
		args = append(args, "-type", strings.TrimSpace(opts.TemplateType))
	}
	if opts.Automatic {
		args = append(args, "-as")
	}
	for k, v := range opts.Headers {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || strings.ContainsAny(k+v, "\r\n") {
			continue
		}
		args = append(args, "-H", k+": "+v)
	}
	if p := strings.TrimSpace(opts.Proxy); p != "" {
		args = append(args, "-proxy", p)
	}
	return args
}

func normalizeTargets(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		if len(t) > 2048 || strings.ContainsAny(t, "\r\n\t") {
			return nil, fmt.Errorf("目标格式不合法: %q", raw)
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
		if len(out) > 500 {
			return nil, fmt.Errorf("单次扫描目标最多 500 个")
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("targets 不能为空")
	}
	return out, nil
}

type rawNucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string          `json:"name"`
		Severity       string          `json:"severity"`
		Tags           json.RawMessage `json:"tags"`
		Classification struct {
			CVEID json.RawMessage `json:"cve-id"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	URL              string   `json:"url"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand      string   `json:"curl-command"`
	Timestamp        string   `json:"timestamp"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
}

func parseResultFile(path string) ([]Result, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var out []Result
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		if r, ok := parseResultLine([]byte(line)); ok {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

func parseResultLine(line []byte) (Result, bool) {
	var raw rawNucleiResult
	if err := json.Unmarshal(line, &raw); err != nil {
		return Result{}, false
	}
	if strings.TrimSpace(raw.TemplateID) == "" && strings.TrimSpace(raw.Info.Name) == "" {
		return Result{}, false
	}
	severity := strings.ToLower(strings.TrimSpace(raw.Info.Severity))
	if severity == "" {
		severity = "unknown"
	}
	return Result{
		TemplateID:  strings.TrimSpace(raw.TemplateID),
		Name:        strings.TrimSpace(raw.Info.Name),
		Severity:    severity,
		Type:        strings.TrimSpace(raw.Type),
		Host:        strings.TrimSpace(raw.Host),
		MatchedAt:   strings.TrimSpace(raw.MatchedAt),
		URL:         strings.TrimSpace(raw.URL),
		MatcherName: strings.TrimSpace(raw.MatcherName),
		Extracted:   raw.ExtractedResults,
		CurlCommand: truncate(raw.CurlCommand, 4000),
		Timestamp:   strings.TrimSpace(raw.Timestamp),
		Request:     truncate(raw.Request, 8000),
		Response:    truncate(raw.Response, 8000),
	}, true
}

func truncate(s string, n int) string {
	if n > 0 && len(s) > n {
		return s[:n] + "…(截断)"
	}
	return s
}

// tailBuffer 只保留最后 64KB 子进程输出，防止异常路径把内存打满。
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if len(b.buf) > commandOutputLimit {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-commandOutputLimit:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(bytes.TrimSpace(b.buf))
}

// SortResults 按严重等级排序，供调用方稳定展示。
func SortResults(in []Result) {
	sort.SliceStable(in, func(a, b int) bool {
		ra, rb := severityRank(in[a].Severity), severityRank(in[b].Severity)
		if ra != rb {
			return ra > rb
		}
		return in[a].TemplateID < in[b].TemplateID
	})
}

// ResultDirFor 返回扫描结果目录（供 server 工具展示）。
func (m *Manager) ResultDirFor() string {
	if m == nil {
		return ""
	}
	return filepath.Clean(m.ScansDir())
}

// scanFileRetention 是扫描目录里临时文件的保留时长：ResultFile 在调用返回后
// 仍需可读（排障/复核），超过一天的 jsonl/targets 已无消费方，删掉防累积。
const scanFileRetention = 24 * time.Hour

// cleanupOldScans 清理扫描目录里超龄的临时文件。尽力而为：错误只记日志。
func (m *Manager) cleanupOldScans(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-scanFileRetention)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() ||
			(!strings.HasPrefix(name, "nuclei-") && !strings.HasPrefix(name, "targets-")) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			log.Printf("[nucleiruntime] 清理旧扫描文件失败 %s: %v", name, err)
		}
	}
}

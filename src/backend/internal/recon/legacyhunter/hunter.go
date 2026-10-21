package legacyhunter

// 遗留系统猎人（对标 Desinter_scan legacy_hunter §5.1）：四步法——
//  ① 拉取 Wayback 历史 URL；② 历史框架指纹匹配（正则+CVE+严重级+描述四元组）；
//  ③ 「当前 404 但历史存在」的端点 → 尝试备份后缀（复用 path_class 备份组语义）；
//  ④ EOL 技术栈标记与优先级提示。
//
// 纯逻辑 + 注入 HTTP 客户端；主动探测（当前状态/备份后缀）一律走调用方注入的
// client（app 层负责授权范围校验与代理出口）。

import (
	"context"
	"fmt"
	"github.com/c1ayooo/4zreark/internal/useragent"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

// FrameworkFingerprint 遗留/EOL 框架指纹四元组。
type FrameworkFingerprint struct {
	Name     string // 框架/技术名
	CVE      string // 关联 CVE（可空）
	Severity string // high / medium / low
	PathRe   string // 匹配历史 URL 路径的正则
	Desc     string // 描述
}

// legacyFingerprints 内置指纹四元组表（EOL/遗留技术栈 → 风险线索）。
// 顺序按特异性从高到低：特定组件指纹（Struts/WebLogic 管理端/ColdFusion）优先
// 于泛后缀（.jsp/.aspx），避免宽泛指纹抢走精确结论。
var legacyFingerprints = []FrameworkFingerprint{
	{
		Name: "Apache Struts 2", CVE: "CVE-2017-5638", Severity: "high", PathRe: `\.(action|do)$`,
		Desc: "Struts2 .action/.do 端点；旧版本存在 S2-045/046 RCE（OGNL 注入），2020 年后仍偶见于遗留内网系统",
	},
	{
		Name: "旧版 WebSphere/WebLogic 管理端", Severity: "high", PathRe: `(?:^|/)console(?:/|$)`,
		Desc: "WebLogic/WebSphere 管理端点（/console）；旧版本存在未授权访问与反序列化风险",
	},
	{
		Name: "WebLogic wls-wsat", CVE: "CVE-2017-10271", Severity: "high", PathRe: `wls-wsat`,
		Desc: "WebLogic wls-wsat 组件，存在 CVE-2017-10271/10352 反序列化 RCE",
	},
	{
		Name: "ColdFusion", CVE: "CVE-2010-2861", Severity: "high", PathRe: `\.cfm(l)?$`,
		Desc: "ColdFusion 应用；旧版本存在已知 RCE/路径穿越",
	},
	{
		Name: "Java Servlet 旧应用", Severity: "medium", PathRe: `\.jsp$`,
		Desc: "JSP 动态页面，多见于 2010 前遗留系统",
	},
	{
		Name: "旧版 ASP/ASP.NET", Severity: "medium", PathRe: `\.aspx?$`,
		Desc: "ASP/ASPX 老应用，常伴随 SQL Server 后端",
	},
	{
		Name: "旧版 PHP", Severity: "low", PathRe: `\.php\d?$`,
		Desc: "PHP 动态页面（php3/php4/php5 后缀 = 2005 前遗留系统信号）",
	},
	{
		Name: "Perl CGI", Severity: "low", PathRe: `\.(cgi|pl)$`,
		Desc: "CGI/Perl 脚本，老旧系统信号",
	},
	{
		Name: "Java Web Start", Severity: "medium", PathRe: `\.(jnlp)$`,
		Desc: "Java Web Start 启动文件，老旧 Java 客户端应用信号",
	},
}

// backupSuffixes 备份后缀探测表：历史端点当前 404 时附加尝试。
// 与 internal/fingerprint/path_class.go 的 pathStaticExts（zip/rar/bak/sql...）同语义，
// 补「基线名」形态（.git/.svn/.env 是点文件而非扩展名）。
var backupSuffixes = []string{
	".bak", ".zip", ".rar", ".7z", ".gz", ".tgz", ".tar", ".sql", ".dump", ".db",
	".old", ".orig", ".save", ".swp", ".tmp", ".env", ".config", "~",
}

// Findings 一次猎手运行的输出。
type Findings struct {
	Frameworks []FrameworkHit `json:"frameworks"`
	Endpoints  []EndpointHit  `json:"endpoints"`
	EOLNote    string         `json:"eol_note,omitempty"`
}

// FrameworkHit 历史框架指纹命中。
type FrameworkHit struct {
	URL      string `json:"url"`
	Name     string `json:"name"`
	CVE      string `json:"cve,omitempty"`
	Severity string `json:"severity"`
	Desc     string `json:"desc"`
	Priority string `json:"priority"`
}

// EndpointHit 遗留端点（历史存在、当前 404）与备份后缀探测结论。
type EndpointHit struct {
	Path       string   `json:"path"`
	BackupHits []string `json:"backup_hits,omitempty"` // 命中备份后缀的 URL
	Priority   string   `json:"priority"`
}

// Options 猎手运行参数。
type Options struct {
	// Domain 目标域（仅拉历史，不做主动探测目标）。
	Domain string
	// MaxEndpoints 参与框架指纹/备份探测的历史端点上限（默认 200）。
	MaxEndpoints int
	// EnableProbe 是否做当前状态与备份后缀探测（默认 true；关闭时只做历史指纹，零出网）。
	EnableProbe bool
	// MaxProbes 单次运行主动探测请求预算（防轰炸；默认 150）。
	MaxProbes int
	// HTTPClient 主动探测用客户端；nil = 禁用探测。
	HTTPClient *http.Client
	Timeout    time.Duration
}

// Hunter 一次运行的执行器。
type Hunter struct {
	opts  Options
	httpc *http.Client
}

// New 构造猎手。HTTPClient 为 nil 时自动关闭主动探测（只做历史指纹分析）。
func New(opts Options) *Hunter {
	h := &Hunter{opts: opts, httpc: opts.HTTPClient}
	if opts.HTTPClient == nil {
		h.opts.EnableProbe = false
	}
	return h
}

// Run 执行四步法。history 为 Wayback CDX 拉取结果（可由 QueryCDX 得到）。
func (h *Hunter) Run(ctx context.Context, history []CDXEntry) (*Findings, error) {
	maxEP := h.opts.MaxEndpoints
	if maxEP <= 0 {
		maxEP = 200
	}
	if len(history) > maxEP {
		history = history[:maxEP]
	}
	out := &Findings{}
	// ② 历史框架指纹（纯本地正则，对历史 URL 路径）。
	seenFw := map[string]bool{}
	for _, e := range history {
		u, err := url.Parse(e.Original)
		if err != nil {
			continue
		}
		for _, fp := range legacyFingerprints {
			if !seenFw[fp.Name] && matchPathPattern(u.Path, fp.PathRe) {
				seenFw[fp.Name] = true
				out.Frameworks = append(out.Frameworks, FrameworkHit{
					URL: e.Original, Name: fp.Name, CVE: fp.CVE, Severity: fp.Severity,
					Desc: fp.Desc, Priority: fp.Severity,
				})
			}
		}
	}
	// ③ 当前 404 但历史存在的端点 → 备份后缀探测。
	if h.httpc != nil && h.opts.EnableProbe {
		budget := h.opts.MaxProbes
		if budget <= 0 {
			budget = 150
		}
		for _, p := range uniquePaths(history) {
			if budget <= 0 {
				break
			}
			hit := h.probeEndpoint(ctx, p, &budget)
			if hit.Path == "" {
				continue
			}
			out.Endpoints = append(out.Endpoints, hit)
		}
	}
	// ④ EOL 标记与优先级。
	if len(out.Frameworks) > 0 || len(out.Endpoints) > 0 {
		out.EOLNote = "发现遗留系统信号：历史框架/EOL 技术栈多为内网老旧业务，漏洞优先级建议提升（先于现代面核查）。"
	}
	return out, nil
}

// probeEndpoint 对单个历史路径做：当前状态探测（404 = 消失）→ 备份后缀尝试。
// 无发现时返回 Path 为空的零值。budget 为剩余探测预算（指针递减）。
func (h *Hunter) probeEndpoint(ctx context.Context, rawPath string, budget *int) EndpointHit {
	u, err := url.Parse(h.opts.Domain)
	if err != nil || u.Host == "" {
		return EndpointHit{}
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	base := scheme + "://" + u.Host + rawPath
	// 当前状态：历史存在 → 现在 404 才算遗留端点（401/403 仍在线，不算）。
	if *budget <= 0 {
		return EndpointHit{}
	}
	*budget--
	status, err := h.headStatus(ctx, base)
	if err != nil || status != 404 {
		return EndpointHit{}
	}
	hit := EndpointHit{Path: rawPath, Priority: "medium"}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, suffix := range backupSuffixes {
		if *budget <= 0 {
			break
		}
		*budget--
		wg.Add(1)
		go func(suf string) {
			defer wg.Done()
			cand := rawPath + suf
			if s2, err2 := h.headStatus(ctx, scheme+"://"+u.Host+cand); err2 == nil && s2 == 200 {
				mu.Lock()
				hit.BackupHits = append(hit.BackupHits, cand)
				mu.Unlock()
			}
		}(suffix)
	}
	wg.Wait()
	if len(hit.BackupHits) == 0 {
		hit.Priority = "low"
	}
	return hit
}

// headStatus 单发 HEAD（回退 GET）取状态码。
func (h *Hunter) headStatus(ctx context.Context, rawURL string) (int, error) {
	timeout := h.opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", useragent.Pick())
	resp, err := h.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	return resp.StatusCode, nil
}

// uniquePaths 历史 URL 去重路径（保留出现顺序；排除静态资源）。
func uniquePaths(history []CDXEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range history {
		u, err := url.Parse(e.Original)
		if err != nil {
			continue
		}
		p := u.Path
		if p == "" {
			p = "/"
		}
		if isStaticAsset(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// isStaticAsset 排除静态资源路径（图片/字体/媒体/脚本样式），它们不是「遗留端点」候选。
func isStaticAsset(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
		".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".gz":
		return true
	}
	return false
}

// matchPathPattern 路径正则匹配。指纹表自行控制锚定（$ 结尾=全路径锚定，
// 无锚=部分匹配段特征）；容忍尾部斜杠差异。
func matchPathPattern(p, pattern string) bool {
	return regexp.MustCompile(pattern).MatchString(strings.TrimSuffix(p, "/"))
}

// FingerprintString 指纹人读摘要（工具输出用）。
func FingerprintString(f FrameworkHit) string {
	cve := ""
	if f.CVE != "" {
		cve = "（" + f.CVE + "）"
	}
	return fmt.Sprintf("%s%s 严重级=%s %s", f.Name, cve, f.Severity, f.Desc)
}

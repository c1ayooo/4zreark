// Package diffprobe 提供「基线 vs 变体」的 HTTP 差分测量。
//
// 它刻意不生成 payload，也不替 agent 下漏洞结论：agent 负责提出假设（哪些
// 请求、哪些对照），本包负责把假设变成可复核的测量——状态码、响应长度、
// 内容相似度、时延统计、DBMS 错误特征、反射标记——并给出「是否观测到稳定
// 差异」的建议性判断。这样既保留模型推理的主导权，又避免「感觉像注入」
// 直接变成 finding。
package diffprobe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

const (
	// DefaultSimilarityThreshold 高于该值视为「与基线内容一致」。
	DefaultSimilarityThreshold = 0.90
	// DefaultTimingDeltaMS 时间盲注建议的最小可观测延迟。
	DefaultTimingDeltaMS = 1000
	// DefaultTimingToleranceMS 采样抖动的容忍上限。
	DefaultTimingToleranceMS = 150
	maxRepeats               = 10
	maxVariants              = 20
	maxCompareBody           = 256 * 1024
)

// Request 是一个待测量请求。Role 用于成对对照：
//   - probe：普通变体；
//   - control：对照（如原样重放）；
//   - true/false：布尔盲注的真/假分支。
//
// Marker 非空时检查它是否出现在响应里（原样/URL 编码/HTML 转义三种形式）。
type Request struct {
	Label   string            `json:"label,omitempty"`
	Role    string            `json:"role,omitempty"`
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
	Marker  string            `json:"marker,omitempty"`
}

// Options 测量参数。
type Options struct {
	// Repeats 每个请求的采样次数。时间盲注建议 >=3；为 0 时按是否设置
	// TimingDeltaMS 自动取 1 或 3。
	Repeats int `json:"repeats,omitempty"`
	// SimilarityThreshold 内容相似度阈值，默认 0.90。
	SimilarityThreshold float64 `json:"similarity_threshold,omitempty"`
	// TimingDeltaMS 时延信号阈值（毫秒），默认 1000。
	TimingDeltaMS int64 `json:"timing_delta_ms,omitempty"`
	// TimingToleranceMS 采样抖动容忍（毫秒），默认 150。
	TimingToleranceMS int64 `json:"timing_tolerance_ms,omitempty"`
	// ErrorPatterns 额外错误特征正则；内置 MySQL/PostgreSQL/MSSQL/Oracle/SQLite。
	ErrorPatterns []string `json:"error_patterns,omitempty"`
	// Proxy / TimeoutSeconds / RandomFingerprint 透传给 httpprobe。
	Proxy             string `json:"proxy,omitempty"`
	TimeoutSeconds    int    `json:"timeout_seconds,omitempty"`
	RandomFingerprint string `json:"random_fingerprint,omitempty"`
}

// Response 是 Doer 的返回：原始探测结果 + 可选证据 ID。
type Response struct {
	Result    *httpprobe.Result
	TrafficID string
}

// Doer 执行一次 HTTP 请求。测试可注入假实现。
type Doer func(ctx context.Context, req httpprobe.Request) (Response, error)

// Sample 单次采样。
type Sample struct {
	StatusCode int    `json:"status_code"`
	BodyLen    int    `json:"body_len"`
	DurationMS int64  `json:"duration_ms"`
	TrafficID  string `json:"traffic_id,omitempty"`
}

// ErrorHit 是一条命中的错误特征。
type ErrorHit struct {
	DBMS    string `json:"dbms"`
	Snippet string `json:"snippet"`
}

// VariantResult 一个请求的聚合测量。
type VariantResult struct {
	Label         string     `json:"label"`
	Role          string     `json:"role"`
	Status        int        `json:"status"`
	BodyLen       int        `json:"body_len"`
	BodyHash      string     `json:"body_hash,omitempty"`
	Samples       []Sample   `json:"samples"`
	DurationMin   float64    `json:"duration_min_ms"`
	DurationMed   float64    `json:"duration_median_ms"`
	DurationMax   float64    `json:"duration_max_ms"`
	DurationMean  float64    `json:"duration_mean_ms"`
	DurationStd   float64    `json:"duration_stddev_ms"`
	Similarity    float64    `json:"similarity"`
	StatusChanged bool       `json:"status_changed"`
	LengthDelta   int        `json:"length_delta"`
	TimingDeltaMS float64    `json:"timing_delta_ms"`
	ErrorHits     []ErrorHit `json:"error_hits,omitempty"`
	DBMSHint      string     `json:"dbms_hint,omitempty"`
	Reflected     bool       `json:"reflected"`
	TrafficIDs    []string   `json:"traffic_ids,omitempty"`
	Error         string     `json:"error,omitempty"`

	Marker string `json:"-"`
	body   string
}

// Signal 是一条建议性信号。它表示「观测到了稳定差异」，不是漏洞结论。
type Signal struct {
	Type       string  `json:"type"`
	Variant    string  `json:"variant,omitempty"`
	Detail     string  `json:"detail"`
	Confidence float64 `json:"confidence"`
}

// Report 一次差分测量的完整结果。
type Report struct {
	Baseline   VariantResult   `json:"baseline"`
	Variants   []VariantResult `json:"variants"`
	Signals    []Signal        `json:"signals,omitempty"`
	Verdict    string          `json:"verdict"` // signal / inconclusive / no_signal
	Confidence float64         `json:"confidence"`
	DBMSHint   string          `json:"dbms_hint,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
	Options    Options         `json:"options"`
}

type errorPattern struct {
	dbms string
	re   *regexp.Regexp
}

// 内置错误特征。顺序影响 DBMS 归因，但每条都会独立匹配。
var builtinErrorPatterns = []errorPattern{
	{"MySQL", regexp.MustCompile(`(?i)(SQL syntax.*MySQL|Warning.*mysql_|MySqlException|check the manual that corresponds to your (MySQL|MariaDB) server version|Unclosed quotation mark after the character string)`)},
	{"PostgreSQL", regexp.MustCompile(`(?i)(PostgreSQL.*ERROR|pg_query\(\)|unterminated quoted string|syntax error at or near|invalid input syntax for type)`)},
	{"MSSQL", regexp.MustCompile(`(?i)(Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|SQLServer JDBC Driver|Incorrect syntax near|Microsoft SQL Server)`)},
	{"Oracle", regexp.MustCompile(`(?i)(ORA-\d{5}|Oracle error|quoted string not properly terminated)`)},
	{"SQLite", regexp.MustCompile(`(?i)(SQLite/JDBCDriver|SQLite\.Exception|sqlite3\.OperationalError|unrecognized token|near ".*": syntax error)`)},
}

var tagRe = regexp.MustCompile(`(?s)<[^>]*>`)

// Run 执行基线和全部变体。baseline 失败会直接返回错误；单个变体失败会记录在
// VariantResult.Error 中并把整体判断降级为 inconclusive。
func Run(ctx context.Context, baseline Request, variants []Request, opts Options, do Doer) (*Report, error) {
	if do == nil {
		return nil, fmt.Errorf("diffprobe: nil doer")
	}
	if strings.TrimSpace(baseline.URL) == "" {
		return nil, fmt.Errorf("diffprobe: baseline.url 为空")
	}
	if len(variants) == 0 {
		return nil, fmt.Errorf("diffprobe: 至少需要一个变体")
	}
	if len(variants) > maxVariants {
		return nil, fmt.Errorf("diffprobe: 变体数量 %d 超过上限 %d", len(variants), maxVariants)
	}
	opts = normalizeOptions(opts)
	custom, err := compilePatterns(opts.ErrorPatterns)
	if err != nil {
		return nil, err
	}
	patterns := append(append([]errorPattern{}, builtinErrorPatterns...), custom...)

	base, err := runOne(ctx, baseline, opts, patterns, do)
	if err != nil {
		return nil, fmt.Errorf("基线请求失败: %w", err)
	}
	rep := &Report{Baseline: base, Options: opts}

	for i, v := range variants {
		label := strings.TrimSpace(v.Label)
		if label == "" {
			label = fmt.Sprintf("variant-%d", i+1)
		}
		v.Label = label
		vr, runErr := runOne(ctx, v, opts, patterns, do)
		if runErr != nil {
			vr = VariantResult{Label: label, Role: normalizeRole(v.Role), Error: runErr.Error()}
		}
		vr.Similarity = Similarity(base.body, vr.body)
		vr.BodyHash = hashBody(vr.body)
		vr.StatusChanged = base.Status != 0 && vr.Status != 0 && base.Status != vr.Status
		vr.LengthDelta = vr.BodyLen - base.BodyLen
		vr.TimingDeltaMS = vr.DurationMed - base.DurationMed
		if vr.Marker != "" {
			vr.Reflected = reflected(vr.Marker, vr.body) && !reflected(vr.Marker, base.body)
		}
		rep.Variants = append(rep.Variants, vr)
	}

	assess(rep)
	return rep, nil
}

func normalizeOptions(o Options) Options {
	if o.Repeats <= 0 {
		if o.TimingDeltaMS > 0 {
			o.Repeats = 3
		} else {
			o.Repeats = 1
		}
	}
	if o.Repeats > maxRepeats {
		o.Repeats = maxRepeats
	}
	if o.SimilarityThreshold <= 0 || o.SimilarityThreshold > 1 {
		o.SimilarityThreshold = DefaultSimilarityThreshold
	}
	if o.TimingDeltaMS <= 0 {
		o.TimingDeltaMS = DefaultTimingDeltaMS
	}
	if o.TimingToleranceMS <= 0 {
		o.TimingToleranceMS = DefaultTimingToleranceMS
	}
	return o
}

func runOne(ctx context.Context, r Request, opts Options, patterns []errorPattern, do Doer) (VariantResult, error) {
	out := VariantResult{Label: strings.TrimSpace(r.Label), Role: normalizeRole(r.Role), Marker: r.Marker}
	var durations []float64
	var statuses []int
	var lengths []int
	var trafficIDs []string
	var errs []string

	for i := 0; i < opts.Repeats; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(80 * time.Millisecond):
			}
		}
		if ctx.Err() != nil {
			break
		}
		resp, err := do(ctx, httpprobe.Request{
			Method:            strings.ToUpper(strings.TrimSpace(r.Method)),
			URL:               r.URL,
			Headers:           r.Headers,
			Body:              r.Body,
			Proxy:             opts.Proxy,
			TimeoutSeconds:    opts.TimeoutSeconds,
			RandomFingerprint: opts.RandomFingerprint,
		})
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if resp.Result == nil {
			errs = append(errs, "空响应")
			continue
		}
		res := resp.Result
		out.Samples = append(out.Samples, Sample{
			StatusCode: res.StatusCode,
			BodyLen:    len(res.RespBody),
			DurationMS: res.DurationMS,
			TrafficID:  resp.TrafficID,
		})
		if out.body == "" {
			out.body = res.RespBody
		}
		durations = append(durations, float64(res.DurationMS))
		statuses = append(statuses, res.StatusCode)
		lengths = append(lengths, len(res.RespBody))
		if resp.TrafficID != "" {
			trafficIDs = append(trafficIDs, resp.TrafficID)
		}
	}

	if len(out.Samples) == 0 {
		if len(errs) == 0 {
			errs = append(errs, "无成功采样")
		}
		return out, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	out.Status = modeInt(statuses)
	out.BodyLen = medianInt(lengths)
	out.BodyHash = hashBody(out.body)
	out.DurationMin, out.DurationMax, out.DurationMed, out.DurationMean, out.DurationStd = stats(durations)
	out.TrafficIDs = trafficIDs
	out.ErrorHits = matchErrors(out.body, patterns)
	out.DBMSHint = dbmsHint(out.ErrorHits)
	if len(errs) > 0 {
		out.Error = strings.Join(errs, "; ")
	}
	return out, nil
}

func assess(rep *Report) {
	base := rep.Baseline
	best := 0.0
	add := func(s Signal) {
		s.Confidence = round2(clamp(s.Confidence, 0, 0.99))
		rep.Signals = append(rep.Signals, s)
		if s.Confidence > best {
			best = s.Confidence
		}
	}

	// 布尔对照：true/false 两条分支分别与基线比相似度，差异越大越可疑。
	var truthy, falsy *VariantResult
	for i := range rep.Variants {
		switch strings.ToLower(rep.Variants[i].Role) {
		case "true":
			truthy = &rep.Variants[i]
		case "false":
			falsy = &rep.Variants[i]
		}
	}
	if truthy != nil && falsy != nil {
		diff := math.Abs(truthy.Similarity - falsy.Similarity)
		if diff >= 0.25 {
			conf := 0.55 + 0.35*clamp((diff-0.25)/0.45, 0, 1)
			// 一条贴近基线、另一条明显偏离，是最干净的布尔信号。
			if (truthy.Similarity >= rep.Options.SimilarityThreshold && falsy.Similarity < rep.Options.SimilarityThreshold-0.08) ||
				(falsy.Similarity >= rep.Options.SimilarityThreshold && truthy.Similarity < rep.Options.SimilarityThreshold-0.08) {
				conf += 0.05
			}
			add(Signal{
				Type:       "boolean_separation",
				Variant:    truthy.Label + " vs " + falsy.Label,
				Detail:     fmt.Sprintf("true 分支相似度 %.3f，false 分支 %.3f，差 %.3f", truthy.Similarity, falsy.Similarity, diff),
				Confidence: conf,
			})
		}
	}

	for i := range rep.Variants {
		v := &rep.Variants[i]
		if v.Error != "" {
			continue
		}

		// 错误特征：基线没有而变体命中，是最直接的注入/解析异常信号。
		if len(v.ErrorHits) > 0 {
			baseDBMS := map[string]bool{}
			for _, h := range base.ErrorHits {
				baseDBMS[h.DBMS] = true
			}
			newHit := false
			for _, h := range v.ErrorHits {
				if !baseDBMS[h.DBMS] {
					newHit = true
					break
				}
			}
			if newHit {
				conf := 0.90
				if len(base.ErrorHits) > 0 {
					conf = 0.65
				}
				add(Signal{
					Type:       "error_based",
					Variant:    v.Label,
					Detail:     "命中错误特征 " + joinHits(v.ErrorHits),
					Confidence: conf,
				})
				if v.DBMSHint != "" {
					rep.DBMSHint = v.DBMSHint
				}
			}
		}

		// 时间盲注：中位数延迟达到阈值，且多数采样都过阈值。
		if delta := v.TimingDeltaMS; delta >= float64(rep.Options.TimingDeltaMS) {
			threshold := float64(rep.Options.TimingDeltaMS)
			over := 0
			for _, s := range v.Samples {
				if float64(s.DurationMS)-base.DurationMed >= threshold {
					over++
				}
			}
			ratio := float64(over) / float64(len(v.Samples))
			if ratio >= 0.60 {
				conf := 0.55 + 0.40*clamp((delta-threshold)/threshold, 0, 1)
				conf *= ratio
				if len(v.Samples) == 1 {
					conf *= 0.70 // 单采样不足以排除网络抖动
				}
				add(Signal{
					Type:       "time_based",
					Variant:    v.Label,
					Detail:     fmt.Sprintf("中位时延 +%.0fms（阈值 %dms），%d/%d 次采样过阈值", delta, rep.Options.TimingDeltaMS, over, len(v.Samples)),
					Confidence: conf,
				})
			}
		}

		// 状态码变化：500/403 等异常值得注意，但单凭状态码不足以定论。
		if v.StatusChanged {
			conf := 0.40
			if v.Status >= 500 && base.Status > 0 && base.Status < 400 {
				conf = 0.65
			} else if v.Status >= 400 && base.Status > 0 && base.Status < 400 {
				conf = 0.55
			}
			add(Signal{
				Type:       "status_change",
				Variant:    v.Label,
				Detail:     fmt.Sprintf("状态码 %d → %d", base.Status, v.Status),
				Confidence: conf,
			})
		}

		// 内容长度变化：弱信号，必须同时内容不相似才提示。
		minDelta := math.Max(64, float64(base.BodyLen)*0.15)
		if math.Abs(float64(v.LengthDelta)) >= minDelta && v.Similarity < rep.Options.SimilarityThreshold {
			add(Signal{
				Type:       "length_change",
				Variant:    v.Label,
				Detail:     fmt.Sprintf("响应长度 %+d 字节，相似度 %.3f", v.LengthDelta, v.Similarity),
				Confidence: 0.40,
			})
		}

		// 反射：只说明输入进入了响应，不等于可利用。
		if v.Reflected {
			add(Signal{
				Type:       "reflection",
				Variant:    v.Label,
				Detail:     "marker 出现在响应中（基线未出现）",
				Confidence: 0.35,
			})
		}
	}

	switch {
	case best >= 0.60:
		rep.Verdict = "signal"
	case best >= 0.35:
		rep.Verdict = "inconclusive"
	default:
		rep.Verdict = "no_signal"
	}
	rep.Confidence = round2(best)

	// 失败变体是重要的不确定性来源。
	for _, v := range rep.Variants {
		if v.Error != "" {
			rep.Verdict = "inconclusive"
			rep.Notes = append(rep.Notes, fmt.Sprintf("变体 %s 未取得有效采样，结论不可靠", v.Label))
		}
	}
}

// Similarity 返回两段响应内容的 Jaccard 相似度（0..1）。比较前会剥离
// HTML 标签、解码实体、压缩空白并小写化，降低模板噪声的影响。
func Similarity(a, b string) float64 {
	if a == b {
		return 1
	}
	an, bn := normalizeText(a), normalizeText(b)
	if an == "" || bn == "" {
		return 0
	}
	as, bs := shingles(an), shingles(bn)
	if len(as) == 0 || len(bs) == 0 {
		return 0
	}
	inter := 0
	for s := range as {
		if _, ok := bs[s]; ok {
			inter++
		}
	}
	union := len(as) + len(bs) - inter
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func normalizeText(s string) string {
	if len(s) > maxCompareBody {
		s = s[:maxCompareBody]
	}
	s = tagRe.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = strings.ToLower(s)
	return strings.Join(strings.Fields(s), " ")
}

func shingles(s string) map[string]struct{} {
	const n = 4
	r := []rune(s)
	if len(r) < n {
		if len(r) == 0 {
			return nil
		}
		return map[string]struct{}{string(r): {}}
	}
	out := make(map[string]struct{}, len(r)-n+1)
	for i := 0; i+n <= len(r); i++ {
		out[string(r[i:i+n])] = struct{}{}
	}
	return out
}

func hashBody(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func compilePatterns(patterns []string) ([]errorPattern, error) {
	out := make([]errorPattern, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("diffprobe: 错误特征正则无效 %q: %w", p, err)
		}
		out = append(out, errorPattern{dbms: "custom", re: re})
	}
	return out, nil
}

func matchErrors(body string, patterns []errorPattern) []ErrorHit {
	if body == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []ErrorHit
	for _, p := range patterns {
		m := p.re.FindString(body)
		if m == "" {
			continue
		}
		if seen[p.dbms] {
			continue
		}
		seen[p.dbms] = true
		out = append(out, ErrorHit{DBMS: p.dbms, Snippet: truncateRunes(strings.TrimSpace(m), 160)})
	}
	return out
}

func dbmsHint(hits []ErrorHit) string {
	if len(hits) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var names []string
	for _, h := range hits {
		if h.DBMS == "" || seen[h.DBMS] {
			continue
		}
		seen[h.DBMS] = true
		names = append(names, h.DBMS)
	}
	return strings.Join(names, "|")
}

func joinHits(hits []ErrorHit) string {
	var parts []string
	for _, h := range hits {
		parts = append(parts, fmt.Sprintf("%s(%s)", h.DBMS, h.Snippet))
	}
	return strings.Join(parts, "；")
}

func reflected(marker, body string) bool {
	if marker == "" || body == "" {
		return false
	}
	if strings.Contains(body, marker) {
		return true
	}
	// 常见的服务端转义/编码形式。
	if strings.Contains(body, html.EscapeString(marker)) {
		return true
	}
	if strings.Contains(body, url.QueryEscape(marker)) {
		return true
	}
	return false
}

func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "control":
		return "control"
	case "true", "truthy", "1":
		return "true"
	case "false", "falsy", "0":
		return "false"
	default:
		return "probe"
	}
}

func modeInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	counts := map[int]int{}
	best, bestN := xs[0], 0
	for _, x := range xs {
		counts[x]++
		if counts[x] > bestN {
			best, bestN = x, counts[x]
		}
	}
	return best
}

func medianInt(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]int(nil), xs...)
	sort.Ints(cp)
	return cp[len(cp)/2]
}

func stats(xs []float64) (min, max, median, mean, std float64) {
	if len(xs) == 0 {
		return 0, 0, 0, 0, 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	min, max = cp[0], cp[len(cp)-1]
	median = cp[len(cp)/2]
	if len(cp)%2 == 0 {
		median = (cp[len(cp)/2-1] + cp[len(cp)/2]) / 2
	}
	var sum float64
	for _, x := range cp {
		sum += x
	}
	mean = sum / float64(len(cp))
	var sq float64
	for _, x := range cp {
		sq += (x - mean) * (x - mean)
	}
	std = math.Sqrt(sq / float64(len(cp)))
	return
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Text 渲染面向模型的可读摘要。结论措辞刻意保持为「观测到差异」，避免把
// 测量结果直接当成漏洞。
func (r *Report) Text() string {
	if r == nil {
		return "差分探测无结果"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "差分探测结果：verdict=%s confidence=%.2f\n", r.Verdict, r.Confidence)
	fmt.Fprintf(&b, "参数：repeats=%d 相似度阈值=%.2f 时延阈值=%dms\n\n", r.Options.Repeats, r.Options.SimilarityThreshold, r.Options.TimingDeltaMS)
	writeVariant(&b, "基线", r.Baseline, true)
	for _, v := range r.Variants {
		writeVariant(&b, "变体", v, false)
	}
	if len(r.Signals) > 0 {
		b.WriteString("\n信号（建议性，不是漏洞结论）：\n")
		for _, s := range r.Signals {
			fmt.Fprintf(&b, "- [%s] %s 置信度 %.2f：%s\n", s.Type, s.Variant, s.Confidence, s.Detail)
		}
	} else {
		b.WriteString("\n未观测到稳定差异化信号。这不等于不存在漏洞：可能是参数/编码/字段不对，或需要更多采样。\n")
	}
	if r.DBMSHint != "" {
		fmt.Fprintf(&b, "DBMS 线索：%s\n", r.DBMSHint)
	}
	if len(r.Notes) > 0 {
		b.WriteString("注意：\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	b.WriteString("\n证据：每个采样都带 traffic_id；可用 bind_finding_traffic 绑定。请结合响应内容与业务语义确认，不要仅凭本结果上报。\n")
	return b.String()
}

func writeVariant(b *strings.Builder, prefix string, v VariantResult, baseline bool) {
	label := v.Label
	if label == "" {
		label = "-"
	}
	if baseline {
		fmt.Fprintf(b, "%s: status=%d len=%d", prefix, v.Status, v.BodyLen)
	} else {
		fmt.Fprintf(b, "%s %s (role=%s): status=%d len=%d sim=%.3f Δlen=%+d Δt=%+.0fms",
			prefix, label, v.Role, v.Status, v.BodyLen, v.Similarity, v.LengthDelta, v.TimingDeltaMS)
	}
	fmt.Fprintf(b, " 时延[min/med/max]=%.0f/%.0f/%.0fms σ=%.0f", v.DurationMin, v.DurationMed, v.DurationMax, v.DurationStd)
	if len(v.ErrorHits) > 0 {
		fmt.Fprintf(b, " 错误特征=%s", joinHits(v.ErrorHits))
	}
	if v.Reflected {
		b.WriteString(" 反射=yes")
	}
	if v.Error != "" {
		fmt.Fprintf(b, " 错误=%s", v.Error)
	}
	b.WriteString("\n")
	if len(v.TrafficIDs) > 0 {
		fmt.Fprintf(b, "  证据 traffic_id: %s\n", strings.Join(v.TrafficIDs, ", "))
	}
}

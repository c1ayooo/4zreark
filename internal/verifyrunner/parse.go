package verifyrunner

// parse.go —— 剧本 YAML 解析 + 红线静态检查（施工单 E1）。
//
// 静态检查是「防模板变爆破」的第一道闸（施工单红线 2）：
//   - 步骤数 / 请求总量 / repeat 超硬顶 → 拒绝加载；
//   - 方法白名单（GET/POST/PUT/HEAD/OPTIONS）；
//   - 并发声明 >1 拒绝（runner 恒串行）；
//   - {{var}} 闭包校验：引用的变量必须在入参或前序 extract 里声明，防运行期静默空串；
//   - 步骤词汇表封闭（V1/V2）：kind ∈ {http,tcp,dns}，request/expect 字段按 kind
//     分词汇表——tcp payload ≤512B、dns 拒绝自定义 resolver、未知 kind 一律拒绝。

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// allowedMethods 剧本允许的 HTTP 方法。TRACE/CONNECT 等一律拒绝。
var allowedMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "HEAD": true, "OPTIONS": true,
}

// varRefRE 匹配 {{name}} 变量引用。
var varRefRE = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// LoadPlaybookFromBytes 解析并校验单个剧本。
func LoadPlaybookFromBytes(data []byte) (*Playbook, error) {
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("剧本 YAML 解析失败: %w", err)
	}
	if err := ValidatePlaybook(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}

// ValidatePlaybook 红线校验（导出）：预设剧本（parse 后）与模型 inline 步骤（verify_run
// 构造后）共用同一套红线——执行保真不区分步骤来源。
func ValidatePlaybook(pb *Playbook) error {
	return validatePlaybook(pb)
}

// LoadPlaybooksFromDir 加载目录下全部 *.yaml/*.yml 剧本（parse 失败的文件跳过并返回错误，
// 不阻断其余剧本——与 workflow seed loader 同策略）。
func LoadPlaybooksFromDir(dir string) (map[string]*Playbook, []error) {
	out := map[string]*Playbook{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, []error{fmt.Errorf("读取剧本目录失败 %s: %w", dir, err)}
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			errs = append(errs, fmt.Errorf("读取剧本 %s 失败: %w", name, rerr))
			continue
		}
		pb, perr := LoadPlaybookFromBytes(data)
		if perr != nil {
			errs = append(errs, fmt.Errorf("剧本 %s: %w", name, perr))
			continue
		}
		if _, dup := out[pb.ID]; dup {
			errs = append(errs, fmt.Errorf("剧本 %s: id %q 重复", name, pb.ID))
			continue
		}
		out[pb.ID] = pb
	}
	return out, errs
}

// validatePlaybook 红线静态检查 + 变量闭包推导。
func validatePlaybook(pb *Playbook) error {
	pb.ID = strings.TrimSpace(pb.ID)
	if pb.ID == "" {
		return fmt.Errorf("剧本缺 id")
	}
	if len(pb.Steps) == 0 {
		return fmt.Errorf("剧本 %s 无步骤", pb.ID)
	}
	if len(pb.Steps) > MaxStepsHard {
		return fmt.Errorf("剧本 %s 步骤数 %d 超硬顶 %d（防爆破红线）", pb.ID, len(pb.Steps), MaxStepsHard)
	}
	total := 0
	for i := range pb.Steps {
		st := &pb.Steps[i]
		if strings.TrimSpace(st.Name) == "" {
			return fmt.Errorf("剧本 %s 第 %d 步缺 name", pb.ID, i+1)
		}
		kind, kerr := normalizeStepKind(st.Kind)
		if kerr != nil {
			return fmt.Errorf("剧本 %s 第 %d 步 %v", pb.ID, i+1, kerr)
		}
		st.Kind = kind
		if rerr := validateStepRequest(pb.ID, i+1, kind, st); rerr != nil {
			return rerr
		}
		if st.Expect == nil && len(st.Extract) == 0 {
			return fmt.Errorf("剧本 %s 第 %d 步既无 expect 也无 extract（纯请求步骤无意义）", pb.ID, i+1)
		}
		if eerr := validateStepExpect(pb.ID, i+1, kind, st.Expect); eerr != nil {
			return eerr
		}
		if xerr := validateStepExtract(pb.ID, i+1, kind, st.Extract); xerr != nil {
			return xerr
		}
		r := st.Request.Repeat
		if r < 0 {
			r = 0
		}
		if r > MaxRepeatPerStep {
			return fmt.Errorf("剧本 %s 第 %d 步 repeat=%d 超上限 %d（防爆破红线）", pb.ID, i+1, r, MaxRepeatPerStep)
		}
		total += r + 1
	}
	maxReq := pb.Limits.MaxRequests
	if maxReq <= 0 {
		maxReq = DefaultMaxRequests
	}
	if maxReq > MaxRequestsHard {
		return fmt.Errorf("剧本 %s max_requests=%d 超硬顶 %d（防爆破红线）", pb.ID, maxReq, MaxRequestsHard)
	}
	if total > maxReq {
		return fmt.Errorf("剧本 %s 潜在请求总量 %d 超过自报 max_requests=%d（收紧 limits 或删步骤）", pb.ID, total, maxReq)
	}
	if pb.Limits.Concurrency > 1 {
		return fmt.Errorf("剧本 %s 声明并发 %d：runner 恒串行（红线：并发 ≤2 取更严）", pb.ID, pb.Limits.Concurrency)
	}
	t := pb.Limits.PerStepTimeoutMS
	if t < 0 || t > int(MaxStepTimeout/time.Millisecond) {
		return fmt.Errorf("剧本 %s per_step_timeout_ms=%d 超范围（0~%d）", pb.ID, t, MaxStepTimeout/time.Millisecond)
	}

	// 变量闭包：所有 {{var}} 引用 ≤ 前序 extract 产出 ∪ 内置（host）∪ 剧本声明（vars_required）
	available := map[string]bool{"host": true}
	for _, v := range pb.VarsRequired {
		available[strings.TrimSpace(v)] = true
	}
	for i, st := range pb.Steps {
		refs := varRefRE.FindAllStringSubmatch(renderableText(st), -1)
		for _, m := range refs {
			name := m[1]
			if !available[name] {
				return fmt.Errorf("剧本 %s 第 %d 步引用未定义变量 {{%s}}（须在 vars_required 声明或前序步骤 extract 产出）", pb.ID, i+1, name)
			}
		}
		for _, ex := range st.Extract {
			available[ex.Name] = true
		}
	}
	return nil
}

// ── 步骤词汇表（施工单 V1/V2）：request/expect 字段按 kind 封闭 ──

// requestVocabByKind / expectVocabByKind 各 kind 允许的字段名（repeat 为通用字段不在此列）。
// 词汇表封闭的立场：verify_run 是假设验证原语（观测+断言），不是自由执行通道——
// 跨 kind 混用字段基本是模型把 tcp/dns 步当 http 步写的笔误，parse 期报错比静默忽略便宜。
var requestVocabByKind = map[string]map[string]bool{
	StepKindHTTP: {"method": true, "url": true, "headers": true, "body": true},
	StepKindTCP:  {"host": true, "port": true, "payload_hex": true},
	StepKindDNS:  {"query_name": true, "query_type": true},
}

var expectVocabByKind = map[string]map[string]bool{
	StepKindHTTP: {"status": true, "status_in": true, "contains": true, "contains_any": true, "not_contains": true, "regex": true,
		"resp_header_contains": true, "resp_header_regex": true, "duration_ms_lt": true, "duration_ms_gt": true},
	StepKindTCP: {"connect_ok": true, "banner_contains": true, "banner_not_contains": true, "banner_regex": true,
		"duration_ms_lt": true, "duration_ms_gt": true},
	StepKindDNS: {"resolve_contains": true, "cname_chain_contains": true, "txt_contains": true, "resolve_count_lt": true,
		"duration_ms_lt": true, "duration_ms_gt": true},
}

// normalizeStepKind kind 归一与校验：空 → http（兼容红线）；未知值拒绝（词汇表封闭）。
func normalizeStepKind(kind string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(kind))
	switch k {
	case "", StepKindHTTP:
		return StepKindHTTP, nil
	case StepKindTCP, StepKindDNS:
		return k, nil
	}
	return "", fmt.Errorf("kind %q 不在步骤词汇表（http/tcp/dns）", kind)
}

// KindOf 归一步骤 kind（空/未知 → http）。parse 期已拒绝未知值；本导出函数供
// 工具层分派（tcp/dns 步的 scope 校验）与运行期兜底使用。
func KindOf(kind string) string {
	switch k := strings.ToLower(strings.TrimSpace(kind)); k {
	case StepKindTCP, StepKindDNS:
		return k
	default:
		return StepKindHTTP
	}
}

// validateStepRequest 按 kind 校验 request 字段集与必填项（就地归一 method/query_type）。
func validateStepRequest(pbID string, idx int, kind string, st *Step) error {
	for _, f := range sortedFields(requestFieldSet(&st.Request)) {
		if !requestVocabByKind[kind][f] {
			if f == "resolver" {
				// 红线单列：dns 查询固定走平台侧 resolver，步骤内自定义即拒
				return fmt.Errorf("剧本 %s 第 %d 步 resolver 不可自定义：查询固定走平台侧解析器（红线）", pbID, idx)
			}
			return fmt.Errorf("剧本 %s 第 %d 步（kind=%s）request 字段 %q 不在词汇表（可用：%s）", pbID, idx, kind, f, vocabList(requestVocabByKind[kind]))
		}
	}
	switch kind {
	case StepKindHTTP:
		m := strings.ToUpper(strings.TrimSpace(st.Request.Method))
		if !allowedMethods[m] {
			return fmt.Errorf("剧本 %s 第 %d 步方法 %q 不在白名单（GET/POST/PUT/HEAD/OPTIONS）", pbID, idx, st.Request.Method)
		}
		st.Request.Method = m
		if strings.TrimSpace(st.Request.URL) == "" {
			return fmt.Errorf("剧本 %s 第 %d 步缺 request.url", pbID, idx)
		}
	case StepKindTCP:
		if strings.TrimSpace(st.Request.Host) == "" {
			return fmt.Errorf("剧本 %s 第 %d 步缺 request.host（tcp 步）", pbID, idx)
		}
		if st.Request.Port < 1 || st.Request.Port > 65535 {
			return fmt.Errorf("剧本 %s 第 %d 步 request.port=%d 越界（1~65535）", pbID, idx, st.Request.Port)
		}
		if hexStr := strings.TrimSpace(st.Request.PayloadHex); hexStr != "" {
			payload, err := hex.DecodeString(hexStr)
			if err != nil {
				return fmt.Errorf("剧本 %s 第 %d 步 payload_hex 非法（须为 hex 编码）: %v", pbID, idx, err)
			}
			if len(payload) > MaxTCPPayloadBytes {
				return fmt.Errorf("剧本 %s 第 %d 步 payload %d 字节超上限 %d（tcp 步红线）", pbID, idx, len(payload), MaxTCPPayloadBytes)
			}
		}
	case StepKindDNS:
		if strings.TrimSpace(st.Request.QueryName) == "" {
			return fmt.Errorf("剧本 %s 第 %d 步缺 request.query_name（dns 步）", pbID, idx)
		}
		qt := strings.ToUpper(strings.TrimSpace(st.Request.QueryType))
		if qt == "" {
			qt = "A"
		}
		switch qt {
		case "A", "CNAME", "TXT", "NS":
		default:
			return fmt.Errorf("剧本 %s 第 %d 步 query_type %q 不在白名单（A/CNAME/TXT/NS）", pbID, idx, st.Request.QueryType)
		}
		st.Request.QueryType = qt
	}
	return nil
}

// validateStepExpect 按 kind 校验断言字段集 + 正则编译。
func validateStepExpect(pbID string, idx int, kind string, ex *Expectation) error {
	if ex == nil {
		return nil
	}
	for _, f := range sortedFields(expectFieldSet(ex)) {
		if !expectVocabByKind[kind][f] {
			return fmt.Errorf("剧本 %s 第 %d 步（kind=%s）断言字段 %q 不在词汇表（可用：%s）", pbID, idx, kind, f, vocabList(expectVocabByKind[kind]))
		}
	}
	if ex.Regex != "" {
		if _, err := regexp.Compile(ex.Regex); err != nil {
			return fmt.Errorf("剧本 %s 第 %d 步 expect 正则非法: %v", pbID, idx, err)
		}
	}
	if ex.RespHeaderRegex != "" {
		if _, err := regexp.Compile(ex.RespHeaderRegex); err != nil {
			return fmt.Errorf("剧本 %s 第 %d 步 resp_header_regex 正则非法: %v", pbID, idx, err)
		}
	}
	if ex.BannerRegex != "" {
		if _, err := regexp.Compile(ex.BannerRegex); err != nil {
			return fmt.Errorf("剧本 %s 第 %d 步 banner_regex 正则非法: %v", pbID, idx, err)
		}
	}
	return nil
}

// validateStepExtract 按 kind 校验提取面：tcp 只许 from banner；dns 无提取面（V2 只做观测断言）。
func validateStepExtract(pbID string, idx int, kind string, extracts []StepExtract) error {
	if kind == StepKindDNS && len(extracts) > 0 {
		return fmt.Errorf("剧本 %s 第 %d 步（kind=dns）不支持 extract（dns 观测结果无提取面）", pbID, idx)
	}
	for _, ex := range extracts {
		if strings.TrimSpace(ex.Name) == "" || strings.TrimSpace(ex.Regex) == "" {
			return fmt.Errorf("剧本 %s 第 %d 步 extract 须同时声明 name 与 regex", pbID, idx)
		}
		if _, err := regexp.Compile(ex.Regex); err != nil {
			return fmt.Errorf("剧本 %s 第 %d 步 extract 正则非法: %v", pbID, idx, err)
		}
		from := strings.ToLower(strings.TrimSpace(ex.From))
		if kind == StepKindTCP {
			if from != "" && from != "banner" {
				return fmt.Errorf("剧本 %s 第 %d 步 extract.from 只支持 banner（tcp 步）", pbID, idx)
			}
			continue
		}
		if from != "" && from != "body" && from != "headers" {
			return fmt.Errorf("剧本 %s 第 %d 步 extract.from 只支持 body/headers", pbID, idx)
		}
	}
	return nil
}

// requestFieldSet / expectFieldSet 已声明（非零值）字段名集合（词汇表校验用）。
func requestFieldSet(r *StepRequest) map[string]bool {
	set := map[string]bool{}
	if strings.TrimSpace(r.Method) != "" {
		set["method"] = true
	}
	if strings.TrimSpace(r.URL) != "" {
		set["url"] = true
	}
	if len(r.Headers) > 0 {
		set["headers"] = true
	}
	if r.Body != "" {
		set["body"] = true
	}
	if strings.TrimSpace(r.Host) != "" {
		set["host"] = true
	}
	if r.Port != 0 {
		set["port"] = true
	}
	if strings.TrimSpace(r.PayloadHex) != "" {
		set["payload_hex"] = true
	}
	if strings.TrimSpace(r.QueryName) != "" {
		set["query_name"] = true
	}
	if strings.TrimSpace(r.QueryType) != "" {
		set["query_type"] = true
	}
	if strings.TrimSpace(r.Resolver) != "" {
		set["resolver"] = true
	}
	return set
}

func expectFieldSet(ex *Expectation) map[string]bool {
	set := map[string]bool{}
	if ex.Status != 0 {
		set["status"] = true
	}
	if len(ex.StatusIn) > 0 {
		set["status_in"] = true
	}
	if len(ex.Contains) > 0 {
		set["contains"] = true
	}
	if len(ex.ContainsAny) > 0 {
		set["contains_any"] = true
	}
	if len(ex.NotContains) > 0 {
		set["not_contains"] = true
	}
	if ex.Regex != "" {
		set["regex"] = true
	}
	if len(ex.RespHeaderContains) > 0 {
		set["resp_header_contains"] = true
	}
	if ex.RespHeaderRegex != "" {
		set["resp_header_regex"] = true
	}
	if ex.DurationMSLt > 0 {
		set["duration_ms_lt"] = true
	}
	if ex.DurationMSGt > 0 {
		set["duration_ms_gt"] = true
	}
	if ex.ConnectOK != nil {
		set["connect_ok"] = true
	}
	if len(ex.BannerContains) > 0 {
		set["banner_contains"] = true
	}
	if len(ex.BannerNotContains) > 0 {
		set["banner_not_contains"] = true
	}
	if ex.BannerRegex != "" {
		set["banner_regex"] = true
	}
	if len(ex.ResolveContains) > 0 {
		set["resolve_contains"] = true
	}
	if len(ex.CnameChainContains) > 0 {
		set["cname_chain_contains"] = true
	}
	if len(ex.TxtContains) > 0 {
		set["txt_contains"] = true
	}
	if ex.ResolveCountLT > 0 {
		set["resolve_count_lt"] = true
	}
	return set
}

// sortedFields 字段名排序（错误信息稳定 + 首个报错字段确定）。
func sortedFields(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// vocabList 词汇表名列表（错误提示用）。
func vocabList(vocab map[string]bool) string {
	return strings.Join(sortedFields(vocab), "/")
}

// renderableText 拼接步骤中所有参与变量渲染的字段（闭包检查用；tcp 步的
// host 与 dns 步的 query_name 都可能携带 {{var}}）。
func renderableText(st Step) string {
	var b strings.Builder
	b.WriteString(st.Request.URL)
	b.WriteByte('\n')
	b.WriteString(st.Request.Body)
	b.WriteByte('\n')
	b.WriteString(st.Request.Host)
	b.WriteByte('\n')
	b.WriteString(st.Request.QueryName)
	b.WriteByte('\n')
	for k, v := range st.Request.Headers {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String()
}

// RenderVars 把 {{var}} 替换为实际值；未定义变量保留原样（闭包校验已在 parse 期拦截，
// 运行期入参缺失的变量由 verify_run 工具层校验）。
func RenderVars(text string, vars map[string]string) string {
	return varRefRE.ReplaceAllStringFunc(text, func(m string) string {
		sub := varRefRE.FindStringSubmatch(m)
		if len(sub) < 2 {
			return m
		}
		if v, ok := vars[sub[1]]; ok {
			return v
		}
		return m
	})
}

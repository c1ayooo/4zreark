package fingerprint

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/c1ayooo/4zreark/config"
	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"gopkg.in/yaml.v3"
)

// DSLEngine 指纹识别引擎。
//
// T10 起内部直接使用 internal/recon/fingerprint 的表达式解析器与 AST（支持 && / || / ! / 括号），
// 不再保留旧的逐函数 dispatch 求值器。两套规则并存于同一个规则表：
//   - 内置规则（dddd 快照 + 种子）：表达式原样编译；
//   - 旧 YAML 规则（finger.yaml / sensitive.yaml）：加载时把
//     contains / contains_all / title / regex / status / header / icon
//     翻译成表达式，规则文件一行不改。
//
// 对外 API（LoadRulesFromFile / AnalyzeResponse / RulesCount）保持兼容。
type DSLEngine struct {
	// Rules 只保存 YAML 加载的原始规则视图（兼容旧调用方）；内置规则不在这里。
	Rules map[string]*FingerprintRule

	mu       sync.RWMutex
	compiled map[string]*compiledRule

	// gram 索引：把「表达式里的必需字面量 → 规则名」建倒排。
	// 长字面量（>=8 字节）用 8-gram，短字面量（4–7 字节）用 4-gram：
	// 4-gram 对长短语误报太多（例如 explorer 的 lore 会命中 lorem）。
	// 大 body 时先求候选集，再对候选跑 AST；索引只用于收窄，不做判定。
	gramLong   map[string][]string // 8-gram
	gramShort  map[string][]string // 4-gram
	alwaysFull []string            // 没有可用字面量的规则，必须全量求值
}

// compiledRule 一条待匹配规则：每个 DSL 行对应一个已编译 AST。
type compiledRule struct {
	name      string
	category  string
	tags      []string
	condition string // and / or
	dsl       []string
	exprs     []reconfp.Expr
	builtin   bool
}

// NewDSLEngine 创建新的 DSL 引擎（空规则表；内置规则用 LoadBuiltinRules 显式加载）。
func NewDSLEngine() *DSLEngine {
	return &DSLEngine{
		Rules:     make(map[string]*FingerprintRule),
		compiled:  make(map[string]*compiledRule),
		gramLong:  make(map[string][]string),
		gramShort: make(map[string][]string),
	}
}

// bigBodyThreshold 超过该长度的 body 才启用 gram 预筛：
// 小响应本身求值就快，建索引与查询 gram 反而更贵。
const bigBodyThreshold = 4096

// 双 gram 长度：长字面量用 8，短字面量用 4（避免 4-gram 对长短语误报）。
const (
	gramLongLen  = 8
	gramShortLen = 4
)

// rebuildGramIndex 重建 gram 索引。调用方需持 e.mu。
func (e *DSLEngine) rebuildGramIndex() {
	e.gramLong = make(map[string][]string, len(e.compiled))
	e.gramShort = make(map[string][]string, len(e.compiled))
	e.alwaysFull = nil

	for name, rule := range e.compiled {
		lits, ok := ruleLiterals(rule)
		added := false
		if ok {
			for _, raw := range lits {
				v := strings.ToLower(raw)
				switch {
				case len(v) >= gramLongLen:
					addGrams(e.gramLong, v, gramLongLen, name)
					added = true
				case len(v) >= gramShortLen:
					addGrams(e.gramShort, v, gramShortLen, name)
					added = true
				}
			}
		}
		if !added {
			e.alwaysFull = append(e.alwaysFull, name)
		}
	}
}

func addGrams(index map[string][]string, value string, n int, name string) {
	seen := make(map[string]bool, len(value))
	for i := 0; i+n <= len(value); i++ {
		g := value[i : i+n]
		if seen[g] {
			continue
		}
		seen[g] = true
		index[g] = append(index[g], name)
	}
}

// ruleLiterals 返回「任意成功匹配都必然出现」的字面量。
//
// 只收安全子集：= / == 叶子可以保证值存在；&& 只要一侧安全即可；
// || 必须两侧都安全（否则另一条分支可能不带字面量命中）；! 不收。
// 没有安全字面量的规则进 alwaysFull，宁可多算也不能漏。
func ruleLiterals(rule *compiledRule) ([]string, bool) {
	lits := make([]string, 0, 4)
	if strings.EqualFold(rule.condition, "and") {
		for _, expr := range rule.exprs {
			if req, ok := requiredLiterals(expr); ok {
				lits = append(lits, req...)
			}
		}
	} else {
		for _, expr := range rule.exprs {
			req, ok := requiredLiterals(expr)
			if !ok {
				return nil, false
			}
			lits = append(lits, req...)
		}
	}
	return lits, len(lits) > 0
}

// requiredLiterals 返回「该子树一旦匹配，其中至少一个值必然出现」的字面量集合。
// ok=false 表示无法保证（含 !、!=、~=、>=、<=，或 OR 只有一侧安全）。
func requiredLiterals(expr reconfp.Expr) ([]string, bool) {
	switch e := expr.(type) {
	case *reconfp.FieldCond:
		if e.Op == "=" || e.Op == "==" {
			return []string{e.Value}, e.Value != ""
		}
		if e.Op == "~=" {
			// 正则里如果能提取出「必须出现」的字面量，同样可以用来收窄。
			if lits := regexRequiredLiterals(e.Value); len(lits) > 0 {
				return lits, true
			}
		}
		return nil, false
	case *reconfp.AndExpr:
		left, lok := requiredLiterals(e.Left)
		right, rok := requiredLiterals(e.Right)
		if !lok && !rok {
			return nil, false
		}
		return append(left, right...), true
	case *reconfp.OrExpr:
		left, lok := requiredLiterals(e.Left)
		right, rok := requiredLiterals(e.Right)
		if !lok || !rok {
			return nil, false
		}
		return append(left, right...), true
	default:
		return nil, false
	}
}

// regexRequiredLiterals 从正则里提取「任何匹配都必然包含」的字面量。
//
// 用 regexp/syntax 的 AST 判断，规则是保守的：
//   - 拼接：任一部分的必需字面量都成立；
//   - 分支：每条分支都必须有必需字面量，取并集；
//   - + / {n,}（n>=1）：子表达式至少出现一次，可取；
//   - * / ? / {0,}：不可取；
//   - 字符类/通配符：不可取。
//
// 提取不到（或正则不受 Go 支持，如 lookahead）时返回空，调用方回退全量求值。
func regexRequiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	lits, ok := regexNodeLiterals(re)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(lits))
	seen := map[string]bool{}
	for _, l := range lits {
		l = strings.ToLower(l)
		if len(l) >= 3 && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func regexNodeLiterals(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return nil, false
		}
		return []string{string(re.Rune)}, true
	case syntax.OpCapture:
		if len(re.Sub) == 1 {
			return regexNodeLiterals(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		out := make([]string, 0, len(re.Sub))
		found := false
		for _, sub := range re.Sub {
			if lits, ok := regexNodeLiterals(sub); ok {
				out = append(out, lits...)
				found = true
			}
		}
		return out, found
	case syntax.OpAlternate:
		out := make([]string, 0, len(re.Sub))
		for _, sub := range re.Sub {
			lits, ok := regexNodeLiterals(sub)
			if !ok {
				return nil, false
			}
			out = append(out, lits...)
		}
		return out, len(out) > 0
	case syntax.OpPlus:
		if len(re.Sub) == 1 {
			return regexNodeLiterals(re.Sub[0])
		}
		return nil, false
	case syntax.OpRepeat:
		if re.Min >= 1 && len(re.Sub) == 1 {
			return regexNodeLiterals(re.Sub[0])
		}
		return nil, false
	default:
		return nil, false
	}
}

// LoadBuiltinRules 加载内置规则集（dddd 快照 + 种子）。
// 返回成功编译的条数。YAML 规则随后加载时按 name 覆盖同名内置规则。
func (e *DSLEngine) LoadBuiltinRules() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	loaded, skipped := 0, 0
	for _, r := range reconfp.DefaultRuleSet() {
		if !r.Enabled && r.Source == reconfp.SourceCustom {
			continue
		}
		expr, err := reconfp.ParseExpression(r.Expression)
		if err != nil {
			skipped++
			continue
		}
		e.compiled[r.Name] = &compiledRule{
			name:      r.Name,
			category:  r.Category,
			condition: "or",
			dsl:       []string{r.Expression},
			exprs:     []reconfp.Expr{expr},
			builtin:   true,
		}
		loaded++
	}
	if skipped > 0 {
		log.Printf("[fingerprint] 内置规则跳过 %d 条（表达式无法编译）", skipped)
	}
	e.rebuildGramIndex()
	return loaded
}

// LoadRulesFromFile 从单个 YAML 文件加载旧格式规则。
func (e *DSLEngine) LoadRulesFromFile(filePath string) error {
	data, err := config.ReadDictFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	return e.LoadRulesFromBytes(data, filePath)
}

// LoadRulesFromBytes 从内存加载 YAML 规则（内置字典/测试用）。
func (e *DSLEngine) LoadRulesFromBytes(data []byte, filePath string) error {

	var rules map[string]*FingerprintRule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse YAML %s: %w", filePath, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for name, rule := range rules {
		if rule == nil {
			continue
		}
		rule.ID = name
		rule.Name = name
		if rule.Condition == "" {
			rule.Condition = "or"
		}

		compiled, err := compileLegacyRule(rule)
		if err != nil {
			log.Printf("[fingerprint] 规则 %s 翻译失败，整条跳过: %v", name, err)
			continue
		}
		e.Rules[name] = rule
		e.compiled[name] = compiled
	}
	e.rebuildGramIndex()
	return nil
}

// LoadRulesFromDir 从目录加载所有规则文件。
func (e *DSLEngine) LoadRulesFromDir(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			if loadErr := e.LoadRulesFromFile(path); loadErr != nil {
				fmt.Printf("Warning: failed to load rules from %s: %v\n", path, loadErr)
			}
		}
		return nil
	})
}

// RulesCount 返回已加载的规则总数（内置 + YAML）。
func (e *DSLEngine) RulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.compiled)
}

// AnalyzeResponse 分析 HTTP 响应并返回匹配的指纹。
func (e *DSLEngine) AnalyzeResponse(resp *HTTPResponse) []*FingerprintMatch {
	if resp == nil {
		return nil
	}
	obs := observationFromHTTP(resp)

	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.analyzeLocked(resp, obs)
}

// analyzeLocked 真正的匹配逻辑；调用方必须持有 e.mu。
func (e *DSLEngine) analyzeLocked(resp *HTTPResponse, obs reconfp.Observation) []*FingerprintMatch {
	candidates := e.candidateRules(&obs)
	matches := make([]*FingerprintMatch, 0, len(candidates))
	seen := make(map[string]bool)
	for _, name := range candidates {
		rule := e.compiled[name]
		if rule == nil {
			continue
		}
		if match := matchRule(resp, obs, rule); match != nil && !seen[rule.name] {
			seen[rule.name] = true
			matches = append(matches, match)
		}
	}
	return matches
}

// candidateRules 返回可能命中的规则名。
//
// 大 body 时先按 4 字节 gram 倒排收窄：表达式里任意一个字面量的任意 gram
// 出现在观测文本里，该规则才进入候选；没有任何可用字面量的规则（纯正则、
// status、!= 等）放进 alwaysFull。索引只做「排除不可能」，不参与判定，
// 因此候选集是超集，不会改变最终结果。
func (e *DSLEngine) candidateRules(obs *reconfp.Observation) []string {
	all := func() []string {
		out := make([]string, 0, len(e.compiled))
		for name := range e.compiled {
			out = append(out, name)
		}
		return out
	}
	// 小响应不做预筛：全量求值的成本低于扫 gram。
	if len(obs.Body) < bigBodyThreshold || (len(e.gramLong) == 0 && len(e.gramShort) == 0) {
		return all()
	}

	seen := make(map[string]bool, len(e.alwaysFull)+16)
	out := make([]string, 0, len(e.alwaysFull)+16)
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, name := range e.alwaysFull {
		add(name)
	}
	for _, text := range observationTexts(obs) {
		for i := 0; i+gramLongLen <= len(text); i++ {
			for _, name := range e.gramLong[text[i:i+gramLongLen]] {
				add(name)
			}
		}
		for i := 0; i+gramShortLen <= len(text); i++ {
			for _, name := range e.gramShort[text[i:i+gramShortLen]] {
				add(name)
			}
		}
	}
	return out
}

// observationTexts 返回参与 gram 预筛的小写字段文本。
// 与 internal/recon/fingerprint getValue 的字段集合保持一致，避免索引漏字段造成假阴性。
func observationTexts(o *reconfp.Observation) []string {
	return []string{
		strings.ToLower(o.Body),
		strings.ToLower(o.Title),
		strings.ToLower(o.HeaderText),
		strings.ToLower(o.Server),
		strings.ToLower(o.Path),
		strings.ToLower(o.Cookie),
		strings.ToLower(o.Cert),
		strings.ToLower(o.ContentType),
		strings.ToLower(o.Banner),
		strings.ToLower(o.BodyHash),
		strings.ToLower(o.IconHash),
		strings.ToLower(o.IconMD5),
		strconv.Itoa(o.Status),
		strconv.Itoa(o.Port),
		strings.ToLower(o.Protocol),
	}
}

// matchRule 用 reconkit AST 求值；置信度口径与旧引擎保持一致。
func matchRule(resp *HTTPResponse, obs reconfp.Observation, rule *compiledRule) *FingerprintMatch {
	if len(rule.exprs) == 0 {
		return nil
	}

	matchedDSLs := make([]string, 0, 1)
	isAnd := strings.ToLower(rule.condition) == "and"

	for i, expr := range rule.exprs {
		ok := expr.Eval(&obs)
		if ok {
			matchedDSLs = append(matchedDSLs, rule.dsl[i])
			if !isAnd {
				break
			}
		} else if isAnd {
			return nil
		}
	}
	if len(matchedDSLs) == 0 {
		return nil
	}

	confidence := 70
	if rule.builtin {
		confidence = 90
		if rule.category != "" {
			confidence = 95
		}
	} else {
		if len(matchedDSLs) >= 2 {
			confidence = 85
		}
		if isAnd && len(matchedDSLs) == len(rule.exprs) {
			confidence = 95
		}
	}

	method := "dsl"
	if rule.builtin {
		method = "native"
	}

	return &FingerprintMatch{
		URL:        resp.URL,
		RuleName:   rule.name,
		Technology: rule.name,
		DSLMatched: matchedDSLs,
		Category:   rule.category,
		Tags:       rule.tags,
		Confidence: confidence,
		Method:     method,
	}
}

// observationFromHTTP 把旧引擎的 HTTPResponse 映射成 reconkit Observation。
// body 在这里统一做字符集解码（GBK/Big5），标题非法 UTF-8 时从解码后的正文重取。
func observationFromHTTP(resp *HTTPResponse) reconfp.Observation {
	headers := make(map[string]string, len(resp.Headers))
	var headerText strings.Builder
	var cookies []string
	for k, v := range resp.Headers {
		lk := strings.ToLower(k)
		headers[lk] = v
		headerText.WriteString(k)
		headerText.WriteString(": ")
		headerText.WriteString(v)
		headerText.WriteString("\r\n")
		if lk == "set-cookie" {
			if idx := strings.Index(v, ";"); idx > 0 {
				cookies = append(cookies, v[:idx])
			} else {
				cookies = append(cookies, v)
			}
		}
	}

	contentType := headers["content-type"]
	body := reconfp.DecodeBody([]byte(resp.Body), contentType)

	title := resp.Title
	if title == "" || !utf8.ValidString(title) {
		title = extractHTMLTitle(body)
	}

	path := ""
	host := ""
	protocol := ""
	if u, err := url.Parse(resp.URL); err == nil {
		path = u.Path
		host = u.Hostname()
		protocol = strings.ToLower(u.Scheme)
	}

	return reconfp.Observation{
		Host:        host,
		Protocol:    protocol,
		Path:        path,
		Status:      resp.StatusCode,
		Headers:     headers,
		HeaderText:  headerText.String(),
		Cookie:      strings.Join(cookies, "; "),
		Body:        body,
		Title:       title,
		Server:      headers["server"],
		ContentType: contentType,
		IconHash:    resp.IconHash,
		IconMD5:     resp.IconMD5,
		Cert:        resp.CertOrg, // cert 规则的匹配数据源（TLS Subject.Organization）
	}
}

var htmlTitleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractHTMLTitle(body string) string {
	if m := htmlTitleRE.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// compileLegacyRule 把旧 YAML 规则翻译成表达式规则。
// 任何一行翻译失败都整条跳过：AND 规则少一行会放宽条件，宁可漏报不误报。
func compileLegacyRule(rule *FingerprintRule) (*compiledRule, error) {
	if len(rule.DSL) == 0 {
		return nil, fmt.Errorf("dsl 为空")
	}
	out := &compiledRule{
		name:      rule.Name,
		category:  rule.Category,
		condition: strings.ToLower(rule.Condition),
		dsl:       make([]string, 0, len(rule.DSL)),
		exprs:     make([]reconfp.Expr, 0, len(rule.DSL)),
	}
	if out.condition != "and" {
		out.condition = "or"
	}
	if rule.Tags != "" {
		for _, t := range strings.Split(rule.Tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out.tags = append(out.tags, t)
			}
		}
	}
	for _, dsl := range rule.DSL {
		expr, err := translateDSL(dsl)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", dsl, err)
		}
		compiled, err := reconfp.ParseExpression(expr)
		if err != nil {
			return nil, fmt.Errorf("%q -> %q: %w", dsl, expr, err)
		}
		out.dsl = append(out.dsl, dsl)
		out.exprs = append(out.exprs, compiled)
	}
	return out, nil
}

// translateDSL 把旧引擎的函数式 DSL 翻译成 reconkit 表达式。
func translateDSL(dsl string) (string, error) {
	dsl = strings.TrimSpace(dsl)
	open := strings.Index(dsl, "(")
	if open <= 0 || !strings.HasSuffix(dsl, ")") {
		return "", fmt.Errorf("无法识别的 DSL 形态")
	}
	fn := strings.ToLower(strings.TrimSpace(dsl[:open]))
	content := dsl[open+1 : len(dsl)-1]

	// regex 的第二个参数是正则原文，可能包含单/双引号与逗号。
	// 走专用路径：按第一个逗号切开，余下整体当 pattern，只剥最外层引号。
	if fn == "regex" {
		idx := strings.Index(content, ",")
		if idx < 0 {
			return "", fmt.Errorf("regex 至少需要 2 个参数")
		}
		field := legacyField(trimQuotes(content[:idx]))
		if field == "" {
			field = "body" // 旧引擎对未知位置回落到 body
		}
		pattern := trimQuotes(strings.TrimSpace(content[idx+1:]))
		if pattern == "" {
			return "", fmt.Errorf("regex 缺少模式")
		}
		return field + "~=" + quoteExpr(pattern), nil
	}

	args := splitDSLArgs(content)

	unquoted := make([]string, len(args))
	for i, a := range args {
		unquoted[i] = trimQuotes(a)
	}

	switch fn {
	case "contains", "contains_any", "contains_all":
		if len(unquoted) < 2 {
			return "", fmt.Errorf("%s 至少需要 2 个参数", fn)
		}
		field := legacyField(unquoted[0])
		if field == "" {
			return "", fmt.Errorf("不支持的匹配位置 %q", unquoted[0])
		}
		joiner := " || "
		if fn == "contains_all" {
			joiner = " && "
		}
		parts := make([]string, 0, len(unquoted)-1)
		for _, v := range unquoted[1:] {
			parts = append(parts, field+"="+quoteExpr(v))
		}
		return "(" + strings.Join(parts, joiner) + ")", nil

	case "title":
		if len(unquoted) < 1 {
			return "", fmt.Errorf("title 缺少参数")
		}
		return "title=" + quoteExpr(unquoted[0]), nil

	case "status":
		if len(unquoted) < 1 {
			return "", fmt.Errorf("status 缺少参数")
		}
		code, err := strconv.Atoi(strings.TrimSpace(unquoted[0]))
		if err != nil {
			return "", fmt.Errorf("status 参数不是数字: %q", unquoted[0])
		}
		return fmt.Sprintf("status==%s", quoteExpr(strconv.Itoa(code))), nil

	case "regex":
		// 已在函数开头走专用路径，不会到这里。
		return "", fmt.Errorf("regex 解析异常")

	case "header":
		if len(unquoted) == 0 {
			return "", fmt.Errorf("header 缺少参数")
		}
		if len(unquoted) == 1 {
			return "header=" + quoteExpr(unquoted[0]), nil
		}
		// 旧语义：指定头的值包含 pattern。用 "名字: 值" 的正则保住名字约束。
		pat := regexp.QuoteMeta(unquoted[0]) + `\s*:\s*` + regexp.QuoteMeta(unquoted[1])
		return "header~=" + quoteExpr(pat), nil

	case "icon":
		if len(unquoted) < 2 {
			return "", fmt.Errorf("icon 至少需要 2 个参数")
		}
		parts := make([]string, 0, len(unquoted)-1)
		for _, hash := range unquoted[1:] {
			parts = append(parts, "icon_hash=="+quoteExpr(hash), "icon_md5=="+quoteExpr(hash))
		}
		return "(" + strings.Join(parts, " || ") + ")", nil

	default:
		return "", fmt.Errorf("不支持的函数 %q", fn)
	}
}

// legacyField 旧 DSL 的匹配位置 → reconkit 字段。
func legacyField(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "body":
		return "body"
	case "header", "headers":
		return "header"
	case "title":
		return "title"
	case "server":
		return "server"
	case "url":
		// reconkit 没有 url 字段；path 是最接近的（保留路径与查询串）。
		return "path"
	default:
		return ""
	}
}

// splitDSLArgs 按逗号切分参数，尊重引号与反斜杠转义。
// 引号未闭合时不报错（旧规则里确有这种写法），按已读内容收尾。
func splitDSLArgs(content string) []string {
	args := make([]string, 0, 4)
	var cur strings.Builder
	inQuote := false
	var quoteChar byte

	for i := 0; i < len(content); i++ {
		c := content[i]
		if inQuote {
			cur.WriteByte(c)
			if c == '\\' && i+1 < len(content) {
				i++
				cur.WriteByte(content[i])
				continue
			}
			if c == quoteChar {
				inQuote = false
			}
			continue
		}
		switch c {
		case '\'', '"':
			inQuote = true
			quoteChar = c
			cur.WriteByte(c)
		case ',':
			args = append(args, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		args = append(args, s)
	}
	return args
}

func trimQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// quoteExpr 把值包成表达式字符串字面量，转义反斜杠与双引号。
func quoteExpr(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// GetRule 根据名称获取原始 YAML 规则；内置规则返回视图形式。
func (e *DSLEngine) GetRule(name string) *FingerprintRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if r, ok := e.Rules[name]; ok {
		return r
	}
	if c, ok := e.compiled[name]; ok {
		return &FingerprintRule{ID: name, Name: name, DSL: StringList(c.dsl), Condition: c.condition, Category: c.category}
	}
	return nil
}

// ListRules 列出所有规则名称（排序保证输出稳定）。
func (e *DSLEngine) ListRules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.compiled))
	for name := range e.compiled {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

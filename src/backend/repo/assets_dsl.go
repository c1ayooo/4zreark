package repo

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ErrDSLSyntax 标记查询串语法错误。调用方据此返回 400，而不是当成数据库错误返回 500。
var ErrDSLSyntax = errors.New("资产查询语法错误")

// 资产查询 DSL：与 ScopesHub 实测语法对齐
//
//	status_code="200" && (domain=="a.com" || title="后台")
//
// 规则：值必须双引号；= 包含匹配，== 精确匹配，!= 取反（缺失字段也算不匹配）；
// 优先级 && 高于 ||，括号可显式分组。
var assetQueryFields = []string{
	"text", "app", "status_code", "title", "domain", "host", "ip", "port", "protocol",
	"icon_hash", "discovery_type", "first_seen", "verified_at", "new_within", "verified_within",
}

type dslParser struct {
	src  []rune
	pos  int
	args *[]any
	base int // 起始占位符编号，调用方已占用 $1..$base-1
}

// BuildAssetWhere 把查询串编译成参数化 SQL 片段（带 s. 前缀别名）与参数列表。
func BuildAssetWhere(q string) (string, []any, error) {
	return BuildAssetWhereFrom(q, 1)
}

// BuildAssetWhereFrom 从指定占位符编号开始编译，避免调用方做字符串替换。
func BuildAssetWhereFrom(q string, base int) (string, []any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil, nil
	}
	if base < 1 {
		base = 1
	}
	args := make([]any, 0, 8)
	p := &dslParser{src: []rune(q), args: &args, base: base}
	expr, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	p.skipSpace()
	if p.pos < len(p.src) {
		return "", nil, p.errf("无法解析的剩余内容")
	}
	return expr, args, nil
}

func (p *dslParser) errf(format string, a ...any) error {
	return fmt.Errorf("%w：第 %d 字符：%s", ErrDSLSyntax, p.pos+1, fmt.Sprintf(format, a...))
}

func (p *dslParser) skipSpace() {
	for p.pos < len(p.src) && (p.src[p.pos] == ' ' || p.src[p.pos] == '\t' || p.src[p.pos] == '\n') {
		p.pos++
	}
}

func (p *dslParser) match(tok string) bool {
	p.skipSpace()
	r := []rune(tok)
	if p.pos+len(r) > len(p.src) {
		return false
	}
	for i, c := range r {
		if p.src[p.pos+i] != c {
			return false
		}
	}
	p.pos += len(r)
	return true
}

func (p *dslParser) peek() rune {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

// parseOr 处理 || 层级。
func (p *dslParser) parseOr() (string, error) {
	left, err := p.parseAnd()
	if err != nil {
		return "", err
	}
	for p.match("||") {
		right, err := p.parseAnd()
		if err != nil {
			return "", err
		}
		left = fmt.Sprintf("(%s OR %s)", left, right)
	}
	return left, nil
}

// parseAnd 处理 && 层级。
func (p *dslParser) parseAnd() (string, error) {
	left, err := p.parsePrimary()
	if err != nil {
		return "", err
	}
	for p.match("&&") {
		right, err := p.parsePrimary()
		if err != nil {
			return "", err
		}
		left = fmt.Sprintf("(%s AND %s)", left, right)
	}
	return left, nil
}

func (p *dslParser) parsePrimary() (string, error) {
	if p.match("(") {
		inner, err := p.parseOr()
		if err != nil {
			return "", err
		}
		if !p.match(")") {
			return "", p.errf("缺少右括号")
		}
		return "(" + inner + ")", nil
	}
	return p.parseCond()
}

func (p *dslParser) parseCond() (string, error) {
	p.skipSpace()
	// 带引号的短语：按全文检索处理（顶层 "美团 招聘" 等价 text="美团 招聘"）。
	if p.peek() == '"' {
		return p.parseBareTerm(true)
	}
	start := p.pos
	for p.pos < len(p.src) && (isAlnum(p.src[p.pos]) || p.src[p.pos] == '_') {
		p.pos++
	}
	field := string(p.src[start:p.pos])
	// 裸词 / 未知字段：整体当一个 text 条件，让搜索框里的普通关键词直接可用。
	// 字段名打错时也按全文检索，而不是报「不支持的查询字段」。
	if field == "" || !isAssetField(field) {
		p.pos = start
		return p.parseBareTerm(false)
	}

	p.skipSpace()
	op := ""
	for _, cand := range []string{"==", "!=", ">=", "<=", "="} {
		if p.match(cand) {
			op = cand
			break
		}
	}
	if op == "" {
		return "", p.errf("字段「%s」后应为 =、==、!=、>= 或 <=", field)
	}

	p.skipSpace()
	if p.peek() != '"' {
		return "", p.errf("字段值必须放在双引号中")
	}
	p.pos++
	var sb strings.Builder
	closed := false
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\\' && p.pos+1 < len(p.src) {
			p.pos++
			sb.WriteRune(p.src[p.pos])
			p.pos++
			continue
		}
		if c == '"' {
			p.pos++
			closed = true
			break
		}
		sb.WriteRune(c)
		p.pos++
	}
	if !closed {
		return "", p.errf("字符串缺少结束引号")
	}
	val := sb.String()
	if len(val) > 1024 {
		return "", p.errf("字段值超过 1024 字节")
	}
	if strings.ContainsAny(val, "\x00\r\n") {
		return "", p.errf("字段值包含控制字符")
	}
	return p.buildCond(field, op, val)
}

// parseBareTerm 读裸检索词：quoted=true 消费一个双引号短语，否则读到
// &&、||、括号或结尾为止。值校验与字段值同一套规则，语义等价 text="…"。
func (p *dslParser) parseBareTerm(quoted bool) (string, error) {
	var sb strings.Builder
	if quoted {
		p.pos++
		closed := false
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if c == '\\' && p.pos+1 < len(p.src) {
				p.pos++
				sb.WriteRune(p.src[p.pos])
				p.pos++
				continue
			}
			if c == '"' {
				p.pos++
				closed = true
				break
			}
			sb.WriteRune(c)
			p.pos++
		}
		if !closed {
			return "", p.errf("字符串缺少结束引号")
		}
	} else {
		for p.pos < len(p.src) {
			c := p.src[p.pos]
			if c == '&' || c == '|' || c == '(' || c == ')' {
				break
			}
			sb.WriteRune(c)
			p.pos++
		}
	}
	val := strings.TrimSpace(sb.String())
	if val == "" {
		return "", p.errf("查询词为空")
	}
	if len(val) > 1024 {
		return "", p.errf("查询词超过 1024 字节")
	}
	if strings.ContainsAny(val, "\x00\r\n") {
		return "", p.errf("查询词包含控制字符")
	}
	return p.buildCond("text", "=", val)
}

func (p *dslParser) add(v any) string {
	*p.args = append(*p.args, v)
	return fmt.Sprintf("$%d", p.base+len(*p.args)-1)
}

func (p *dslParser) buildCond(field, op, val string) (string, error) {
	like := func(v string) string {
		return "%" + escapeLike(v) + "%"
	}
	neg := op == "!="

	switch field {
	case "status_code", "port":
		n, err := strconv.Atoi(val)
		if err != nil {
			return "", p.errf("字段「%s」需要整数", field)
		}
		col := "s." + field
		if field == "status_code" {
			col = "s.http_status"
		}
		if neg {
			return fmt.Sprintf("(%s IS NULL OR %s <> %s)", col, col, p.add(n)), nil
		}
		return fmt.Sprintf("%s = %s", col, p.add(n)), nil

	case "icon_hash":
		col := "s.icon_sha256"
		if neg {
			return fmt.Sprintf("(%s IS NULL OR %s::text <> %s)", col, col, p.add(val)), nil
		}
		return fmt.Sprintf("%s::text = %s", col, p.add(val)), nil

	case "domain":
		ph := p.add(val)
		ph2 := p.add("%." + escapeLike(val))
		if neg {
			return fmt.Sprintf("(s.host IS NULL OR (s.host <> %s AND s.host NOT LIKE %s))", ph, ph2), nil
		}
		return fmt.Sprintf("(s.host = %s OR s.host LIKE %s)", ph, ph2), nil

	case "host":
		pattern := like(val)
		if neg {
			return fmt.Sprintf("(s.host IS NULL OR s.host NOT ILIKE %s)", p.add(pattern)), nil
		}
		if op == "==" {
			return fmt.Sprintf("s.host = %s", p.add(val)), nil
		}
		return fmt.Sprintf("s.host ILIKE %s", p.add(pattern)), nil

	case "ip":
		if neg {
			return fmt.Sprintf("(s.ip IS NULL OR s.ip::text NOT LIKE %s)", p.add(like(val))), nil
		}
		return fmt.Sprintf("s.ip::text LIKE %s", p.add(like(val))), nil

	case "protocol":
		if neg {
			return fmt.Sprintf("s.protocol <> %s", p.add(val)), nil
		}
		return fmt.Sprintf("s.protocol = %s", p.add(val)), nil

	case "discovery_type":
		if neg {
			return fmt.Sprintf("s.discovery_type <> %s", p.add(val)), nil
		}
		return fmt.Sprintf("s.discovery_type = %s", p.add(val)), nil

	case "title":
		if neg {
			return fmt.Sprintf("(s.title IS NULL OR s.title NOT ILIKE %s)", p.add(like(val))), nil
		}
		if op == "==" {
			return fmt.Sprintf("s.title = %s", p.add(val)), nil
		}
		return fmt.Sprintf("s.title ILIKE %s", p.add(like(val))), nil

	case "first_seen", "verified_at":
		col := "s." + field
		switch op {
		case ">=":
			return fmt.Sprintf("%s >= %s::date", col, p.add(val)), nil
		case "<=":
			return fmt.Sprintf("%s < (%s::date + interval '1 day')", col, p.add(val)), nil
		}
		return fmt.Sprintf("%s::date = %s::date", col, p.add(val)), nil

	case "app":
		// 优先走 fingerprint_hits（有索引），没命中规则名时回退到 sites.tech 数组。
		// v2 §19 记的正是这个字段：ScopesHub 自己在这里返回 500，这里两条路径都要兜住。
		cond := appExistsCond(p.add(strings.ToLower(val)), p.add("%"+escapeLike(strings.ToLower(val))+"%"))
		if neg {
			return "(NOT " + cond + ")", nil
		}
		return cond, nil

	case "new_within", "verified_within":
		col := "s.first_seen"
		if field == "verified_within" {
			col = "s.verified_at"
		}
		return fmt.Sprintf("%s >= now() - (%s)::interval", col, p.add(intervalOf(val))), nil

	default: // text
		pattern := like(val)
		cond := fmt.Sprintf("(s.value ILIKE %s OR coalesce(s.title,'') ILIKE %s OR s.host ILIKE %s OR coalesce(s.ip::text,'') ILIKE %s)",
			p.add(pattern), p.add(pattern), p.add(pattern), p.add(pattern))
		if neg {
			return "(NOT " + cond + ")", nil
		}
		return cond, nil
	}
}

// appExistsCond 是 app 字段的共享谓词：指纹规则名精确命中（fingerprint_hits，
// 有索引）或站点技术栈模糊包含（sites.tech），别名固定为 s。DSL 编译与
// 图标/技术栈聚类接口共用，保证「按指纹筛选」在各视图同一口径。
func appExistsCond(exactPh, fuzzyPh string) string {
	return fmt.Sprintf(`(exists (select 1 from fingerprint_hits f
                               join fingerprint_rules fr on fr.id = f.rule_id
                              where f.site_id = s.id and lower(fr.name) = %s)
                     or exists (select 1 from jsonb_array_elements_text(s.tech) t
                                 where lower(t) like %s))`, exactPh, fuzzyPh)
}

// intervalOf 把 "7d" / "12h" / "30m" 转成 PostgreSQL interval 文本。
func intervalOf(v string) string {
	if v == "" {
		return "7 days"
	}
	unit := v[len(v)-1]
	num := v[:len(v)-1]
	if _, err := strconv.Atoi(num); err != nil {
		return "7 days"
	}
	switch unit {
	case 'd':
		return num + " days"
	case 'h':
		return num + " hours"
	case 'm':
		return num + " minutes"
	default:
		return "7 days"
	}
}

// escapeLike 转义 LIKE 通配符，避免用户值绕过筛选语义。
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func isAlnum(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isAssetField(f string) bool {
	for _, x := range assetQueryFields {
		if x == f {
			return true
		}
	}
	return false
}

// dslHintRe 识别 DSL 痕迹：字段=值（含比较符）或逻辑符。普通关键词不含这些。
var dslHintRe = regexp.MustCompile(`[a-zA-Z_]\w*\s*(==|!=|>=|<=|=)|&&|\|\|`)

// looksLikeAssetDSL 判断查询串应按 DSL 编译还是按纯文本检索。
// record 视图与聚类接口没有字段约束的概念，靠它把两种写法分开，互不误伤。
func looksLikeAssetDSL(q string) bool {
	return dslHintRe.MatchString(q)
}

// dslValueRe 抠出 text/host/domain/title/ip 的字段值，给不支持 DSL 的接口
// （图标/技术栈聚类只按 host ILIKE）把查询串还原成纯文本检索词。
var dslValueRe = regexp.MustCompile(`(?:text|host|domain|title|ip)\s*(?:==|=|!=)\s*"([^"]*)"`)

// ExtractAppTerm 取查询串里的 app="…" 指纹条件值；没有则返回空串。
// 供图标/技术栈聚类接口把指纹过滤带进聚类 SQL（纯文本检索词带不了这个条件）。
func ExtractAppTerm(q string) string {
	m := appTermRe.FindStringSubmatch(strings.TrimSpace(q))
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

var appTermRe = regexp.MustCompile(`(?:^|[^\w"])\s*app\s*(?:==|=)\s*"([^"]*)"`)

// ExtractSearchTerm 把资产查询串还原成纯文本检索词：
// text="a" host="b" 之类取值以空格拼接；裸词原样返回；
// 其余 DSL 表达式（端口、状态码等）在纯文本口径下无从匹配，返回空串。
func ExtractSearchTerm(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	if m := dslValueRe.FindAllStringSubmatch(q, -1); len(m) > 0 {
		terms := make([]string, 0, len(m))
		for _, v := range m {
			if v[1] = strings.TrimSpace(v[1]); v[1] != "" {
				terms = append(terms, v[1])
			}
		}
		if len(terms) > 0 {
			return strings.Join(terms, " ")
		}
	}
	if looksLikeAssetDSL(q) {
		return ""
	}
	return q
}

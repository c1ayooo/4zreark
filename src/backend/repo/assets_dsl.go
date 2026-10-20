package repo

import (
	"errors"
	"fmt"
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
	"text", "status_code", "title", "domain", "host", "ip", "port", "protocol",
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
	start := p.pos
	for p.pos < len(p.src) && (isAlnum(p.src[p.pos]) || p.src[p.pos] == '_') {
		p.pos++
	}
	field := string(p.src[start:p.pos])
	if field == "" {
		return "", p.errf("此处应为字段名")
	}
	if !isAssetField(field) {
		return "", p.errf("不支持的查询字段「%s」，支持：%s", field, strings.Join(assetQueryFields, ", "))
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

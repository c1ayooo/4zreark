package fingerprint

import (
	"fmt"
	"regexp"
	"strings"
)

// toRegexp 包装用户正则：默认整体忽略大小写。
func toRegexp(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("空正则")
	}
	return regexp.Compile("(?i)" + pattern)
}

type tokenKind int

const (
	tkField tokenKind = iota
	tkOp
	tkString
	tkAnd
	tkOr
	tkNot
	tkLParen
	tkRParen
)

type token struct {
	kind tokenKind
	text string
}

var opTokens = []string{"~=", "==", "!=", ">=", "<=", "=", "&&", "||"}
var fieldRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// knownFields 允许的匹配字段（解析期校验，避免笔误规则永远不命中）。
var knownFields = map[string]bool{
	"header": true, "cookie": true, "body": true, "server": true, "title": true, "cert": true,
	"status": true, "content_type": true, "contenttype": true, "path": true,
	"banner": true, "port": true, "protocol": true,
	"body_hash": true, "bodyhash": true, "icon_hash": true, "iconhash": true,
	"icon_md5": true, "iconmd5": true,
}

// tokenize 词法分析：识别字段/操作符/带引号字符串/逻辑符/括号。
func tokenize(input string) ([]token, error) {
	var out []token
	i := 0
	for i < len(input) {
		c := input[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{tkLParen, "("})
			i++
		case c == ')':
			out = append(out, token{tkRParen, ")"})
			i++
		case c == '!' && i+1 < len(input) && input[i+1] == '=':
			out = append(out, token{tkOp, "!="})
			i += 2
		case c == '!':
			out = append(out, token{tkNot, "!"})
			i++
		case strings.HasPrefix(input[i:], "&&"):
			out = append(out, token{tkAnd, "&&"})
			i += 2
		case strings.HasPrefix(input[i:], "||"):
			out = append(out, token{tkOr, "||"})
			i += 2
		case c == '"' || c == '\'':
			quote := c
			j := i + 1
			var sb strings.Builder
			closed := false
			for j < len(input) {
				if input[j] == '\\' && j+1 < len(input) {
					sb.WriteByte(input[j+1])
					j += 2
					continue
				}
				if input[j] == quote {
					closed = true
					j++
					break
				}
				sb.WriteByte(input[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("第 %d 列附近字符串引号未闭合", i+1)
			}
			out = append(out, token{tkString, sb.String()})
			i = j
		default:
			// 操作符或字段名
			matched := false
			for _, op := range opTokens {
				if strings.HasPrefix(input[i:], op) {
					out = append(out, token{tkOp, op})
					i += len(op)
					matched = true
					break
				}
			}
			if matched {
				continue
			}
			j := i
			for j < len(input) && (input[j] == '_' || input[j] == '-' ||
				(input[j] >= 'a' && input[j] <= 'z') || (input[j] >= 'A' && input[j] <= 'Z') ||
				(input[j] >= '0' && input[j] <= '9')) {
				j++
			}
			if j == i {
				return nil, fmt.Errorf("第 %d 列附近存在无法识别的字符 %q", i+1, string(c))
			}
			word := input[i:j]
			if fieldRE.MatchString(word) && !isKeyword(word) {
				out = append(out, token{tkField, strings.ToLower(word)})
			} else if isKeyword(word) {
				return nil, fmt.Errorf("字段名不能是保留字 %q", word)
			} else {
				return nil, fmt.Errorf("第 %d 列附近字段名非法: %q", i+1, word)
			}
			i = j
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("表达式为空")
	}
	return out, nil
}

func isKeyword(w string) bool {
	switch strings.ToLower(w) {
	case "and", "or", "not", "true", "false", "null":
		return true
	}
	return false
}

// parser 递归下降：or := and (|| and)*; and := unary (&& unary)*; unary := !unary | (expr) | field op value
type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() (token, bool) {
	if p.pos >= len(p.tokens) {
		return token{}, false
	}
	return p.tokens[p.pos], true
}

func (p *parser) next() (token, bool) {
	t, ok := p.peek()
	if ok {
		p.pos++
	}
	return t, ok
}

// ParseExpression 解析指纹表达式为 AST。
func ParseExpression(input string) (Expr, error) {
	tokens, err := tokenize(strings.TrimSpace(input))
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if _, more := p.peek(); more {
		t, _ := p.peek()
		return nil, fmt.Errorf("第 %d 个 token 附近有多余内容 %q", p.pos+1, t.text)
	}
	return expr, nil
}

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tkOr {
			return left, nil
		}
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &OrExpr{Left: left, Right: right}
	}
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.kind != tkAnd {
			return left, nil
		}
		p.next()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &AndExpr{Left: left, Right: right}
	}
}

func (p *parser) parseUnary() (Expr, error) {
	t, ok := p.next()
	if !ok {
		return nil, fmt.Errorf("表达式意外结束")
	}
	switch t.kind {
	case tkNot:
		inner, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &NotExpr{Inner: inner}, nil
	case tkLParen:
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		close, ok := p.next()
		if !ok || close.kind != tkRParen {
			return nil, fmt.Errorf("括号未闭合")
		}
		return inner, nil
	case tkField:
		if !knownFields[t.text] {
			return nil, fmt.Errorf("未知字段 %q（支持: header/cookie/body/server/title/cert/status/content_type/path/banner/port/protocol/body_hash/icon_hash）", t.text)
		}
		opTok, ok := p.next()
		if !ok || opTok.kind != tkOp {
			if ok {
				return nil, fmt.Errorf("字段 %q 后应为操作符，得到 %q", t.text, opTok.text)
			}
			return nil, fmt.Errorf("字段 %q 后缺少操作符", t.text)
		}
		valTok, ok := p.next()
		if !ok || valTok.kind != tkString {
			if ok {
				return nil, fmt.Errorf("操作符 %q 后应为带引号的值，得到 %q", opTok.text, valTok.text)
			}
			return nil, fmt.Errorf("操作符 %q 后缺少值", opTok.text)
		}
		cond := &FieldCond{Field: t.text, Op: opTok.text, Value: valTok.text}
		if opTok.text == "=" || opTok.text == "!=" {
			// 小写值解析期预算：Eval 热路径免做常量 ToLower
			cond.valueLower = strings.ToLower(valTok.text)
		}
		if opTok.text == "~=" {
			re, err := compileRegexp(valTok.text)
			if err != nil {
				return nil, err
			}
			cond.re = re
		}
		if opTok.text == ">=" || opTok.text == "<=" {
			if t.text != "port" && t.text != "status" {
				return nil, fmt.Errorf("字段 %q 不支持 %s", t.text, opTok.text)
			}
		}
		return cond, nil
	default:
		return nil, fmt.Errorf("意外的 token %q", t.text)
	}
}

// Package fingerprint 原生 Web 指纹识别引擎。
// 指纹规则表达式 AST 与匹配模型，不依赖外部工具运行时：
//
//	字段: header body server title cert status content_type path banner port protocol body_hash icon_hash
//	操作: = 包含  != 不包含  == 相等  ~= 正则  >= <= 数值(port/status)
//	逻辑: && || ! 括号
package fingerprint

import (
	"fmt"
	"strconv"
	"strings"
)

// Observation 一次探测收集到的可匹配事实。
type Observation struct {
	Host        string
	Port        int
	Protocol    string // http / https
	Path        string
	Status      int
	Headers     map[string]string // 键小写
	HeaderText  string            // 全部头拼接（header 字段匹配用）
	Cookie      string            // 全部 Set-Cookie 值拼接（cookie 字段匹配用，Wappalyzer 指纹源）
	Body        string
	Title       string
	Server      string
	ContentType string
	Banner      string
	Cert        string
	BodyHash    string // md5(body)
	IconHash    string // mmh3(base64(favicon))，fofa 风格
	ICP         string // 页面备案号（body 提取，主号已去 -N 子号后缀），ICP 裂变反查的键
	// Links 页面内提取的链接（绝对 URL，去重有上限）：门户/导航页常挂多个业务系统
	// 入口，链接清单即资产线索，供 agent 决定是否逐个 fingerprint_scan 追下去。
	Links []string `json:"links,omitempty"`

	// lowerCache 字段小写缓存（*Observation 匹配路径专用，见 loweredValue）。
	// body 可达 512KB：数千条规则逐条 Eval 时每条件重新 ToLower 会产生数千次
	// 大字符串分配，这里每观测每字段只算一次。unexported，拷贝/序列化自动丢弃。
	lowerCache map[string]loweredField
}

// loweredField 小写缓存条目：ok 区分「字段缺失」与「空值」。
type loweredField struct {
	value string
	ok    bool
}

// loweredValue 返回字段文本的小写形式（= / != 包含匹配专用路径）。
func (o *Observation) loweredValue(field string) (string, bool) {
	if o.lowerCache == nil {
		o.lowerCache = make(map[string]loweredField, 4)
	}
	if got, ok := o.lowerCache[field]; ok {
		return got.value, got.ok
	}
	got := loweredField{}
	if raw, ok := o.getValue(field); ok {
		got = loweredField{value: strings.ToLower(raw), ok: true}
	}
	o.lowerCache[field] = got
	return got.value, got.ok
}

// getValue 返回字段文本值；数值字段返回十进制字符串。
func (o Observation) getValue(field string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(field)) {
	case "header":
		return o.HeaderText, true
	case "cookie":
		return o.Cookie, true
	case "body":
		return o.Body, true
	case "server":
		return o.Server, true
	case "title":
		return o.Title, true
	case "cert":
		return o.Cert, true
	case "status":
		if o.Status <= 0 {
			return "", false
		}
		return strconv.Itoa(o.Status), true
	case "content_type", "contenttype":
		return o.ContentType, true
	case "path":
		return o.Path, true
	case "banner":
		return o.Banner, true
	case "port":
		if o.Port <= 0 {
			return "", false
		}
		return strconv.Itoa(o.Port), true
	case "protocol":
		return o.Protocol, true
	case "body_hash", "bodyhash":
		return o.BodyHash, true
	case "icon_hash", "iconhash":
		return o.IconHash, true
	default:
		return "", false
	}
}

// Match 单条命中结果。
type Match struct {
	Product     string  `json:"product"`
	Expression  string  `json:"expression"`
	Confidence  float64 `json:"confidence"`
	MatchedExpr string  `json:"matched_expr"` // 触发的那条表达式（一个产品可有多条）
}

// Expr 规则 AST 节点。
type Expr interface {
	Eval(o *Observation) bool
	String() string
}

// FieldCond 单条件：字段 + 操作符 + 值。
type FieldCond struct {
	Field      string
	Op         string // "=", "!=", "==", "~=", ">=", "<="
	Value      string
	valueLower string                                // Op=="="/"!=" 时的小写值（解析期预算，见 parser）
	re         interface{ MatchString(string) bool } // Op=="~=" 时的编译结果
}

func (c *FieldCond) Eval(o *Observation) bool {
	switch c.Op {
	case "=", "!=":
		// valueLower 解析期已预算；直接构造 FieldCond 的调用方（测试）在此按值
		// 兜底计算，不回写结构体以保持规则共享只读。
		valueLower := c.valueLower
		if valueLower == "" && c.Value != "" {
			valueLower = strings.ToLower(c.Value)
		}
		v, ok := o.loweredValue(c.Field)
		if !ok {
			return false
		}
		if c.Op == "=" {
			return strings.Contains(v, valueLower)
		}
		return !strings.Contains(v, valueLower)
	}
	v, ok := o.getValue(c.Field)
	// 端口/状态码类数值条件：字段缺失视为不满足（!= 也不满足，避免误报）
	if !ok {
		return false
	}
	switch c.Op {
	case "==":
		return strings.EqualFold(strings.TrimSpace(v), c.Value)
	case "~=":
		if c.re == nil {
			return false
		}
		return c.re.MatchString(v)
	case ">=", "<=":
		iv, err1 := strconv.ParseFloat(strings.TrimSpace(v), 64)
		ic, err2 := strconv.ParseFloat(c.Value, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		if c.Op == ">=" {
			return iv >= ic
		}
		return iv <= ic
	default:
		return false
	}
}

func (c *FieldCond) String() string {
	return c.Field + c.Op + `"` + c.Value + `"`
}

type NotExpr struct{ Inner Expr }

func (n *NotExpr) Eval(o *Observation) bool { return !n.Inner.Eval(o) }
func (n *NotExpr) String() string           { return "!(" + n.Inner.String() + ")" }

type AndExpr struct{ Left, Right Expr }

func (a *AndExpr) Eval(o *Observation) bool { return a.Left.Eval(o) && a.Right.Eval(o) }
func (a *AndExpr) String() string           { return "(" + a.Left.String() + " && " + a.Right.String() + ")" }

type OrExpr struct{ Left, Right Expr }

func (o *OrExpr) Eval(obs *Observation) bool { return o.Left.Eval(obs) || o.Right.Eval(obs) }
func (o *OrExpr) String() string             { return "(" + o.Left.String() + " || " + o.Right.String() + ")" }

// compileRegexp 编译 ~= 正则：默认忽略大小写，非法表达式返回错误。
func compileRegexp(pattern string) (interface{ MatchString(string) bool }, error) {
	re, err := toRegexp(pattern)
	if err != nil {
		return nil, fmt.Errorf("正则无效 %q: %w", pattern, err)
	}
	return re, nil
}

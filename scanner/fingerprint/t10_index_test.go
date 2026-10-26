package fingerprint

import (
	"strings"
	"testing"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
)

// T10：gram 预筛必须与全量求值结果完全一致（只收窄候选，不改变判定）。
func TestGramIndexMatchesBruteForce(t *testing.T) {
	e := NewDSLEngine()
	if n := e.LoadBuiltinRules(); n == 0 {
		t.Fatal("内置规则未加载")
	}

	cases := []*HTTPResponse{
		{
			StatusCode: 200,
			Title:      "管理后台 - Nginx",
			Headers:    map[string]string{"Server": "nginx/1.24", "Content-Type": "text/html"},
			Body:       strings.Repeat("wp-content jquery react vue nginx apache ", 400),
		},
		{
			StatusCode: 200,
			Title:      "Welcome",
			Headers:    map[string]string{"Server": "Apache", "X-Powered-By": "PHP/7.4"},
			Body:       strings.Repeat("index.jsp login.php old console ", 500),
		},
		{
			StatusCode: 404,
			Title:      "",
			Headers:    map[string]string{},
			Body:       strings.Repeat("not found ", 600),
		},
	}

	for i, resp := range cases {
		obs := observationFromHTTP(resp)

		e.mu.RLock()
		fast := map[string]bool{}
		for _, m := range e.analyzeLocked(resp, obs) {
			fast[m.Technology] = true
		}
		brute := map[string]bool{}
		for _, rule := range e.compiled {
			if matchRule(resp, obs, rule) != nil {
				brute[rule.name] = true
			}
		}
		e.mu.RUnlock()

		if len(fast) != len(brute) {
			t.Fatalf("case %d 命中数不一致: fast=%d brute=%d\nfast=%v\nbrute=%v", i, len(fast), len(brute), fast, brute)
		}
		for name := range brute {
			if !fast[name] {
				t.Fatalf("case %d 预筛漏报规则 %q", i, name)
			}
		}
	}
}

// T10：requiredLiterals 对不安全子树必须返回 false，否则会漏报。
func TestRequiredLiteralsSafety(t *testing.T) {
	mustParse := func(expr string) reconfp.Expr {
		e, err := reconfp.ParseExpression(expr)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", expr, err)
		}
		return e
	}

	cases := []struct {
		expr string
		ok   bool
	}{
		{`body="nginx"`, true},
		{`body="a" && body="b"`, true},
		{`body="a" && body!="b"`, true},
		{`body="a" || body="b"`, true},
		{`body="a" || body~="x"`, false},
		{`body="a" || !body="b"`, false},
		{`body!="a"`, false},
		{`body~="nginx"`, true}, // 正则里能提取出必需字面量 nginx
		{`body~="[0-9]{32}"`, false},
		{`status=="200"`, true}, // 数值字段也有确定的字面量；observationTexts 会扫描 status
	}
	for _, c := range cases {
		_, ok := requiredLiterals(mustParse(c.expr))
		if ok != c.ok {
			t.Fatalf("requiredLiterals(%q) ok=%v，期望 %v", c.expr, ok, c.ok)
		}
	}
}

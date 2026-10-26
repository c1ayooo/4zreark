package fingerprint

import "testing"

// T10：布尔表达式（&& / || / ! / 括号）必须能正确求值。
func TestParseExpressionBoolean(t *testing.T) {
	expr, err := ParseExpression(`header="X-Edge" && !body="blocked"`)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	ok := Observation{
		HeaderText: "X-Edge: yes\r\n",
		Body:       "welcome",
	}
	if !expr.Eval(&ok) {
		t.Fatal("header 命中且 body 不含 blocked 时应为 true")
	}

	bad := Observation{
		HeaderText: "X-Edge: yes\r\n",
		Body:       "blocked by waf",
	}
	if expr.Eval(&bad) {
		t.Fatal("body 含 blocked 时应为 false")
	}
}

func TestParseExpressionPrecedence(t *testing.T) {
	expr, err := ParseExpression(`body="a" || body="b" && status=="200"`)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	// && 优先级高于 ||：等价于 a || (b && 200)
	if !expr.Eval(&Observation{Body: "a", Status: 404}) {
		t.Fatal("body=a 应短路为 true，不受 status 影响")
	}
	if expr.Eval(&Observation{Body: "b", Status: 404}) {
		t.Fatal("body=b 但 status!=200 应为 false")
	}
	if !expr.Eval(&Observation{Body: "b", Status: 200}) {
		t.Fatal("body=b 且 status=200 应为 true")
	}
}

package fingerprint

import (
	"testing"

	reconfp "github.com/c1ayooo/4zreark/internal/recon/fingerprint"
	"golang.org/x/text/encoding/simplifiedchinese"
)

// T10：GBK 页面先解码再匹配，中文标题规则才能命中。
func TestGBKTitleMatching(t *testing.T) {
	html := `<html><head><title>管理后台</title></head><body><img src="/wp-content/a.png"></body></html>`
	gbk, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(html))
	if err != nil {
		t.Fatalf("GBK 编码失败: %v", err)
	}

	e := NewDSLEngine()
	if err := e.LoadRulesFromFile("testdata/t8_rules.yaml"); err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	matches := e.AnalyzeResponse(&HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html; charset=gbk"},
		Body:       string(gbk),
		// Title 留空：模拟旧扫描器未能正确提取 GBK 标题的情况
	})

	var found bool
	for _, m := range matches {
		if m.Technology == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Fatalf("GBK 页面应命中 WordPress（body wp-content + title 后台），实际 %+v", matches)
	}
}

// T10：旧 DSL 五种函数都能翻译成可编译的表达式。
func TestTranslateLegacyDSL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{`contains(body, 'wp-content', 'wordpress')`, `(body="wp-content" || body="wordpress")`},
		{`contains_all(header, 'spring', 'jsessionid')`, `(header="spring" && header="jsessionid")`},
		{`title('后台')`, `title="后台"`},
		{`status(200)`, `status=="200"`},
		{`icon('/favicon.ico', 'abc123')`, `(icon_hash=="abc123" || icon_md5=="abc123")`},
		{`regex(body, '[.]jsp$')`, `body~="[.]jsp$"`},
	}
	for _, c := range cases {
		got, err := translateDSL(c.in)
		if err != nil {
			t.Fatalf("translateDSL(%q) 失败: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("translateDSL(%q)=%q，期望 %q", c.in, got, c.want)
		}
		if _, err := reconfp.ParseExpression(got); err != nil {
			t.Fatalf("翻译结果无法编译: %q: %v", got, err)
		}
	}
}

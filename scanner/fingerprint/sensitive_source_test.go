package fingerprint

import (
	"github.com/c1ayooo/4zreark/config"
	"path/filepath"
	"testing"
)

// sensitive.yaml 的条目是「泄露特征」，不是技术栈：命中时必须带 source=sensitive，
// 扫描器据此把它们挡在 sites.tech 之外（历史问题：Linkfinder / 系统绝对路径泄漏
// 这类词条会把技术栈统计和筛选污染掉）。
func TestSensitiveRulesTaggedAsSensitive(t *testing.T) {
	rules := []byte(`
Linux私钥泄漏:
  dsl:
  - contains(body, 'BEGIN RSA PRIVATE KEY')
`)
	e := NewDSLEngine()
	if err := e.LoadRulesFromBytes(rules, filepath.Join("config", "dicts", "yaml", "sensitive.yaml")); err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}

	matches := e.AnalyzeResponse(&HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
	})
	if len(matches) == 0 {
		t.Fatal("应命中 Linux私钥泄漏 规则")
	}
	for _, m := range matches {
		if m.Source != "sensitive" {
			t.Fatalf("sensitive.yaml 的命中应标记 source=sensitive，实际 %q（规则 %s）", m.Source, m.RuleName)
		}
	}

	// 普通指纹规则不能被误标
	plain := NewDSLEngine()
	if err := plain.LoadRulesFromBytes([]byte(`
WordPress:
  dsl:
  - contains(body, '/wp-content/')
`), filepath.Join("config", "dicts", "yaml", "finger.yaml")); err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	got := plain.AnalyzeResponse(&HTTPResponse{
		StatusCode: 200,
		Body:       `<img src="/wp-content/a.png">`,
	})
	if len(got) == 0 {
		t.Fatal("应命中 WordPress")
	}
	if got[0].Source != "fingerprint" {
		t.Fatalf("普通指纹规则的 source 应为 fingerprint，实际 %q", got[0].Source)
	}
}

// 真实 sensitive.yaml：每条规则的 source 都必须是 sensitive。
func TestRealSensitiveYamlTagged(t *testing.T) {
	raw, err := config.ReadDictFile("config/dicts/yaml/sensitive.yaml")
	if err != nil {
		t.Fatalf("读取内置 sensitive.yaml 失败: %v", err)
	}
	e := NewDSLEngine()
	if err := e.LoadRulesFromBytes(raw, "config/dicts/yaml/sensitive.yaml"); err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if _, ok := e.compiled["Linkfinder"]; !ok {
		t.Fatal("Linkfinder 规则应被加载")
	}
	for name, r := range e.compiled {
		if r.source != "sensitive" {
			t.Fatalf("规则 %s 的 source 应为 sensitive，实际 %q", name, r.source)
		}
	}
}

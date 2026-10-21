package fingerprint

import (
	"sort"
	"testing"
)

// T8 特性测试：固定输入 -> 固定输出，锁定旧 DSL 引擎的对外行为。
// 阶段 B 替换引擎后，这些断言必须仍然成立（或按预期逐条记录差异）。

func loadT8Rules(t *testing.T) *DSLEngine {
	t.Helper()
	e := NewDSLEngine()
	if err := e.LoadRulesFromFile("testdata/t8_rules.yaml"); err != nil {
		t.Fatalf("加载 T8 规则失败: %v", err)
	}
	if e.RulesCount() != 5 {
		t.Fatalf("规则数量不符: %d", e.RulesCount())
	}
	return e
}

func matchedNames(matches []*FingerprintMatch) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.RuleName)
	}
	sort.Strings(out)
	return out
}

func assertNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("命中规则不符: %v，期望 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("命中规则不符: %v，期望 %v", got, want)
		}
	}
}

func TestT8FingerprintRuleMatrix(t *testing.T) {
	e := loadT8Rules(t)

	cases := []struct {
		name string
		resp *HTTPResponse
		want []string
	}{
		{
			name: "OR 命中 header",
			resp: &HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"Server": "nginx/1.24.0"},
				Body:       "hello",
			},
			want: []string{"Nginx"},
		},
		{
			name: "OR 命中 body",
			resp: &HTTPResponse{
				StatusCode: 200,
				Body:       "powered by nginx",
			},
			want: []string{"Nginx"},
		},
		{
			name: "AND 两个条件都命中",
			resp: &HTTPResponse{
				StatusCode: 200,
				Title:      "管理后台",
				Body:       `<img src="/wp-content/logo.png">`,
			},
			want: []string{"WordPress"},
		},
		{
			name: "AND 只命中标题不成立",
			resp: &HTTPResponse{
				StatusCode: 200,
				Title:      "管理后台",
				Body:       "plain html",
			},
			want: nil,
		},
		{
			name: "contains_all 命中全部 token",
			resp: &HTTPResponse{
				StatusCode: 200,
				Headers: map[string]string{
					"X-Powered-By": "Spring Boot",
					"Set-Cookie":   "JSESSIONID=abc123",
				},
			},
			want: []string{"Spring"},
		},
		{
			name: "contains_all 缺一个 token",
			resp: &HTTPResponse{
				StatusCode: 200,
				Headers:    map[string]string{"X-Powered-By": "Spring Boot"},
			},
			want: nil,
		},
		{
			name: "AND regex + status 命中",
			resp: &HTTPResponse{
				StatusCode: 200,
				Body:       `<a href="/old/index.jsp">old</a>`,
			},
			want: []string{"LegacyJSP"},
		},
		{
			name: "AND regex 命中但 status 不符",
			resp: &HTTPResponse{
				StatusCode: 404,
				Body:       `<a href="/old/index.jsp">old</a>`,
			},
			want: nil,
		},
		{
			name: "icon 哈希命中",
			resp: &HTTPResponse{
				StatusCode: 200,
				IconHash:   "-12345",
			},
			want: []string{"IconOnly"},
		},
		{
			name: "空响应不命中",
			resp: &HTTPResponse{},
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertNames(t, matchedNames(e.AnalyzeResponse(c.resp)), c.want)
		})
	}
}

func TestT8FingerprintConfidence(t *testing.T) {
	e := loadT8Rules(t)

	// OR：命中一个即短路 -> 70
	orMatches := e.AnalyzeResponse(&HTTPResponse{
		StatusCode: 200,
		Headers:    map[string]string{"Server": "nginx"},
	})
	if len(orMatches) != 1 || orMatches[0].Confidence != 70 {
		t.Fatalf("OR 置信度不符: %+v", orMatches)
	}

	// AND：全部命中 -> 95
	andMatches := e.AnalyzeResponse(&HTTPResponse{
		StatusCode: 200,
		Title:      "后台",
		Body:       "wp-content",
	})
	if len(andMatches) != 1 || andMatches[0].Confidence != 95 {
		t.Fatalf("AND 置信度不符: %+v", andMatches)
	}
}

func TestT8FingerprintNilResponse(t *testing.T) {
	if got := loadT8Rules(t).AnalyzeResponse(nil); got != nil {
		t.Fatalf("nil 响应应返回 nil，实际 %+v", got)
	}
}

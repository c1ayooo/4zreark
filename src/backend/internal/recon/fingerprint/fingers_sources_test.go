package fingerprint

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
)

func gz(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func TestParseEHoleFinger(t *testing.T) {
	data := gz(t, map[string]any{"fingerprint": []map[string]any{
		{"cms": "Seeyon", "method": "keyword", "location": "body", "keyword": []string{"/seeyon/common/", "LOGIN"}},
		{"cms": "Firewall", "method": "keyword", "location": "header", "keyword": []string{"X-FW"}},
		{"cms": "BadRegex", "method": "regular", "location": "body", "keyword": []string{"("}}, // 非法正则
	}})
	rules, stats, err := ParseEHoleFinger(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || stats.Imported != 2 {
		t.Fatalf("rules=%d stats=%+v", len(rules), stats)
	}
	for _, r := range rules {
		if _, err := ParseExpression(r.Expression); err != nil {
			t.Fatalf("规则 %s 未过 DSL 校验: %v", r.Name, err)
		}
	}
	// 多关键字 AND + 小写化
	seeyon := rules[0]
	want := `(body = "/seeyon/common/" && body = "login")`
	if seeyon.Expression != want {
		t.Fatalf("seeyon 表达式 = %s, want %s", seeyon.Expression, want)
	}
	if rules[1].Expression != `(header = "x-fw")` {
		t.Fatalf("header 表达式 = %s", rules[1].Expression)
	}
	// 非 gzip 输入也要能处理（上游可能直接给明文）
	if _, _, err := ParseEHoleFinger([]byte(`{"fingerprint":[]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestParseGobyFinger(t *testing.T) {
	data := gz(t, []map[string]any{
		{
			"name":  "Router-X",
			"logic": "a || (b && c)",
			"rule": []map[string]any{
				{"label": "a", "feature": "Router X GUI"},
				{"label": "b", "feature": `realm=\"X`},
				{"label": "c", "feature": "Server: X"},
			},
		},
		{"name": "NoLogic", "rule": []map[string]any{{"label": "a", "feature": "only"}}},
		{"name": "Empty", "logic": "", "rule": nil},
	})
	rules, stats, err := ParseGobyFinger(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules=%d stats=%+v", len(rules), stats)
	}
	router := rules[0]
	// logic 原文代换：保留上游的空格
	if !strings.Contains(router.Expression, `(banner="Router X GUI")`) ||
		!strings.Contains(router.Expression, `(banner="realm=\\\"X") && (banner="Server: X")`) {
		t.Fatalf("goby 表达式 = %s", router.Expression)
	}
	if _, err := ParseExpression(router.Expression); err != nil {
		t.Fatalf("goby 表达式未过 DSL 校验: %v", err)
	}
}

func TestParseFingersHTTP(t *testing.T) {
	// favicon 对象的两种位置 + regexps + 无效正则
	data := gz(t, []map[string]any{
		{
			"name": "nifi",
			"rule": []map[string]any{
				{"regexps": map[string]any{"body": []string{`<a href="/nifi/">/nifi</a>`}}},
			},
		},
		{
			"name": "supermicro",
			"rule": []map[string]any{
				{"regexps": map[string]any{
					"body":    []string{"Supermicro"},
					"favicon": map[string]any{"mmh3": []string{"1410610129"}, "md5": []string{"23e8c7bd78e8cd826c5a6073b15068b1"}},
				}},
			},
		},
		{
			"name": "sibling-favicon",
			"rule": []map[string]any{
				{"regexps": map[string]any{"header": []string{"X-Sib"}}, "favicon": map[string]any{"mmh3": []string{"123"}}},
			},
		},
	})
	rules, stats, err := ParseFingersHTTP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || stats.Invalid != 0 {
		t.Fatalf("rules=%d stats=%+v", len(rules), stats)
	}
	found := map[string]string{}
	for _, r := range rules {
		if _, err := ParseExpression(r.Expression); err != nil {
			t.Fatalf("规则 %s 未过 DSL 校验: %v", r.Name, err)
		}
		found[r.Name] = r.Expression
	}
	if !strings.Contains(found["supermicro"], `(body ~= "Supermicro")`) ||
		!strings.Contains(found["supermicro"], `(icon_hash == "1410610129")`) ||
		!strings.Contains(found["supermicro"], `(icon_md5 == "23e8c7bd78e8cd826c5a6073b15068b1")`) {
		t.Fatalf("supermicro = %s", found["supermicro"])
	}
	if !strings.Contains(found["sibling-favicon"], `(header ~= "X-Sib")`) ||
		!strings.Contains(found["sibling-favicon"], `(icon_hash == "123")`) {
		t.Fatalf("sibling-favicon = %s", found["sibling-favicon"])
	}
}

func TestFingersResourceURLs(t *testing.T) {
	urls := FingersResourceURLs("ehole.json.gz")
	if len(urls) != 2 {
		t.Fatalf("候选 URL 数 = %d", len(urls))
	}
	if !bytes.Contains([]byte(urls[0]), []byte(fingersPinnedCommit)) {
		t.Fatal("raw URL 未钉 commit")
	}
}

package wih

import (
	"fmt"
	"strings"
	"testing"
)

// findPath 在候选里按路径查找，找不到返回 nil。
func findPath(cands []EndpointCandidate, path string) *EndpointCandidate {
	for i := range cands {
		if cands[i].Path == path {
			return &cands[i]
		}
	}
	return nil
}

// 用例 1：fetch 提取 + query 去除 + 第三方域名绝对 URL 丢弃
func TestWihExtractFetch(t *testing.T) {
	base := "https://example.com/"
	body := `fetch("/api/user/info");fetch('/api/list?page=2');fetch("https://cdn.other.com/lib.js")`
	got := ExtractEndpoints(base, body)

	if c := findPath(got, "/api/user/info"); c == nil || c.Source != "fetch" || c.Raw != "/api/user/info" {
		t.Fatalf("应提取到 /api/user/info（source=fetch），got %+v", got)
	}
	if c := findPath(got, "/api/list"); c == nil {
		t.Fatalf("query 应被去掉并提取 /api/list，got %+v", got)
	} else if c.Path != "/api/list" || strings.Contains(c.Path, "?") {
		t.Fatalf("/api/list 不应带 query，got %s", c.Path)
	}
	if findPath(got, "/lib.js") != nil {
		t.Fatalf("第三方域名绝对 URL 应被丢弃，got %+v", got)
	}
}

// 用例 2：axios.get/post/delete 提取 + 按路径去重（先到先得）
func TestWihExtractAxios(t *testing.T) {
	base := "https://example.com/"
	body := `axios.get("/v1/users");axios.post('/v1/users',{a:1});axios.delete("/v1/users/1")`
	got := ExtractEndpoints(base, body)

	if len(got) != 2 {
		t.Fatalf("重复的 /v1/users 应去重为一条，got %+v", got)
	}
	if c := findPath(got, "/v1/users"); c == nil || c.Source != "axios" {
		t.Fatalf("source 应为 axios，got %+v", got)
	}
	if findPath(got, "/v1/users/1") == nil {
		t.Fatalf("应提取到 /v1/users/1，got %+v", got)
	}
}

// 用例 3：$.ajax({url: ...}) 提取
func TestWihExtractAjax(t *testing.T) {
	base := "https://example.com/"
	body := "$.ajax({url: '/api/data', type: 'GET'});$.ajax({ timeout: 1000, url:\"/api/data\" });"
	got := ExtractEndpoints(base, body)

	if len(got) != 1 {
		t.Fatalf("$.ajax 的 url 应提取且去重为一条，got %+v", got)
	}
	if got[0].Path != "/api/data" || got[0].Source != "ajax" {
		t.Fatalf("应为 /api/data（source=ajax），got %+v", got[0])
	}
}

// 用例 4：url: / action= / href= 属性形态提取；mailto: 排除
func TestWihExtractAttr(t *testing.T) {
	base := "https://example.com/"
	body := `var cfg={url:"/cfg/init"};form.action="/login";a.href="/help";b.href="mailto:x@y.com"`
	got := ExtractEndpoints(base, body)

	if len(got) != 3 {
		t.Fatalf("应提取 3 条属性形态候选，got %+v", got)
	}
	for _, want := range []string{"/cfg/init", "/login", "/help"} {
		c := findPath(got, want)
		if c == nil || c.Source != "attr" {
			t.Fatalf("应提取 %s（source=attr），got %+v", want, got)
		}
	}
}

// 用例 5：相对路径字面量（../ 与 ./ 与 / 开头）解析到基准 URL
func TestWihExtractLiteral(t *testing.T) {
	base := "https://example.com/a/b/page.html"
	body := `var a="../up/api";var b="./sibling";var c="/root/api";var d="nopath"`
	got := ExtractEndpoints(base, body)

	want := map[string]string{
		"/a/up/api":    "../up/api 应解析到 /a/up/api",
		"/a/b/sibling": "./sibling 应解析到 /a/b/sibling",
		"/root/api":    "/root/api 应原样保留",
	}
	if len(got) != len(want) {
		t.Fatalf("应提取 3 条（无斜杠的 nopath 排除），got %+v", got)
	}
	for path, msg := range want {
		if findPath(got, path) == nil {
			t.Fatalf("%s，got %+v", msg, got)
		}
	}
}

// 用例 6：静态资源 / 纯锚点 / javascript: 过滤
func TestWihExtractFilterStatic(t *testing.T) {
	base := "https://example.com/"
	body := `x("/static/app.js");y("/img/logo.png");z("/css/main.css");` +
		`u("/font/a.woff");v("#section");w("javascript:void(0)");n("/api/keep")`
	got := ExtractEndpoints(base, body)

	if len(got) != 1 || got[0].Path != "/api/keep" {
		t.Fatalf("静态资源/锚点/javascript: 应全被过滤，只留 /api/keep，got %+v", got)
	}
}

// 用例 7：同 host 绝对 URL 保留，第三方域名丢弃
func TestWihExtractAbsoluteSameHost(t *testing.T) {
	base := "https://example.com/app/"
	body := `fetch("https://example.com/api/same");fetch("https://evil.example.net/api/bad")`
	got := ExtractEndpoints(base, body)

	if len(got) != 1 {
		t.Fatalf("只应保留同 host 绝对 URL，got %+v", got)
	}
	if got[0].Path != "/api/same" {
		t.Fatalf("同 host 绝对 URL 应归一化为 /api/same，got %+v", got[0])
	}
}

// 用例 8：按归一化 path 去重（query 差异视为同一路径），优先级高的来源留下
func TestWihExtractDedupPriority(t *testing.T) {
	base := "https://example.com/"
	body := `fetch("/api/dup");var s="/api/dup";var t="/api/dup?x=1";`
	got := ExtractEndpoints(base, body)

	if len(got) != 1 {
		t.Fatalf("query 差异不应影响去重，got %+v", got)
	}
	if got[0].Source != "fetch" {
		t.Fatalf("优先级高的 fetch 来源应留下，got %+v", got[0])
	}
}

// 用例 9：归一化去掉 fragment；fragment/query 差异折叠为同一路径
func TestWihExtractNormalize(t *testing.T) {
	base := "https://example.com/"
	body := `var a="/api/x#frag";var b="/api/x?q=1";var c="/api/x?q=2";`
	got := ExtractEndpoints(base, body)

	if len(got) != 1 || got[0].Path != "/api/x" {
		t.Fatalf("fragment 与 query 均应去掉并折叠为 /api/x，got %+v", got)
	}
}

// 用例 10：单次提取候选上限 100
func TestWihExtractCap(t *testing.T) {
	base := "https://example.com/"
	var b strings.Builder
	for i := 0; i < 150; i++ {
		fmt.Fprintf(&b, `var p%d="/api/p%d";`, i, i)
	}
	got := ExtractEndpoints(base, b.String())
	if len(got) != maxCandidatesPerInput {
		t.Fatalf("候选数应截断到 %d，got %d", maxCandidatesPerInput, len(got))
	}
}

// 用例 11：非法基准 URL 返回 nil
func TestWihExtractInvalidBase(t *testing.T) {
	if got := ExtractEndpoints("not-a-host", `x("/api/a")`); got != nil {
		t.Fatalf("无 host 的基准 URL 应返回 nil，got %+v", got)
	}
	if got := ExtractEndpoints("", `x("/api/a")`); got != nil {
		t.Fatalf("空基准 URL 应返回 nil，got %+v", got)
	}
}

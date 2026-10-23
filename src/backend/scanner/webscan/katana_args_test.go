package webscan

import (
	"encoding/json"
	"strings"
	"testing"
)

// katana 的作用域必须显式落在命令行上：只靠结果层过滤，
// 工具仍会把站外链接抓回来，浪费配额并污染日志。
func TestKatanaCommonArgsIncludeFieldScope(t *testing.T) {
	k := &KatanaScanner{Depth: 3, Concurrency: 10, Timeout: 30, RateLimit: 150}
	args := k.commonArgs("/tmp/katana.json")

	var scope, rdn, output, jsCrawl, jsluice bool
	for i, a := range args {
		switch a {
		case "-jc":
			jsCrawl = true
		case "-jsl":
			jsluice = true
		case "-fs":
			scope = true
			if i+1 < len(args) && args[i+1] == "rdn" {
				rdn = true
			}
		case "-o":
			if i+1 < len(args) && args[i+1] == "/tmp/katana.json" {
				output = true
			}
		}
	}
	if !scope || !rdn {
		t.Fatalf("katana 参数缺少 -fs rdn: %v", args)
	}
	if !output {
		t.Fatalf("katana 参数缺少输出文件: %v", args)
	}
	if !jsCrawl || !jsluice {
		t.Fatalf("katana 需要同时开启 -jc 和 -jsl: %v", args)
	}
}

func TestKatanaCrawledURLKeepsDiscoverySource(t *testing.T) {
	var out KatanaJSONOutput
	line := `{"timestamp":"t","request":{"method":"get","endpoint":"https://career.example.com/category/allData","tag":"script","attribute":"jsluice-fetch","source":"https://example.com"},"response":{"status_code":200,"headers":{"content-type":"application/json; charset=utf-8"},"content_length":1234}}`
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatal(err)
	}
	got := katanaCrawledURL(out)
	if got.Method != "GET" {
		t.Errorf("method = %q，期望 GET", got.Method)
	}
	if got.Tag != "script" || got.Attribute != "jsluice-fetch" {
		t.Errorf("发现来源丢失: tag=%q attribute=%q", got.Tag, got.Attribute)
	}
	if got.Source != "https://example.com" {
		t.Errorf("来源页面 = %q", got.Source)
	}
	if got.ContentType != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", got.ContentType)
	}
	if got.Length != 1234 {
		t.Errorf("length = %d", got.Length)
	}
}

func TestKatanaExtensionFilterKeepsJS(t *testing.T) {
	k := &KatanaScanner{Depth: 3, Concurrency: 10, Timeout: 30, RateLimit: 150}
	args := k.commonArgs("/tmp/katana.json")
	var filter string
	for i, a := range args {
		if a == "-ef" && i+1 < len(args) {
			filter = args[i+1]
		}
	}
	if filter == "" {
		t.Fatal("katana 参数缺少 -ef")
	}
	for _, ext := range []string{"css", "png", "woff2", "map"} {
		if !strings.Contains(filter, ext) {
			t.Errorf("-ef 应包含 %s: %s", ext, filter)
		}
	}
	for _, ext := range []string{"js", "mjs"} {
		if strings.Contains(filter, ext) {
			t.Errorf("-ef 不应排除 %s（JS 需要保留）: %s", ext, filter)
		}
	}
}

func TestKatanaHeadlessArgs(t *testing.T) {
	plain := &KatanaScanner{Depth: 3, Concurrency: 5, Timeout: 30, RateLimit: 10}
	headless := &KatanaScanner{Depth: 3, Concurrency: 5, Timeout: 30, RateLimit: 10, Headless: true}

	plainArgs := plain.commonArgs("/tmp/katana.json")
	headlessArgs := headless.commonArgs("/tmp/katana.json")

	// 验收口径：headless 关闭时参数与旧行为一致（不带任何 headless 系参数）
	t.Logf("headless=off: katana %s", strings.Join(plainArgs, " "))
	t.Logf("headless=on : katana -u <target> %s", strings.Join(headlessArgs, " "))
	for _, a := range plainArgs {
		if a == "-headless" || a == "-no-sandbox" || a == "-xhr" || a == "-sc" {
			t.Fatalf("非 headless 模式不应出现 %s: %v", a, plainArgs)
		}
	}

	has := func(args []string, flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}
	for _, flag := range []string{"-headless", "-no-sandbox", "-xhr", "-sc"} {
		if !has(headlessArgs, flag) {
			t.Fatalf("headless 模式缺少 %s: %v", flag, headlessArgs)
		}
	}

	// headless 下 timeout 抬到下限 60，但不改结构体默认值
	timeoutOf := func(args []string) int {
		for i, a := range args {
			if a == "-timeout" && i+1 < len(args) {
				n := 0
				for _, c := range args[i+1] {
					if c < '0' || c > '9' {
						t.Fatalf("非法 timeout: %v", args)
					}
					n = n*10 + int(c-'0')
				}
				return n
			}
		}
		t.Fatalf("缺少 -timeout: %v", args)
		return 0
	}
	if got := timeoutOf(headlessArgs); got < 60 {
		t.Fatalf("headless timeout 应 >= 60, got %d", got)
	}
	if headless.Timeout != 30 {
		t.Fatalf("headless 不应改写结构体默认 Timeout, got %d", headless.Timeout)
	}
	if got := timeoutOf(plainArgs); got != 30 {
		t.Fatalf("非 headless timeout 应保持 30, got %d", got)
	}

	// 红线：-fs rdn / -ob -or 在两种模式下都必须还在
	for _, args := range [][]string{plainArgs, headlessArgs} {
		if !has(args, "-fs") || !has(args, "-ob") || !has(args, "-or") {
			t.Fatalf("红线参数丢失: %v", args)
		}
	}
}

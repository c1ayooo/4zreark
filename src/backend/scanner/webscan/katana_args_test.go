package webscan

import (
	"strings"
	"testing"
)

// katana 的作用域必须显式落在命令行上：只靠结果层过滤，
// 工具仍会把站外链接抓回来，浪费配额并污染日志。
func TestKatanaCommonArgsIncludeFieldScope(t *testing.T) {
	k := &KatanaScanner{Depth: 3, Concurrency: 10, Timeout: 30, RateLimit: 150}
	args := k.commonArgs("/tmp/katana.json")

	var scope, rdn, output bool
	for i, a := range args {
		switch a {
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

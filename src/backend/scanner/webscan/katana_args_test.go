package webscan

import "testing"

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

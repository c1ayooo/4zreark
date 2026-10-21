package vulnverify

import (
	"os"
	"path/filepath"
	"testing"
)

// -t 双目录解析（知识库分域方案 P2）：官方根在前、自定义根在后，模板文件按序
// 在根下解析，首个命中者生效；导入期已阻断 id 冲突，双根无歧义。
func TestBuildNucleiArgsRoots(t *testing.T) {
	official := t.TempDir()
	custom := t.TempDir()
	write := func(root, rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write(official, "http/cves/2021/CVE-2021-44228.yaml", "official")
	write(custom, "http/custom/my-check.yaml", "custom")
	write(custom, "file/scripts/run.yaml", "non-http") // 非 http 前缀：两条路径都拒绝

	refs := []TemplateRef{
		{ID: "CVE-2021-44228", Path: "http/cves/2021/CVE-2021-44228.yaml"},
		{ID: "my-check", Path: "http/custom/my-check.yaml"},
		{ID: "missing", Path: "http/nowhere/gone.yaml"},
		{ID: "code-run", Path: "file/scripts/run.yaml"},
	}
	args, paths := buildNucleiArgsRoots("http://target", []string{official, custom}, refs, []string{"critical", "high"}, 10, "-jsonl")

	joined := ""
	for _, a := range args {
		joined += a + "\x00"
	}
	if !contains(joined, filepath.Join(official, "http/cves/2021/CVE-2021-44228.yaml")) {
		t.Fatalf("官方根模板应从官方根解析: %v", args)
	}
	if !contains(joined, filepath.Join(custom, "http/custom/my-check.yaml")) {
		t.Fatalf("自定义模板应从自定义根解析: %v", args)
	}
	if contains(joined, "gone.yaml") || contains(joined, "run.yaml") {
		t.Fatalf("缺失与非 http 模板不应出现: %v", args)
	}
	if len(paths) != 2 {
		t.Fatalf("应命中 2 个模板路径: %v", paths)
	}

	// 单根旧语义（buildNucleiArgs 委托）：官方根里的模板照常解析
	args2, paths2 := buildNucleiArgs("http://target", official, refs[:1], []string{"critical"}, 10, "-json")
	if len(paths2) != 1 || !contains2(args2, filepath.Join(official, "http/cves/2021/CVE-2021-44228.yaml")) {
		t.Fatalf("单根旧语义被破坏: %v %v", args2, paths2)
	}

	// 无根：不挂任何 -t
	_, paths3 := buildNucleiArgsRoots("http://target", nil, refs, nil, 10, "-json")
	if len(paths3) != 0 {
		t.Fatalf("无根配置应全跳过: %v", paths3)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func contains2(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

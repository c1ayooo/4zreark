package githubleak

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRulesFile(t *testing.T, rulesJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "extra-rules.json")
	if err := os.WriteFile(path, []byte(rulesJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dynamicRulesDetector(t *testing.T, extraRulesPath string) *Detector {
	t.Helper()
	detector, err := NewDetector(Settings{
		FingerprintKey: "unit-test-fingerprint-key-32-bytes",
		Keywords:       []string{"storage-service"},
		ExtraRulesPath: extraRulesPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

// 动态规则（extra_rules_path / gitleaks 导入产物）加载语义：坏正则与缺 id 条目
// 逐条跳过，其余正常装载——可选增强不因个别脏条目整体失效（R3 约定）。
func TestDetectorDynamicRulesLoad(t *testing.T) {
	rules := `{"rules":[
		{"id":"acme_api_key","description":"Acme platform key","regex":"acme_[A-Za-z0-9]{20}","severity":"high"},
		{"id":"bad_regex","regex":"([unclosed","severity":"high"},
		{"id":"","regex":"missing-id-[A-Za-z0-9]{8}"},
		{"regex":"also-missing-id-[A-Za-z0-9]{8}"},
		{"id":"vendor_wrapped","description":"capture group","regex":"vendor\\{([A-Za-z0-9]{16})\\}","secret_group":1}
	]}`
	detector := dynamicRulesDetector(t, writeRulesFile(t, rules))
	if got := detector.DynamicRuleCount(); got != 2 {
		t.Fatalf("动态规则应加载 2 条（坏正则/缺 id 逐条跳过），实际 %d", got)
	}
}

func TestDetectorDynamicRulesDetect(t *testing.T) {
	rules := `{"rules":[
		{"id":"acme_api_key","regex":"acme_[A-Za-z0-9]{20}","severity":"high"},
		{"id":"vendor_wrapped","regex":"vendor\\{([A-Za-z0-9]{16})\\}","secret_group":1}
	]}`
	detector := dynamicRulesDetector(t, writeRulesFile(t, rules))
	item := SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: "aaaaaaaa",
		HTMLURL:   "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{"key = \"acme_A1b2C3d4E5f6G7h8I9j0\" and vendor{M3n4O5p6Q7rS8t9U}"},
	}
	candidates := detector.Detect("storage-service", item)
	var acme, vendor *Candidate
	for i := range candidates {
		switch candidates[i].SecretType {
		case "gitleaks:acme_api_key":
			acme = &candidates[i]
		case "gitleaks:vendor_wrapped":
			vendor = &candidates[i]
		}
	}
	if acme == nil {
		t.Fatal("整串匹配的动态规则未命中")
	}
	if acme.Confidence != "likely" || acme.Severity != "high" {
		t.Fatalf("整串候选 confidence/severity = %s/%s，应为 likely/high", acme.Confidence, acme.Severity)
	}
	if vendor == nil {
		t.Fatal("捕获组（secret_group）动态规则未命中")
	}
	if vendor.Severity != "medium" {
		t.Fatalf("缺省 severity 应落 medium，实际 %s", vendor.Severity)
	}
}

// 动态规则是可选增强：文件缺失/坏 JSON 等任何异常都静默降级，不阻断监控启动。
func TestDetectorDynamicRulesDegradeSilently(t *testing.T) {
	t.Run("文件不存在", func(t *testing.T) {
		detector := dynamicRulesDetector(t, filepath.Join(t.TempDir(), "missing.json"))
		if got := detector.DynamicRuleCount(); got != 0 {
			t.Fatalf("文件缺失应静默降级为 0 条，实际 %d", got)
		}
	})
	t.Run("空路径", func(t *testing.T) {
		detector := dynamicRulesDetector(t, "")
		if got := detector.DynamicRuleCount(); got != 0 {
			t.Fatalf("空路径应为 0 条，实际 %d", got)
		}
	})
	t.Run("坏JSON", func(t *testing.T) {
		detector := dynamicRulesDetector(t, writeRulesFile(t, `{"rules": [`))
		if got := detector.DynamicRuleCount(); got != 0 {
			t.Fatalf("坏 JSON 应静默降级为 0 条，实际 %d", got)
		}
	})
	t.Run("rules非数组", func(t *testing.T) {
		detector := dynamicRulesDetector(t, writeRulesFile(t, `{"rules": "nope"}`))
		if got := detector.DynamicRuleCount(); got != 0 {
			t.Fatalf("rules 类型错误应静默降级为 0 条，实际 %d", got)
		}
	})
}

// 入库规则文件必须能被运行时完整加载——extra_rules_path 接线守门：导入产物
// 损坏（坏正则比例过高导致 0 条装载）时在此失败，而非线上检测面静默缩水。
func TestDetectorShippedExtraRulesLoad(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "gitleaks_extra_rules.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("规则文件不存在（%v）", err)
	}
	detector := dynamicRulesDetector(t, path)
	if got := detector.DynamicRuleCount(); got == 0 {
		t.Fatal("入库 gitleaks 规则文件装载 0 条——导入产物或解析链路损坏")
	}
}

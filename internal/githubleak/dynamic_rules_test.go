package githubleak

import (
	"os"
	"strings"
	"testing"
)

// tcAKIDFixture 是合成测试样本（非真实凭据）：源码里拆行拼接，不出现完整
// AKID 字面量，避免 GitHub push protection 把测试数据当真密钥拦截。
var tcAKIDFixture = "AKID" +
	"qSaiV0Ed2vGh2Dm1D8mF" +
	"QhBnSxcadaOa"

func TestDetectorDynamicRulesAndChineseCloud(t *testing.T) {
	// 创建临时规则文件（测试结束后清理）
	rulesPath := "/tmp/extra_rules_test.json"
	rulesContent := `{
  "rules": [
    {
      "id": "sample-custom-key",
      "description": "Sample custom key pattern",
      "regex": "zreco_[A-Za-z0-9]{20,}",
      "secret_group": 0,
      "severity": "high"
    }
  ]
}`
	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0644); err != nil {
		t.Fatalf("写入测试规则文件失败: %v", err)
	}
	defer os.Remove(rulesPath)

	d, err := NewDetector(Settings{Token: strings.Repeat("b", 40), ExtraRulesPath: rulesPath})
	if err != nil {
		t.Fatal(err)
	}
	item := SearchItem{
		Repository: "owner/repo", Path: "config.env", BlobSHA: strings.Repeat("c", 40),
		HTMLURL: "https://github.com/owner/repo/blob/main/config.env",
		Fragments: []string{
			"access_key_id = LTAI5tBcF9xZq1WqMb2Cd3Ef",
			"secret_id: \"" + tcAKIDFixture + "\"",
			"token = zreco_AbCdEfGh9134567820KlMnOp",
		},
	}
	candidates := d.Detect("zh-cloud", item)
	kinds := map[string]bool{}
	for _, c := range candidates {
		kinds[c.SecretType] = true
	}
	if !kinds["aliyun_access_key"] {
		t.Errorf("阿里云 LTAI 未命中, got %v", kinds)
	}
	if !kinds["tencentcloud_secret_id"] {
		t.Errorf("腾讯云 AKID 未命中, got %v", kinds)
	}
	if !kinds["gitleaks:sample-custom-key"] {
		t.Errorf("动态规则未命中, got %v", kinds)
	}
}

package pipeline

import (
	"strings"
	"testing"
)

// 指纹驱动选模板的三道防线（蜗牛实测教训：登录页形态词把 619/800 模板
// 全选进来，等于换借口全量扫）：
//  1. techTokens 过滤页面形态噪声词
//  2. matchesTech 只对干净 token 做 tag 精确/ID名称子串匹配
//  3. selectTemplates 命中超半库判定无效，回退 verified
func TestTechTokensFiltersLoginNoise(t *testing.T) {
	techs := []string{
		"Auth-Login-Password-Input", "Auth-Login-Credential-Fields",
		"Exposure-SecretKey", "EwoMail", "Nginx", "jQuery",
	}
	tokens := techTokens(techs)
	set := map[string]bool{}
	for _, tok := range tokens {
		set[tok] = true
	}
	for _, noise := range []string{"auth", "login", "password", "input", "credential", "fields", "exposure", "secretkey", "nginx", "jquery"} {
		if set[noise] {
			t.Errorf("噪声 token %q 应被过滤", noise)
		}
	}
	if !set["ewomail"] {
		t.Error("产品 token ewomail 应保留")
	}
}

func TestMatchesTechWordBoundary(t *testing.T) {
	tpl := templateEntry{ID: "ewomail-webmail", Name: "EwoMail WebMail", Tags: []string{"mail"}}
	if !matchesTech(tpl, []string{"ewomail"}) {
		t.Error("产品 token 应命中")
	}
	// 干净 token 的子串匹配保留（受限输入词表里 "mail" 是 ewomail 的合理线索）
	if !matchesTech(tpl, []string{"mail"}) {
		t.Error("子串 mail 应命中 ewomail-webmail")
	}
}

func TestSelectTemplatesFallsBackWhenOverHalfLibrary(t *testing.T) {
	m := &VulnScanModule{}
	// 构造 10 条模板库：6 条 ID 含 "auth"（会被登录页 token 命中），
	// 4 条 verified 无关模板
	inv := make([]templateEntry, 0, 10)
	for i := 0; i < 6; i++ {
		inv = append(inv, templateEntry{
			ID: "auth-" + string(rune('a'+i)), Name: "auth thing", Verified: true,
			Content: "x",
		})
	}
	for i := 0; i < 4; i++ {
		inv = append(inv, templateEntry{
			ID: "misc-" + string(rune('a'+i)), Name: "misc", Verified: true,
			Content: "x",
		})
	}
	m.invOnce.Do(func() {}) // 预占 once：inventory() 将直接返回手动注入的 m.inv
	m.inv = inv
	m.invErr = nil

	// 登录页形态 token 经噪声过滤后为空 → 回退 verified 集合
	got := m.selectTemplates([]string{
		"Auth-Login-Password-Input", "Auth-Login-Credential-Fields", "Exposure-SecretKey",
	})
	// 全部 token 都是噪声 → tokens 为空 → 回退 verified（10 条全 verified）
	if len(got) != len(inv) {
		t.Fatalf("回退 verified 应返回 %d 条, 得到 %d", len(inv), len(got))
	}
}

func TestSelectTemplatesProductFingerprintStaysPrecise(t *testing.T) {
	m := &VulnScanModule{}
	inv := []templateEntry{
		{ID: "ewomail-webmail", Name: "EwoMail WebMail", Verified: false, Content: "a"},
		{ID: "nginx-default", Name: "Nginx Default", Verified: true, Content: "b"},
		{ID: "misc-1", Name: "misc one", Verified: true, Content: "c"},
		{ID: "misc-2", Name: "misc two", Verified: true, Content: "d"},
	}
	m.invOnce.Do(func() {})
	m.inv = inv
	m.invErr = nil

	got := m.selectTemplates([]string{"EwoMail"})
	if len(got) != 1 || got[0].ID != "ewomail-webmail" {
		t.Fatalf("产品指纹应精准命中 1 条, 得到 %+v", got)
	}
	if strings.Contains(got[0].ID, "misc") {
		t.Fatal("不应混入无关模板")
	}
}

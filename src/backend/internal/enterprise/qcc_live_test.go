package enterprise

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestQccLive 实测企查查网页 SSR 解析（需 QCC_COOKIE 环境变量）。
func TestQccLive(t *testing.T) {
	ck := os.Getenv("QCC_COOKIE")
	if ck == "" {
		t.Skip("未设置 QCC_COOKIE")
	}
	p, err := NewQccProvider(ck, "")
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	refs, err := p.Search(ctx, "腾讯", 5)
	if err != nil {
		t.Fatalf("搜索失败: %v", err)
	}
	t.Logf("搜索返回 %d 条", len(refs))
	for i, r := range refs {
		if i >= 5 {
			break
		}
		t.Logf("  %s | %s", r.ExtID, r.Name)
	}

	d, err := p.Detail(ctx, refs[0].ExtID)
	if err != nil {
		t.Fatalf("详情失败: %v", err)
	}
	wan, ok := ParseCapitalWan(d.RegisteredCapital)
	t.Logf("详情: name=%q legal=%q status=%q capital=%q (%.0f 万元, 解析成功=%v)",
		d.Name, d.LegalPerson, d.OpenStatus, d.RegisteredCapital, wan, ok)
	if d.Name == "" {
		t.Fatal("企业名为空")
	}
	if !ok {
		t.Fatalf("注册资本解析失败: %q", d.RegisteredCapital)
	}
}

func TestParseCapitalWan(t *testing.T) {
	cases := map[string]float64{
		"6500万元":   6500,
		"104250万元": 104250,
		"1.2亿元":    12000,
		"3000万人民币": 3000,
		"50000000元": 5000,
		"200万美元": 200,
		"1.5亿美元": 15000,
	}
	for in, want := range cases {
		got, ok := ParseCapitalWan(in)
		if !ok || got != want {
			t.Errorf("ParseCapitalWan(%q) = %v,%v want %v", in, got, ok, want)
		}
	}
}

package test

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// TestAqcInvestProbe 临时探针：爱企查 Investments/Branches/Domains 对
// 浙江省能源集团真实 pid 的返回（验证一键侦察只采到分公司、没采到
// 对外投资子公司如宁波海运的原因）。需要 ZRE_PG_PASSWORD 读托管会话。
func TestAqcInvestProbe(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	r, err := repo.Open(context.Background(), &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	defer r.Close()

	cookie, _, _ := service.ResolveDatasourceSession("aqc", "", "", "")
	if cookie == "" {
		t.Skip("跳过：aqc 无托管会话")
	}
	prov, err := enterprise.NewProvider("aqc", map[string]string{"cookie": cookie}, "")
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}

	const pid = "74592675267130" // 浙江省能源集团有限公司
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// 原始响应对照：investajax vs branchajax 的信封键名差异排查。
	hc := &http.Client{Timeout: 30 * time.Second}
	for _, path := range []string{
		"/detail/investajax?size=10&pid=" + pid + "&p=1",
		"/detail/branchajax?size=10&pid=" + pid + "&p=1",
	} {
		req, _ := http.NewRequest("GET", "https://aiqicha.baidu.com"+path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
		req.Header.Set("Referer", "https://aiqicha.baidu.com/company_detail_"+pid)
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Cookie", cookie)
		resp, err := hc.Do(req)
		if err != nil {
			t.Logf("raw %s: %v", path, err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		t.Logf("raw %s: HTTP %d len=%d body=%s", path, resp.StatusCode, len(body), string(body[:min(len(body), 300)]))
	}


	inv, more, err := prov.Investments(ctx, pid, 1, 10)
	t.Logf("Investments: n=%d more=%v err=%v", len(inv), more, err)
	for i, c := range inv {
		if i >= 30 {
			break
		}
		t.Logf("  投资 %s | %s", c.ExtID, c.Name)
	}

	br, _, err := prov.Branches(ctx, pid, 1, 10)
	t.Logf("Branches: n=%d err=%v", len(br), err)

	dom, _, err := prov.Domains(ctx, pid, 1, 100)
	t.Logf("Domains: n=%d err=%v", len(dom), err)
	for _, d := range dom {
		t.Logf("  域名 %s | %s | %s", d.Domain, d.Site, d.ICP)
	}
}


// TestTycInvestProbe 对照源：天眼查 Investments 是否能采到对外投资子公司。
func TestTycInvestProbe(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	cfg := config.LoadConfig("../config/config.yaml")
	r, err := repo.Open(context.Background(), &cfg.Postgres)
	if err != nil {
		t.Fatalf("连接 PG 失败: %v", err)
	}
	defer r.Close()

	cookie, _, _ := service.ResolveDatasourceSession("tyc", "", "", "")
	if cookie == "" {
		t.Skip("跳过：tyc 无托管会话")
	}
	prov, err := enterprise.NewProvider("tyc", map[string]string{"cookie": cookie}, "")
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	refs, err := prov.Search(ctx, "浙江省能源集团有限公司", 3)
	if err != nil {
		t.Fatalf("搜索失败: %v", err)
	}
	for _, c := range refs {
		t.Logf("搜索 %s | %s", c.ExtID, c.Name)
	}
	if len(refs) == 0 {
		t.Skip("搜索无结果")
	}
	inv, more, err := prov.Investments(ctx, refs[0].ExtID, 1, 50)
	t.Logf("TycInvestments: n=%d more=%v err=%v", len(inv), more, err)
	for i, c := range inv {
		if i >= 30 {
			break
		}
		t.Logf("  投资 %s | %s", c.ExtID, c.Name)
	}
	dom, _, err := prov.Domains(ctx, refs[0].ExtID, 1, 100)
	t.Logf("TycDomains: n=%d err=%v", len(dom), err)
	for _, d := range dom {
		t.Logf("  域名 %s | %s | %s", d.Domain, d.Site, d.ICP)
	}
}

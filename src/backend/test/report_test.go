package test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 报告域验收：信息收集（资产测绘）报告与漏洞交付报告的模板化输出。
func TestReportAssetAndVulnTemplates(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	code := fmt.Sprintf("rpt-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name, region) VALUES ($1,$2,$3) RETURNING id`,
		code, "报告测试项目", "cn").Scan(&projectID); err != nil {
		t.Fatalf("建项目失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `DELETE FROM projects WHERE id=$1`, projectID)
	})

	// 两个站点：一个可达带指纹，一个失联；再挂两个入口。
	var siteA, siteB int64
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO sites (project_id, site_key, host, port, protocol, value, ip, http_status, title, tech, state, discovery_type, raw_count)
VALUES ($1,$2,$2,443,'https','https://'||$2,'203.0.113.10',200,'A 系统','["nginx","vue"]'::jsonb,'reachable','scan',3)
RETURNING id`, projectID, code+".example.com").Scan(&siteA); err != nil {
		t.Fatalf("写站点 A 失败: %v", err)
	}
	if err := r.Pool().QueryRow(ctx, `
INSERT INTO sites (project_id, site_key, host, port, protocol, value, ip, http_status, title, tech, state, discovery_type, raw_count)
VALUES ($1,$2,$2,80,'http','http://'||$2,'203.0.113.11',0,'B 系统','[]'::jsonb,'lost','import',1)
RETURNING id`, projectID, "b."+code+".example.com").Scan(&siteB); err != nil {
		t.Fatalf("写站点 B 失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx, `
INSERT INTO site_endpoints (site_id, scheme, host, port) VALUES ($1,'https','a',443),($1,'http','a',80),($2,'http','b',80)`,
		siteA, siteB); err != nil {
		t.Fatalf("写入口失败: %v", err)
	}
	if _, err := r.Pool().Exec(ctx,
		`INSERT INTO seeds (project_id, kind, value, enabled) VALUES ($1,'domain',$2,true)`,
		projectID, code+".example.com"); err != nil {
		t.Fatalf("写种子失败: %v", err)
	}

	svc := service.NewReportService()

	// 1) 资产测绘报告：统计口径、清单、封面交付信息都必须落到产物里。
	assetRep, err := svc.Generate(ctx, service.ReportGenInput{
		ProjectID: projectID,
		Kind:      "asset",
		Template:  "asset-full",
		Format:    "html",
		Title:     "报告测试-信息收集",
		Delivery: models.ReportDelivery{
			ClientName: "验收客户", ReportNo: "RPT-T-1", Classification: "内部",
		},
	})
	if err != nil {
		t.Fatalf("生成资产报告失败: %v", err)
	}
	if assetRep.ReportKind != "asset" || assetRep.Template != "asset-full" {
		t.Fatalf("报告的 kind/template 落库错误: %s/%s", assetRep.ReportKind, assetRep.Template)
	}
	t.Cleanup(func() { cleanupReport(context.Background(), r, assetRep) })
	if assetRep.Summary.TotalAssets != 2 {
		t.Errorf("资产报告摘要站点数应为 2，实际 %d", assetRep.Summary.TotalAssets)
	}
	body := readReportFile(t, assetRep.FilePath)
	for _, want := range []string{
		"信息收集报告", "验收客户", "RPT-T-1", "域名清单", "站点清单", "203.0.113.10", "nginx",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("资产报告缺少 %q", want)
		}
	}
	if strings.Contains(body, "漏洞明细") {
		t.Error("资产报告不应包含漏洞明细章节")
	}

	// 2) Markdown 与资产简报模板：清单仍然存在，模板名写进页脚。
	mdRep, err := svc.Generate(ctx, service.ReportGenInput{
		ProjectID: projectID, Kind: "asset", Template: "asset-brief", Format: "markdown",
	})
	if err != nil {
		t.Fatalf("生成资产简报失败: %v", err)
	}
	t.Cleanup(func() { cleanupReport(context.Background(), r, mdRep) })
	md := readReportFile(t, mdRep.FilePath)
	for _, want := range []string{"## 一、执行摘要", "域名清单", "站点清单", "内部资产简报"} {
		if !strings.Contains(md, want) {
			t.Errorf("资产简报 Markdown 缺少 %q", want)
		}
	}

	// 3) 漏洞报告沿用旧行为：kind 缺省仍是 vuln。
	vulnRep, err := svc.Generate(ctx, service.ReportGenInput{Format: "html"})
	if err != nil {
		t.Fatalf("生成漏洞报告失败: %v", err)
	}
	t.Cleanup(func() { cleanupReport(context.Background(), r, vulnRep) })
	if vulnRep.ReportKind != "vuln" || vulnRep.Template != "standard" {
		t.Errorf("漏洞报告默认 kind/template 应为 vuln/standard，实际 %s/%s", vulnRep.ReportKind, vulnRep.Template)
	}
}

// 参数校验：模板与类型不匹配、未知模板、资产报告缺项目都必须 400 语义。
func TestReportRejectsBadInput(t *testing.T) {
	if os.Getenv("ZRE_PG_PASSWORD") == "" {
		t.Skip("跳过：未设置 ZRE_PG_PASSWORD")
	}
	svc := service.NewReportService()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cases := []struct {
		name string
		in   service.ReportGenInput
	}{
		{"未知模板", service.ReportGenInput{Kind: "vuln", Template: "nope"}},
		{"模板类型不匹配", service.ReportGenInput{Kind: "asset", Template: "standard", ProjectID: 1}},
		{"资产报告缺项目", service.ReportGenInput{Kind: "asset"}},
		{"非法 kind", service.ReportGenInput{Kind: "pdf"}},
	}
	for _, c := range cases {
		_, err := svc.Generate(ctx, c.in)
		if err == nil {
			t.Errorf("%s：应当报错", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "报告参数不合法") {
			t.Errorf("%s：错误类型应为参数错误，实际 %v", c.name, err)
		}
	}
}

func readReportFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取报告文件 %s 失败: %v", path, err)
	}
	return string(data)
}

// cleanupReport 删除测试生成的报告文件与台账行，避免把临时数据留在真实库里。
func cleanupReport(ctx context.Context, r *repo.Repo, rep *models.VulnReport) {
	if rep == nil {
		return
	}
	_ = os.Remove(rep.FilePath)
	_, _ = r.Pool().Exec(ctx, `DELETE FROM vuln_reports WHERE id=$1`, rep.ID.Hex())
}

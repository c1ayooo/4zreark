package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service"
)

// 报告生成链路：漏洞库 -> report 渲染 -> 文件落盘 -> 台账。
func TestReportGenerateHTML(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	name := "报告生成测试漏洞-" + time.Now().Format("150405.000000")
	ws := oid.NewObjectID()
	vuln := &models.Vulnerability{
		WorkspaceID: ws,
		Name:        name,
		Severity:    models.VulnSeverityHigh,
		Type:        "rce",
		Target:      "http://report-test.example.com/api",
		Method:      "POST",
		Evidence:    "=== REQUEST ===\nPOST /api HTTP/1.1\nHost: report-test.example.com\n\nx=1\n=== RESPONSE ===\nHTTP/1.1 200 OK\n\nroot:x:0:0",
		Request:     "POST /api HTTP/1.1\nHost: report-test.example.com\n\nx=1",
		Response:    "HTTP/1.1 200 OK\n\nroot:x:0:0",
		Scanner:     "test",
	}
	vulnSvc := service.NewVulnService()
	if err := vulnSvc.CreateVulnerability(vuln); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, vuln.ID.Hex())
	})

	reportSvc := service.NewReportService()
	rep, err := reportSvc.Generate(ctx, service.ReportGenInput{
		WorkspaceID: ws.Hex(),
		Name:        "报告链路测试-" + time.Now().Format("150405"),
		Title:       "4zreark 报告链路测试",
		Format:      "html",
	})
	if err != nil {
		t.Fatalf("生成报告失败: %v", err)
	}
	t.Cleanup(func() {
		if rep.FilePath != "" {
			_ = os.Remove(rep.FilePath)
		}
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vuln_reports WHERE id = $1`, rep.ID.Hex())
	})
	if rep.FilePath == "" {
		t.Fatal("报告文件路径为空")
	}
	raw, err := os.ReadFile(rep.FilePath)
	if err != nil {
		t.Fatalf("读取报告文件失败: %v", err)
	}
	if !strings.Contains(string(raw), name) {
		t.Fatalf("报告未包含测试漏洞标题")
	}
	if rep.Type != "html" {
		t.Fatalf("报告类型 = %q，期望 html", rep.Type)
	}
}

package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service"
)

// 漏洞确认 -> 自动沉淀 POC（默认不启用）。
func TestPocHarvestOnConfirm(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	name := "POC 沉淀测试漏洞-" + time.Now().Format("150405.000000")
	vuln := &models.Vulnerability{
		WorkspaceID: oid.NewObjectID(),
		Name:        name,
		Description: "测试用漏洞，包含目标 10.9.8.7:8080",
		Severity:    models.VulnSeverityHigh,
		Type:        "misconfig",
		Target:      "10.9.8.7:8080",
		Method:      "GET",
		Evidence:    "HTTP/1.1 200 OK",
		Solution:    "升级组件",
		Scanner:     "test",
	}
	vulnSvc := service.NewVulnService()
	if err := vulnSvc.CreateVulnerability(vuln); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, vuln.ID.Hex())
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM pocs WHERE name = $1`, name)
	})

	if err := vulnSvc.UpdateVulnerability(vuln.ID.Hex(), map[string]interface{}{
		"status": models.VulnStatusConfirmed,
	}); err != nil {
		t.Fatalf("确认漏洞失败: %v", err)
	}

	p, err := r.Pocs().GetByName(ctx, name)
	if err != nil {
		t.Fatalf("未沉淀 POC: %v", err)
	}
	if p.Enabled {
		t.Fatal("自动沉淀的 POC 不应默认启用")
	}
	if p.Source != "auto-harvest" || p.Origin != "import" {
		t.Fatalf("来源标记不符: source=%s origin=%s", p.Source, p.Origin)
	}
}

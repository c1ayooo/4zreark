package test

import (
	"context"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/service"
)

// 证据质量体检：缺 request/response/solution 的漏洞应被标出来。
func TestComponentEvidenceQuality(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ws := oid.NewObjectID()
	vuln := &models.Vulnerability{
		WorkspaceID: ws,
		Name:        "证据质量测试-" + time.Now().Format("150405.000000"),
		Severity:    models.VulnSeverityMedium,
		Type:        "xss",
		Target:      "http://evidence-test.example.com",
		Evidence:    "alert(1)",
		Scanner:     "test",
	}
	vulnSvc := service.NewVulnService()
	if err := vulnSvc.CreateVulnerability(vuln); err != nil {
		t.Fatalf("创建漏洞失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM vulnerabilities WHERE id = $1`, vuln.ID.Hex())
	})

	items, err := service.NewComponentService().EvidenceQuality(ctx, ws.Hex(), 20)
	if err != nil {
		t.Fatalf("证据体检失败: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("期望 1 条，实际 %d", len(items))
	}
	foundMissing := map[string]bool{}
	for _, m := range items[0].Missing {
		foundMissing[m] = true
	}
	if !foundMissing["request"] || !foundMissing["response"] || !foundMissing["solution"] {
		t.Fatalf("缺失项不符: %+v", items[0].Missing)
	}
}

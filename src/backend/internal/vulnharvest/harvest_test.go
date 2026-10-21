package vulnharvest

import (
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
)

func TestBuildMasksIPv4AndKeepsStructure(t *testing.T) {
	v := &models.Vulnerability{
		ID:          oid.NewObjectID(),
		Name:        "内网 Redis 未授权访问",
		Description: "目标 10.1.2.3:6379 无认证",
		Target:      "10.1.2.3:6379",
		Severity:    models.VulnSeverityHigh,
		Method:      "TCP",
		Payload:     "INFO",
		Evidence:    "redis_version:7.0",
		Solution:    "加 requirepass",
	}
	title, content, ok := Build(v)
	if !ok {
		t.Fatal("应可沉淀")
	}
	if !strings.Contains(title, "Redis") {
		t.Fatalf("标题不符: %s", title)
	}
	if strings.Contains(content, "10.1.2.3") {
		t.Fatal("IPv4 未脱敏")
	}
	if !strings.Contains(content, "10.1.x.x") {
		t.Fatal("脱敏形式不符")
	}
	for _, want := range []string{"## 漏洞概述", "## 复现步骤", "## 证据要点", "## 处置建议"} {
		if !strings.Contains(content, want) {
			t.Fatalf("缺少章节 %s", want)
		}
	}
}

func TestBuildRejectsEmptyTarget(t *testing.T) {
	if _, _, ok := Build(&models.Vulnerability{Name: "x"}); ok {
		t.Fatal("无目标不应沉淀")
	}
}

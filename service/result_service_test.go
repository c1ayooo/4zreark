package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/oid"
)

func TestPortDedupKeyUsesHostPortNotIP(t *testing.T) {
	taskID := oid.NewObjectID()
	mk := func(ip string) *models.ScanResult {
		return &models.ScanResult{
			TaskID: taskID,
			Type:   models.ResultTypePort,
			Data: map[string]interface{}{
				"host": "api.example.com",
				"ip":   ip,
				"port": "443",
			},
		}
	}
	a := mk("10.0.0.1")
	b := mk("10.0.0.2")
	applyDedupKey(a)
	applyDedupKey(b)
	if a.DedupKey == "" || a.DedupKey != b.DedupKey {
		t.Fatalf("同一 host:port 不同 IP 必须同键: %q != %q", a.DedupKey, b.DedupKey)
	}

	c := &models.ScanResult{
		TaskID: taskID,
		Type:   models.ResultTypePort,
		Data:   map[string]interface{}{"host": "api.example.com", "port": "80"},
	}
	applyDedupKey(c)
	if c.DedupKey == a.DedupKey {
		t.Fatal("不同端口不能共用去重键")
	}
}

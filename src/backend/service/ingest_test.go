package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/pipeline"
)

func TestRawRecordFromScan(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		host      string
		status    int
		wantOK    bool
		wantHost  string
		wantPort  int
		wantProto string
	}{
		{"完整 URL", "https://a.example.com:8443/x", "", 200, true, "a.example.com", 8443, "https"},
		{"无端口 URL", "http://b.example.com/", "", 200, true, "b.example.com", 0, "http"},
		{"只有 host + 状态码", "", "c.example.com", 200, true, "c.example.com", 0, "https"},
		{"没有 URL/host/状态码", "", "", 0, false, "", 0, ""},
		{"密文主机不可解析成 URL", "not a url", "", 200, false, "", 0, ""},
	}
	for _, c := range cases {
		rec, ok := rawRecordFromScan(c.url, c.host, "https", c.status, "title", "1.2.3.4", []string{"nginx"})
		if ok != c.wantOK {
			t.Fatalf("%s: ok=%v，期望 %v", c.name, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if rec.Host != c.wantHost || rec.Port != c.wantPort || rec.Protocol != c.wantProto {
			t.Fatalf("%s: rec=%+v，期望 host=%s port=%d proto=%s",
				c.name, rec, c.wantHost, c.wantPort, c.wantProto)
		}
		if rec.Source != "scan" || rec.Title != "title" || rec.IP != "1.2.3.4" {
			t.Fatalf("%s: 证据字段不符: %+v", c.name, rec)
		}
	}
}

func TestRawRecordFromCrawlKeepsInterfaceEvidence(t *testing.T) {
	rec, ok := rawRecordFromCrawl(pipeline.UrlResult{
		Output:      "https://career.meituan.com/category/allData",
		Method:      "POST",
		ContentType: "application/json; charset=utf-8",
		Tag:         "script",
		Attribute:   "jsluice-fetch",
		Referrer:    "https://career.meituan.com/",
	})
	if !ok {
		t.Fatal("爬虫 URL 应转成原始记录")
	}
	if rec.Evidence["method"] != "POST" ||
		rec.Evidence["content_type"] != "application/json; charset=utf-8" ||
		rec.Evidence["tag"] != "script" ||
		rec.Evidence["attribute"] != "jsluice-fetch" ||
		rec.Evidence["referrer"] != "https://career.meituan.com/" {
		t.Fatalf("采集来源没有完整保留: %+v", rec.Evidence)
	}
	if rec.Evidence["is_interface"] != true || rec.Evidence["interface_reason"] != "method" {
		t.Fatalf("接口标记不符: %+v", rec.Evidence)
	}

	// 没有 /api 前缀、没有方法/来源标签时，查询串仍能命中。
	rec, ok = rawRecordFromCrawl(pipeline.UrlResult{
		Output: "https://career.meituan.com/category/allData?type=1",
		Method: "GET",
	})
	if !ok {
		t.Fatal("带查询串的 URL 应转成原始记录")
	}
	if rec.Evidence["is_interface"] != true || rec.Evidence["interface_reason"] != "query" {
		t.Fatalf("查询串接口标记不符: %+v", rec.Evidence)
	}
}

func TestRawRecordFromPort(t *testing.T) {
	cases := []struct {
		host, service string
		port          int
		wantOK        bool
		wantProto     string
	}{
		{"store.meituan.com", "", 6379, true, "tcp"},
		{"store.meituan.com", "ssh", 22, true, "tcp"},
		{"store.meituan.com", "https", 443, true, "https"},
		{"store.meituan.com", "http", 80, true, "http"},
		{"", "ssh", 22, false, ""},
		{"store.meituan.com", "ssh", 0, false, ""},
	}
	for _, c := range cases {
		rec, ok := rawRecordFromPort(c.host, c.port, c.service, "1.2.3.4")
		if ok != c.wantOK {
			t.Fatalf("host=%s port=%d: ok=%v，期望 %v", c.host, c.port, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if rec.Host != c.host || rec.Port != c.port || rec.Protocol != c.wantProto || rec.Source != "scan" {
			t.Fatalf("端口记录不符: %+v", rec)
		}
		if rec.Value == "" || rec.IP != "1.2.3.4" {
			t.Fatalf("端口记录证据字段不符: %+v", rec)
		}
	}
}

func TestReplayPortAndServiceMapToRawRecords(t *testing.T) {
	portRow := repo.ReplayRow{
		Type: "port",
		Data: []byte(`{"host":"store.meituan.com","ip":"1.2.3.4","port":"6379","service":""}`),
	}
	rec, ok := rawRecordFromStoredResult(portRow, models.TaskTypePortScan, models.TaskConfig{})
	if !ok || rec.Port != 6379 || rec.Protocol != "tcp" || rec.Host != "store.meituan.com" {
		t.Fatalf("port 结果未映射为资产记录: %+v ok=%v", rec, ok)
	}

	serviceRow := repo.ReplayRow{
		Type: "service",
		Data: []byte(`{"host":"store.meituan.com","ip":"1.2.3.4","port":"22","service":"ssh"}`),
	}
	rec, ok = rawRecordFromStoredResult(serviceRow, models.TaskTypePortScan, models.TaskConfig{})
	if !ok || rec.Port != 22 || rec.Protocol != "tcp" {
		t.Fatalf("service 结果未映射为资产记录: %+v ok=%v", rec, ok)
	}
}

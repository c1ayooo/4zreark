package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

func TestRawRecordFromStoredResult(t *testing.T) {
	cases := []struct {
		name      string
		row       repo.ReplayRow
		taskType  models.TaskType
		config    models.TaskConfig
		wantOK    bool
		wantHost  string
		wantPort  int
		wantProto string
	}{
		{
			name: "subdomain",
			row: repo.ReplayRow{Type: "subdomain", Data: []byte(`{
				"url":"https://a.example.com/x","full_domain":"a.example.com",
				"status_code":200,"title":"A","ips":["10.0.0.5"],"technologies":["nginx"]}`)},
			taskType: models.TaskTypeSubdomain,
			wantOK:   true, wantHost: "a.example.com", wantPort: 0, wantProto: "https",
		},
		{
			name: "service 带端口",
			row: repo.ReplayRow{Type: "service", Data: []byte(`{
				"host":"b.example.com","port":8080,"status_code":403,"title":"B","ip":"10.0.0.6"}`)},
			taskType: models.TaskTypePortScan,
			wantOK:   true, wantHost: "b.example.com", wantPort: 8080, wantProto: "http",
		},
		{
			name:     "url",
			row:      repo.ReplayRow{Type: "url", Data: []byte(`{"url":"http://c.example.com/p","status_code":200}`)},
			taskType: models.TaskTypeCrawler,
			wantOK:   true,
			wantHost: "c.example.com",
			wantPort: 0, wantProto: "http",
		},
		{
			name:     "port 回放",
			row:      repo.ReplayRow{Type: "port", Data: []byte(`{"host":"d.example.com","port":22,"service":"ssh"}`)},
			taskType: models.TaskTypePortScan,
			wantOK:   true, wantHost: "d.example.com", wantPort: 22, wantProto: "tcp",
		},
		{
			name:     "port 未勾选端口扫描不回放",
			row:      repo.ReplayRow{Type: "port", Data: []byte(`{"host":"d.example.com","port":22}`)},
			taskType: models.TaskTypeSubdomain,
			wantOK:   false,
		},
		{
			name:     "url 未勾选爬虫不回放",
			row:      repo.ReplayRow{Type: "url", Data: []byte(`{"url":"http://c.example.com/p"}`)},
			taskType: models.TaskTypeSubdomain,
			wantOK:   false,
		},
		{name: "vuln 不回放", row: repo.ReplayRow{Type: "vuln", Data: []byte(`{"target":"x"}`)}, taskType: models.TaskTypeFull, wantOK: false},
		{name: "坏 JSON", row: repo.ReplayRow{Type: "subdomain", Data: []byte(`{`)}, taskType: models.TaskTypeSubdomain, wantOK: false},
	}

	for _, c := range cases {
		rec, ok := rawRecordFromStoredResult(c.row, c.taskType, c.config)
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
		if rec.Source != "scan" {
			t.Fatalf("%s: source 应为 scan（与实时写入共用去重键），实际 %q", c.name, rec.Source)
		}
	}
}

package pipeline

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/scanner/scope"
)

func TestModuleScopeGuards(t *testing.T) {
	s := scope.New([]string{"example.com", "10.0.0.0/24"})

	d := NewDirScanModule(context.Background(), nil, 1, nil)
	d.SetScope(s)
	if d.allowsURL("https://evil.test/x") {
		t.Fatal("目录扫描不应接收站外 URL")
	}
	if !d.allowsURL("https://a.example.com/x") {
		t.Fatal("目录扫描应接收授权子域")
	}

	c := NewCrawlerModule(context.Background(), nil, 1, true, false)
	c.SetScope(s)
	if c.allowsURL("http://10.0.0.9/") != true {
		t.Fatal("CIDR 内地址应放行")
	}
	if c.allowsURL("http://10.0.1.9/") {
		t.Fatal("CIDR 外地址应拒绝")
	}

	sub := NewSubdomainScanModule(context.Background(), nil, 1, true)
	sub.SetScope(s)
	if sub.allowsHost("evil.test") || !sub.allowsHost("a.example.com") {
		t.Fatal("子域模块 scope 判断不符")
	}
}

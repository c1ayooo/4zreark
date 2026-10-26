package whois

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// mockWhoisServer 起一个本地 TCP :43 服务，按收到的查询词返回脚本化应答。
func startMock(t *testing.T, handler func(query string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock 监听失败: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				c.Write([]byte(handler(strings.TrimSpace(line))))
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

const ianaResponse = `Domain Name: EXAMPLE.COM
whois: %SERVER`

const registryResponse = `Domain Name: example.com
Registrar WHOIS Server: %SERVER
Registrar: Registry-Registrar, Inc.
Registry Expiry Date: 2028-01-01T00:00:00Z
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned`

const registrarResponse = `Domain Name: example.com
Registrar: GoDaddy-like Registrar, LLC
Registrar URL: https://www.godaddy-like.com
Updated Date: 2026-03-01T08:00:00Z
Creation Date: 2010-05-05T12:00:00Z
Registrar Registration Expiration Date: 2028-01-01T00:00:00Z
Registrant Organization: Example Holdings LLC
Registrant Email: REDACTED FOR PRIVACY
Domain Status: clientTransferProhibited
Name Server: ns1.example.com
Name Server: NS2.EXAMPLE.COM.`

// 单跳：IANA → 注册商，字段直接解析；GDPR 脱敏占位清空；NS 归一去重。
func TestQuerySingleHop(t *testing.T) {
	restore := ianaWhoisServer
	defer func() { ianaWhoisServer = restore }()

	registrar := startMock(t, func(q string) string { return registrarResponse })
	iana := startMock(t, func(q string) string {
		return strings.ReplaceAll(ianaResponse, "%SERVER", registrar)
	})
	ianaWhoisServer = iana

	rec, err := Query(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Query 失败: %v", err)
	}
	if rec.Registrar != "GoDaddy-like Registrar, LLC" {
		t.Errorf("Registrar = %q", rec.Registrar)
	}
	if rec.RegistrantOrg != "Example Holdings LLC" {
		t.Errorf("RegistrantOrg = %q", rec.RegistrantOrg)
	}
	if rec.RegistrantEml != "" {
		t.Errorf("REDACTED 邮箱应被清空, got %q", rec.RegistrantEml)
	}
	if rec.CreationDate != "2010-05-05T12:00:00Z" || rec.ExpiryDate == "" {
		t.Errorf("日期解析不符: created=%q expiry=%q", rec.CreationDate, rec.ExpiryDate)
	}
	if len(rec.NameServers) != 2 || rec.NameServers[0] != "ns1.example.com" {
		t.Errorf("NS 归一/去重不符: %v", rec.NameServers)
	}
	if len(rec.Status) == 0 || rec.RawText == "" || rec.Server == "" {
		t.Errorf("Status/RawText/Server 不应缺省: %v %q %q", rec.Status, rec.RawText, rec.Server)
	}
}

// 两跳：IANA → 注册局（字段少 + 转介）→ 注册商（字段全）。合并语义：
// 已有值不被覆盖，缺失值由注册商补全。
func TestQueryTwoHopMerge(t *testing.T) {
	restore := ianaWhoisServer
	defer func() { ianaWhoisServer = restore }()

	registrar := startMock(t, func(q string) string { return registrarResponse })
	registry := startMock(t, func(q string) string {
		return strings.ReplaceAll(registryResponse, "%SERVER", registrar)
	})
	iana := startMock(t, func(q string) string {
		return strings.ReplaceAll(ianaResponse, "%SERVER", registry)
	})
	ianaWhoisServer = iana

	rec, err := Query(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Query 失败: %v", err)
	}
	if rec.Registrar != "Registry-Registrar, Inc." {
		t.Errorf("Registrar 应保留注册局的先答值, got %q", rec.Registrar)
	}
	if rec.RegistrantOrg != "Example Holdings LLC" {
		t.Errorf("RegistrantOrg 应由注册商补全, got %q", rec.RegistrantOrg)
	}
	if rec.CreationDate != "2010-05-05T12:00:00Z" {
		t.Errorf("CreationDate 应由注册商补全, got %q", rec.CreationDate)
	}
	if rec.Server != registrar {
		t.Errorf("最终 Server 应指向注册商 %q, got %q", registrar, rec.Server)
	}
}

// 小众 TLD：IANA 无转介且无注册数据 → 明确报错而不是空结构。
func TestQueryIANAOnlyNoData(t *testing.T) {
	restore := ianaWhoisServer
	defer func() { ianaWhoisServer = restore }()

	iana := startMock(t, func(q string) string { return "NOT FOUND\n% No entries found" })
	ianaWhoisServer = iana

	if _, err := Query(context.Background(), "xyz.example"); err == nil {
		t.Fatal("无注册数据应报错（TLD 未开放 whois）")
	}
}

func TestNormalizeDomainAndCleanValue(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path": "example.com",
		"EXAMPLE.COM.":             "example.com",
		"example.com:43":           "example.com",
		"":                         "",
		"localhost":                "",
		"a b.com":                  "",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
	if v := cleanValue("REDACTED FOR PRIVACY"); v != "" {
		t.Errorf("脱敏占位应清空, got %q", v)
	}
	if v := cleanValue("whois@godaddy-like.com"); v == "" {
		t.Error("正常邮箱不应清空")
	}
}

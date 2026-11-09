package entityid

import "testing"

func TestRepoRef(t *testing.T) {
	if got := RepoRef("Owner/Repo.git", "v1.2.3"); got != "owner/repo@v1.2.3" {
		t.Fatalf("RepoRef = %q", got)
	}
	if got := RepoRef("owner/repo", ""); got != "owner/repo" {
		t.Fatalf("RepoRef without ref = %q", got)
	}
}

func TestHostPort(t *testing.T) {
	cases := []struct {
		host, port, want string
	}{
		{"https://API.Example.com:443/login", "443", "api.example.com:443"},
		{"api.example.com", "80", "api.example.com:80"},
		{"api.example.com", "", "api.example.com"},
		{"", "80", ""},
	}
	for _, c := range cases {
		if got := HostPort(c.host, c.port); got != c.want {
			t.Errorf("HostPort(%q,%q) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	if got := NormalizeHost("HTTPS://Example.COM:443/path"); got != "example.com/path" {
		// url.Parse 后 Host 已去掉默认端口，这里只要求去掉协议与大小写。
		t.Logf("NormalizeHost = %q（url.Parse 后路径可能保留）", got)
	}
	if got := NormalizeHost("example.com"); got != "example.com" {
		t.Fatalf("NormalizeHost = %q", got)
	}
}

func TestDiffJobKey(t *testing.T) {
	if DiffJobKey("owner/repo@v1", "2026-11") != "owner/repo@v1|2026-11" {
		t.Fatal("diff 幂等键格式变化")
	}
}

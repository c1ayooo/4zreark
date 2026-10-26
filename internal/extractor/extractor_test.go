package extractor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForTemplate(t *testing.T) {
	cases := []struct {
		id      string
		wantNil bool
	}{
		{"vscode-sftp", false},
		{"phpinfo-files", false},
		{"xampp-phpinfo-detect", false},
		{"ruijie-phpinfo", false},
		{"git-config", false},
		{"exposed-gitmodules", false},
		{"mysql-dump", false},
		{"zip-backup-files", false},
		{"php-backup-files", false},
		{"sql-server-dump", false},
		{"totally-unknown-template", true},
		{"", true},
	}
	for _, c := range cases {
		got := ForTemplate(c.id)
		if (got == nil) != c.wantNil {
			t.Errorf("ForTemplate(%q) nil=%v, want nil=%v", c.id, got == nil, c.wantNil)
		}
	}
}

func TestSFTPExtractor(t *testing.T) {
	cases := []struct {
		name       string
		templateID string
		resp       string
		wantHit    bool
		wantHost   string
		wantUser   string
	}{
		{"标准 JSON 命中", "vscode-sftp",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
				`{"name":"web","host":"192.168.1.10","protocol":"sftp","port":2222,"username":"root","password":"s3cret","privateKeyPath":"~/.ssh/id_rsa"}`,
			true, "192.168.1.10", "root"},
		{"JSONC 注释回退", "vscode-sftp",
			"HTTP/1.1 200 OK\r\n\r\n" +
				"{\n  // 远程服务器配置\n  \"name\": \"prod\",\n  \"host\": \"10.0.0.8\",\n  \"protocol\": \"sftp\",\n  \"username\": \"deploy\",\n  \"password\": \"pw\",\n}",
			true, "10.0.0.8", "deploy"},
		{"默认端口推导", "vscode-sftp",
			"HTTP/1.1 200 OK\r\n\r\n" +
				`{"name":"x","host":"h.example.com","protocol":"sftp","username":"u"}`,
			true, "h.example.com", "u"},
		{"非 JSON 响应不产出", "vscode-sftp",
			"HTTP/1.1 200 OK\r\n\r\n<html><body>not a config</body></html>",
			false, "", ""},
		{"无响应报文不产出", "vscode-sftp", "", false, "", ""},
	}
	for _, c := range cases {
		f, err := (sftpExtractor{}).Extract(context.Background(), &Ctx{
			TemplateID: c.templateID,
			Target:     "https://h.example.com/sftp.json",
			MatchURL:   "https://h.example.com/sftp.json",
			Response:   c.resp,
		})
		if err != nil {
			t.Errorf("%s: 不应报错: %v", c.name, err)
			continue
		}
		if (f != nil) != c.wantHit {
			t.Errorf("%s: hit=%v, want %v", c.name, f != nil, c.wantHit)
			continue
		}
		if !c.wantHit {
			continue
		}
		if !strings.Contains(f.Data, c.wantHost) || !strings.Contains(f.Data, c.wantUser) {
			t.Errorf("%s: Data 缺少 host/user: %s", c.name, f.Data)
		}
		if f.Category != "sftp_credential" {
			t.Errorf("%s: category=%s, want sftp_credential", c.name, f.Category)
		}
	}
}

func TestPHPInfoExtractor(t *testing.T) {
	phpinfoHTML := "HTTP/1.1 200 OK\r\n\r\n" +
		`<html><head><title>phpinfo()</title></head><body>` +
		`<h1>PHP Version 7.4.33</h1>` +
		`<table><tr><td class="e">System</td><td class="v">Linux web01 5.4.0 x86_64</td></tr>` +
		`<tr><td class="e">SERVER_ADDR</td><td class="v">10.10.1.5</td></tr>` +
		`<tr><td class="e">SERVER_NAME</td><td class="v">www.example.com</td></tr>` +
		`<tr><td class="e">SERVER_SOFTWARE</td><td class="v">Apache/2.4.41 (Ubuntu) PHP/7.4.33</td></tr>` +
		`<tr><td class="e">DOCUMENT_ROOT</td><td class="v">/var/www/html</td></tr>` +
		`<tr><td class="e">PHP_SAPI</td><td class="v">fpm-fcgi</td></tr>` +
		`</table></body></html>`
	cases := []struct {
		name         string
		templateID   string
		resp         string
		wantHit      bool
		wantAddr     string
		wantInternal bool
	}{
		{"phpinfo 命中含内网 IP", "phpinfo-files", phpinfoHTML, true, "10.10.1.5", true},
		{"非 phpinfo 页面不产出", "phpinfo-files",
			"HTTP/1.1 200 OK\r\n\r\n<html><body>hello world</body></html>", false, "", false},
		{"无响应不产出", "xampp-phpinfo-detect", "", false, "", false},
	}
	for _, c := range cases {
		f, err := (phpinfoExtractor{}).Extract(context.Background(), &Ctx{
			TemplateID: c.templateID,
			Target:     "https://www.example.com/phpinfo.php",
			MatchURL:   "https://www.example.com/phpinfo.php",
			Response:   c.resp,
		})
		if err != nil {
			t.Errorf("%s: 不应报错: %v", c.name, err)
			continue
		}
		if (f != nil) != c.wantHit {
			t.Errorf("%s: hit=%v, want %v", c.name, f != nil, c.wantHit)
			continue
		}
		if !c.wantHit {
			continue
		}
		if !strings.Contains(f.Data, c.wantAddr) {
			t.Errorf("%s: Data 缺少 SERVER_ADDR: %s", c.name, f.Data)
		}
		if strings.Contains(f.Data, `"server_addr_internal":true`) != c.wantInternal {
			t.Errorf("%s: server_addr_internal 标记不符: %s", c.name, f.Data)
		}
		if !strings.Contains(f.Data, "7.4.33") {
			t.Errorf("%s: PHP 版本未提取: %s", c.name, f.Data)
		}
	}
}

func TestGitExtractor(t *testing.T) {
	gitConfig := "HTTP/1.1 200 OK\r\n\r\n" +
		"[core]\n\trepositoryformatversion = 0\n" +
		"[remote \"origin\"]\n" +
		"\turl = https://admin:secret123@git.example.com/team/repo.git\n" +
		"\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	cases := []struct {
		name       string
		templateID string
		matchURL   string
		resp       string
		extracted  []string
		wantHit    bool
		wantRemote string
		wantCred   bool
	}{
		{"git-config 内嵌凭据", "git-config", "https://example.com/repo/.git/config", gitConfig, nil, true, "https://admin:secret123@git.example.com/team/repo.git", true},
		{"extracted 片段携带 URL", "git-config", "https://example.com/repo/.git/config", "HTTP/1.1 200 OK\r\n\r\n[core]\n", []string{"url = https://user:pass@x.com/r.git"}, true, "url = https://user:pass@x.com/r.git", true},
		{"非 git 模板不产出", "other-template", "https://example.com/repo/.git/config", gitConfig, nil, false, "", false},
		{"空配置且无 git 路径不产出", "git-config", "https://example.com/other.html", "HTTP/1.1 200 OK\r\n\r\n", nil, false, "", false},
	}
	for _, c := range cases {
		f, err := (gitExtractor{}).Extract(context.Background(), &Ctx{
			TemplateID: c.templateID,
			Target:     "https://example.com/repo/.git/config",
			MatchURL:   c.matchURL,
			Response:   c.resp,
			Extracted:  c.extracted,
		})
		if err != nil {
			t.Errorf("%s: 不应报错: %v", c.name, err)
			continue
		}
		if (f != nil) != c.wantHit {
			t.Errorf("%s: hit=%v, want %v", c.name, f != nil, c.wantHit)
			continue
		}
		if !c.wantHit {
			continue
		}
		if c.wantRemote != "" && !strings.Contains(f.Data, c.wantRemote) {
			t.Errorf("%s: remote url 未提取: %s", c.name, f.Data)
		}
		if c.wantCred && !strings.Contains(f.Data, "has_credential") {
			t.Errorf("%s: 凭据标记缺失: %s", c.name, f.Data)
		}
	}
}

func TestBackupExtractor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("-- MySQL dump 8.0\nCREATE TABLE users (id int);\n"))
	}))
	defer srv.Close()

	f, err := (backupExtractor{}).Extract(context.Background(), &Ctx{
		TemplateID:  "mysql-dump",
		Target:      srv.URL + "/backup.sql",
		MatchURL:    srv.URL + "/backup.sql",
		HTTPClient:  srv.Client(),
		DownloadDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("backup 提取不应报错: %v", err)
	}
	if f == nil {
		t.Fatal("backup 命中应产出")
	}
	if f.Category != "backup_file" || f.Kind != "sql" {
		t.Fatalf("category/kind 不符: %s/%s", f.Category, f.Kind)
	}
	if f.FilePath == "" || !strings.Contains(f.Data, "sha256") {
		t.Fatalf("归档路径/哈希缺失: path=%q data=%s", f.FilePath, f.Data)
	}

	// 目录列表类（下载到 HTML）：不产出。
	htmlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>Index of /backups</title></head><body><ul><li>a.sql</li></ul></body></html>"))
	}))
	defer htmlSrv.Close()
	f2, err := (backupExtractor{}).Extract(context.Background(), &Ctx{
		TemplateID:  "backup-directory-listing",
		Target:      htmlSrv.URL + "/backups/",
		MatchURL:    htmlSrv.URL + "/backups/",
		HTTPClient:  htmlSrv.Client(),
		DownloadDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("HTML 列表提取不应报错: %v", err)
	}
	if f2 != nil {
		t.Fatalf("HTML 目录列表不应产出备份产物: %+v", f2)
	}
}

func TestBodyFromResponse(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello", "hello"},
		{"HTTP/1.1 200 OK\n\nhello", "hello"},
		{"no headers body", "no headers body"},
		{"", ""},
	}
	for _, c := range cases {
		if got := bodyFromResponse(c.in); got != c.want {
			t.Errorf("bodyFromResponse(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

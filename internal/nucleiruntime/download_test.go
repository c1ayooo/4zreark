package nucleiruntime

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExtractZipBinary(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "release.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	// 真实 release 里二进制可能带一层目录；用 basename 匹配即可。
	w, err := zw.Create("nuclei_3.11.1_linux_amd64/nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("fake-nuclei")); err != nil {
		t.Fatal(err)
	}
	// 非目标文件不应被选中。
	w2, _ := zw.Create("nuclei_3.11.1_linux_amd64/README.md")
	_, _ = w2.Write([]byte("readme"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "nuclei")
	if err := extractZipBinary(zipPath, "nuclei", dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake-nuclei" {
		t.Fatalf("extracted = %q", got)
	}
	if err := extractZipBinary(zipPath, "nuclei.exe", filepath.Join(dir, "nuclei.exe")); err == nil {
		t.Fatal("missing binary should error")
	}
}

func TestDownloadCandidates(t *testing.T) {
	u := "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/a.zip"
	t.Setenv("ZRE_GH_MIRROR", "https://m1.example, https://m2.example/")
	got := downloadCandidates([]string{u, u})
	want := []string{"https://m1.example/" + u, "https://m2.example/" + u, u}
	if len(got) != len(want) {
		t.Fatalf("显式镜像应优先且去重（3 个候选）: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("候选顺序错误: %v, want %v", got, want)
		}
	}

	t.Setenv("ZRE_GH_MIRROR", "")
	got = downloadCandidates([]string{u})
	if len(got) != 4 || got[0] != u {
		t.Fatalf("未配置时应为直连 + 3 个内置镜像: %v", got)
	}
	if !strings.HasPrefix(got[1], "https://gh-proxy.com/") {
		t.Errorf("实测可用的 gh-proxy.com 应排内置镜像首位: %v", got)
	}
	for _, c := range got[1:] {
		if !strings.HasSuffix(c, "/"+u) {
			t.Errorf("镜像候选格式错误: %s", c)
		}
	}
}

// 响应体传了一半被掐断（phase=body）时同源重试；连接级失败则直接换源，
// 不会在一个坏源上耗光后台 ctx。
func TestDownloadAnyRetriesEOF(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				return
			}
			// 声明 100 字节却只写 7 字节再断连：Do 成功、io.Copy 报 unexpected EOF。
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial")
			_ = buf.Flush()
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte("nuclei-payload"))
	}))
	defer srv.Close()

	m := New(t.TempDir(), nil)
	f, err := os.CreateTemp(t.TempDir(), "download-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := m.downloadAny(context.Background(), []string{srv.URL + "/nuclei.zip"}, f, nil); err != nil {
		t.Fatalf("EOF 后应重试成功: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("未发生重试: calls=%d", got)
	}
	raw, err := os.ReadFile(f.Name())
	if err != nil || string(raw) != "nuclei-payload" {
		t.Fatalf("重试后文件内容不完整: %q err=%v", string(raw), err)
	}
}

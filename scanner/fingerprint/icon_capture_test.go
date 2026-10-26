package fingerprint

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 扫描阶段抓到的 favicon 必须带 sha256 与原始字节，资产域才能自动入库。
func TestScanFingerprintCapturesIconBytes(t *testing.T) {
	// 1x1 PNG
	icon, err := base64.StdEncoding.DecodeString(
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" || r.URL.Path == "/favicon.png" {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(icon)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>icon test</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	s := NewFingerprintScanner(1)
	res := s.ScanFingerprint(context.Background(), srv.URL)
	if res == nil {
		t.Fatal("ScanFingerprint 返回 nil")
	}
	sum := sha256.Sum256(icon)
	if res.IconSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("IconSHA256 不符: %q", res.IconSHA256)
	}
	if len(res.IconData) != len(icon) {
		t.Fatalf("IconData 长度不符: %d", len(res.IconData))
	}
	if res.IconMMH3 == 0 || res.IconType == "" {
		t.Fatalf("图标哈希/类型缺失: mmh3=%d type=%q", res.IconMMH3, res.IconType)
	}
}

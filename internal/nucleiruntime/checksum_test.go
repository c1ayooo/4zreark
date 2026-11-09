package nucleiruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 上游清单解析：GNU 风格 "<sha256>  file" 与 BSD 风格 "<sha256> *file" 都要认。
func TestExpectedChecksum(t *testing.T) {
	content := `2b5d2a2d5c0b1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f  nuclei_3.3.9_linux_amd64.zip
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA *nuclei_3.3.9_darwin_arm64.zip
short  not-a-valid-line
`
	if got, ok := expectedChecksum(content, "nuclei_3.3.9_linux_amd64.zip"); !ok || len(got) != 64 {
		t.Fatalf("GNU 风格应解析出 64 位哈希: %q ok=%v", got, ok)
	}
	if got, ok := expectedChecksum(content, "nuclei_3.3.9_darwin_arm64.zip"); !ok || len(got) != 64 {
		t.Fatalf("BSD 星号风格应解析: %q ok=%v", got, ok)
	}
	if _, ok := expectedChecksum(content, "nuclei_3.3.9_windows_386.zip"); ok {
		t.Fatalf("缺失条目应返回 false")
	}
}

// 文件哈希计算与内容一致性。
func TestSHA256SumFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob.bin")
	data := []byte("nuclei-binary-payload")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := sha256SumFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("哈希不符: %s", got)
	}
	if _, err := sha256SumFile(filepath.Join(dir, "missing")); err == nil {
		t.Fatalf("缺失文件应报错")
	}
}

// 解析器对脏行健壮：空行、注释行、字段过多都不参与匹配。
func TestExpectedChecksumIgnoresJunk(t *testing.T) {
	content := strings.Join([]string{
		"",
		"# comment",
		"deadbeef extra fields here.bin",
		"2b5d2a2d5c0b1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f  target.zip",
	}, "\n")
	if got, ok := expectedChecksum(content, "target.zip"); !ok || !strings.HasPrefix(got, "2b5d") {
		t.Fatalf("有效行应被解析: %q ok=%v", got, ok)
	}
}

// 官方 v3.11.1 的清单资产带版本号；旧版裸名作为兜底候选。
func TestChecksumsURLVersioned(t *testing.T) {
	want := "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_checksums.txt"
	if got := checksumsURL("3.11.1"); got != want {
		t.Fatalf("checksumsURL = %s, want %s", got, want)
	}
	if got := checksumsURL("v3.11.1"); got != want {
		t.Fatalf("带 v 前缀版本应归一化: %s", got)
	}
	cands := checksumCandidates("3.11.1")
	if len(cands) != 2 || cands[0] != want ||
		!strings.HasSuffix(cands[1], "/v3.11.1/checksums.txt") {
		t.Fatalf("候选清单应含带版本号与裸名两种: %v", cands)
	}
}

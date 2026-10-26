package fingerprint

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/spaolacci/murmur3"
)

// T9 黄金值测试：favicon 的 mmh3 必须落在 dddd/FOFA/EHole 同一个哈希空间，
// 即 mmh3(Python base64.encodebytes(icon))。
//
// 这里的 fixture 是确定性字节串，覆盖 76 列折行的三个边界：
//   - 55–57 字节：base64 恰好 76 列（旧实现会多补一个换行，落进另一个空间）
//   - 100/120 字节：多段折行 + 末尾不足/正好 76 列

func goldenFixture(n int) []byte {
	d := make([]byte, n)
	for i := range d {
		d[i] = byte(i*7 + 13)
	}
	return d
}

// referenceEncodeBytes 独立实现 Python base64.encodebytes 的换行规则：
// 每 76 列一段，每段后都补 \n（包括最后一段，即使不足 76 列）。
func referenceEncodeBytes(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(raw); i += 76 {
		end := i + 76
		if end > len(raw) {
			end = len(raw)
		}
		b.WriteString(raw[i:end])
		b.WriteByte('\n')
	}
	return b.String()
}

func TestStdBase64MIMEMatchesPythonEncodebytes(t *testing.T) {
	for _, n := range []int{1, 54, 55, 56, 57, 76, 100, 120} {
		got := stdBase64MIME(goldenFixture(n))
		want := referenceEncodeBytes(goldenFixture(n))
		if got != want {
			t.Fatalf("n=%d 编码不一致:\n got=%q\nwant=%q", n, got, want)
		}
	}
}

func TestFaviconMMH3GoldenValues(t *testing.T) {
	want := map[int]string{
		1:   "-1081388334",
		55:  "-1127788618",
		57:  "654477405",
		76:  "-220008149",
		100: "1665491875",
		120: "406376946",
	}
	for n, w := range want {
		if got := faviconMMH3(goldenFixture(n)); got != w {
			t.Fatalf("n=%d favicon mmh3=%s，期望 %s（哈希空间变了）", n, got, w)
		}
	}
}

func TestSingleLineBase64IsDifferentSpace(t *testing.T) {
	data := goldenFixture(100)
	h := murmur3.New32WithSeed(0)
	_, _ = h.Write([]byte(base64.StdEncoding.EncodeToString(data)))
	singleLine := fmt.Sprint(int32(h.Sum32()))

	if got := faviconMMH3(data); got == singleLine {
		t.Fatalf("单行 base64 与 MIME 折行不应落在同一哈希值（都是 %s）", got)
	}
}

package report

import (
	"encoding/base64"
	"strings"
	"testing"
)

func pngB64(n int) string {
	// 合法 PNG 魔数 + 填充（base64 前 8 字节解码须命中 PNG 魔数）
	raw := append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, n)...)
	return base64.StdEncoding.EncodeToString(raw)
}

func TestHighlightResponse_ProofHint(t *testing.T) {
	resp := `HTTP/1.1 200 OK
{"code":0,"data":{"uid":10017322,"role":"admin","nickname":"张三"},"password":"x123"}`
	out := string(HighlightResponse(resp, "", "越权", `"role":"admin"`))
	// 证明位：橙红 hl-proof
	if !strings.Contains(out, `<mark class="hl-proof">&#34;role&#34;:&#34;admin&#34;</mark>`) {
		t.Errorf("证明位未以 hl-proof 高亮:\n%s", out)
	}
	// 自动规则仍在：密码字段黄底
	if !strings.Contains(out, `mark class="hl">`) {
		t.Error("自动规则高亮缺失")
	}
	// 无 proof 时不存在 hl-proof
	out2 := string(HighlightResponse(resp, "", "越权", ""))
	if strings.Contains(out2, "hl-proof") {
		t.Error("未传 proof 不应出现证明位高亮")
	}
}

func TestHighlightResponse_ProofRegex(t *testing.T) {
	resp := "rows: [a1, a2, a3]"
	out := string(HighlightResponse(resp, "", "", `a\d`))
	if strings.Count(out, `hl-proof`) != 3 {
		t.Errorf("正则证明位应命中 3 处:\n%s", out)
	}
}

func TestHighlightResponse_Base64ImageRestore(t *testing.T) {
	b64 := pngB64(200) // ~270 字符的合法 PNG base64
	resp := "HTTP/1.1 200 OK\n{\"faceImg\":\"" + b64 + "\",\"ok\":true}"
	out := string(HighlightResponse(resp, "", "信息泄露", ""))
	if !strings.Contains(out, `<img class="resp-img" src="data:image/png;base64,`) {
		t.Errorf("base64 图片未还原为 <img>:\n%s", first240(out))
	}
	if strings.Count(out, "resp-img") != 1 {
		t.Errorf("应恰好还原 1 张图片:\n%s", first240(out))
	}
}

func TestHighlightResponse_Base64NonImageNotRestored(t *testing.T) {
	// 普通 base64（非图片魔数）不得误判为图片
	b64 := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("plain text payload;", 12)))
	resp := "HTTP/1.1 200 OK\ndata: " + b64
	out := string(HighlightResponse(resp, "", "", ""))
	if strings.Contains(out, "resp-img") {
		t.Error("非图片 base64 不应还原为 <img>")
	}
}

func TestHighlightResponse_DataURI(t *testing.T) {
	b64 := pngB64(120)
	resp := `HTTP/1.1 200 OK
{"avatar":"data:image/png;base64,` + b64 + `"}`
	out := string(HighlightResponse(resp, "", "", ""))
	if !strings.Contains(out, `<img class="resp-img" src="data:image/png;base64,`+b64+`"`) {
		t.Errorf("data URI 未整体还原:\n%s", first240(out))
	}
}

func first240(s string) string {
	if len(s) > 240 {
		return s[:240]
	}
	return s
}

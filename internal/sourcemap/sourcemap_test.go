package sourcemap

import (
	"strings"
	"testing"
)

// 标准 webpack 产物形态：带 sourceRoot、webpack:// 协议、loader 前缀、
// sourcesContent 内嵌完整源码。
const webpackMap = `{
  "version": 3,
  "file": "app.bundle.js",
  "sourceRoot": "",
  "sources": [
    "webpack://app/./src/index.js",
    "webpack://app/./src/api/client.ts",
    "webpack://app/./src/config.js",
    "node_modules/lodash/lodash.js"
  ],
  "sourcesContent": [
    "console.log('entry');\n",
    "const API_KEY = 'sk-live-abcdefgh12345';\nexport const client = { key: API_KEY };\n",
    "export const dbPass = 'root:toor';\n",
    null
  ],
  "names": [],
  "mappings": "AAAA;AACA;ACDA"
}`

func TestParseAndRestore(t *testing.T) {
	f, err := Parse([]byte(webpackMap))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := f.RestoredCount(); got != 3 {
		t.Fatalf("RestoredCount = %d, want 3（lodash 的 null content 不可还原）", got)
	}

	restored := f.Restore()
	if len(restored) != 3 {
		t.Fatalf("Restore = %d 个文件, want 3", len(restored))
	}

	// webpack:// 协议与 namespace 清洗
	if restored[0].Path != "src/index.js" {
		t.Errorf("Path[0] = %q, want src/index.js", restored[0].Path)
	}
	if !strings.Contains(restored[1].Content, "sk-live-abcdefgh12345") {
		t.Errorf("还原内容缺密钥样本: %q", restored[1].Content)
	}
	// 落盘名：序号前缀 + 保留原文件名
	if restored[1].Name != "001-client.ts" {
		t.Errorf("Name[1] = %q, want 001-client.ts", restored[1].Name)
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse([]byte(`{"version":3,"sources":[]}`)); err == nil {
		t.Fatal("无 sources 的 map 应报错")
	}
	if _, err := Parse([]byte(`not json`)); err == nil {
		t.Fatal("非 JSON 应报错")
	}
}

func TestParseNormalizesNullContentArray(t *testing.T) {
	// 部分工具产出等长 null 数组：应等价于缺席
	f, err := Parse([]byte(`{"version":3,"sources":["a.js","b.js"],"sourcesContent":[null,null]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if f.RestoredCount() != 0 || f.Restore() != nil {
		t.Fatal("全 null content 不应有还原结果")
	}
	// 但 sources 路径清单仍在（目录结构泄露）
	paths := f.SourcePaths()
	if len(paths) != 2 || paths[0] != "a.js" {
		t.Fatalf("SourcePaths = %v", paths)
	}
}

func TestSourcePathCleaning(t *testing.T) {
	f := &File{Sources: []string{
		"./src/a.vue!babel-loader",
		"../../../etc/passwd",
		"<anon>",
		"",
	}, SourceRoot: "web"}
	want := []string{"web/src/a.vue", "web/etc/passwd", "source-2", "source-3"}
	got := f.SourcePaths()
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SourcePaths[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestExtractSourceMappingURL(t *testing.T) {
	cases := []struct {
		js   string
		want string
	}{
		{"code();\n//# sourceMappingURL=app.js.map\n", "app.js.map"},
		{"code();\n//@ sourceMappingURL=old.map", "old.map"},
		{"code();\n//# sourceMappingURL=https://cdn.example.com/x.map", "https://cdn.example.com/x.map"},
		{"code();\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==", "data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=="},
		{"code();\n//# sourceMappingURL=inline.map\n//# sourceMappingURL=real.map\n", "real.map"},
		{"no map here", ""},
	}
	for _, c := range cases {
		if got := ExtractSourceMappingURL(c.js); got != c.want {
			t.Errorf("ExtractSourceMappingURL(%q) = %q, want %q", c.js, got, c.want)
		}
	}
}

func TestIsDataURI(t *testing.T) {
	if !IsDataURI("data:application/json;base64,xx") {
		t.Error("data URI 应识别")
	}
	if IsDataURI("app.js.map") {
		t.Error("相对路径不应识别为 data URI")
	}
}

func TestSafeFileName(t *testing.T) {
	if got := SafeFileName(0, "src/api/client.ts"); got != "000-client.ts" {
		t.Errorf("SafeFileName = %q", got)
	}
	if got := SafeFileName(2, "a/b/c d+e.js"); got != "002-c_d_e.js" {
		t.Errorf("非法字符应清洗: %q", got)
	}
	long := SafeFileName(1, strings.Repeat("x", 100)+".js")
	if len(long) > 68 {
		t.Errorf("超长文件名应截断: %d", len(long))
	}
}

package repo

import (
	"strings"
	"testing"
)

// 裸词与引号短语按 text 全文检索：搜索框里的普通关键词不能再报语法错误。
// 回归背景：q=com / q=1 曾以「不支持的查询字段」400，站点/域名/IP 视图搜索全废。
func TestBuildAssetWhereBareTerms(t *testing.T) {
	cases := []struct {
		name  string
		q     string
		want  string // 期望包含的 SQL 片段
		arg   string // 期望出现的参数
		nargs int
	}{
		{"英文裸词", "com", "s.value ILIKE", "%com%", 4},
		{"数字裸词", "1", "s.value ILIKE", "%1%", 4},
		{"中文裸词", "美团", "s.value ILIKE", "%美团%", 4},
		{"带引号短语", `"美团 招聘"`, "s.value ILIKE", "%美团 招聘%", 4},
		{"裸词与字段组合", `meituan && status_code="200"`, "AND", "%meituan%", 5},
		{"未知字段按裸词", `foo=1`, "s.value ILIKE", "%foo=1%", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expr, args, err := BuildAssetWhere(c.q)
			if err != nil {
				t.Fatalf("裸词查询不应报错: %v", err)
			}
			if !strings.Contains(expr, c.want) {
				t.Fatalf("表达式缺 %s：%s", c.want, expr)
			}
			if len(args) != c.nargs {
				t.Fatalf("参数个数期望 %d，实际 %d（%v）", c.nargs, len(args), args)
			}
			found := false
			for _, a := range args {
				if a == c.arg {
					found = true
				}
			}
			if !found {
				t.Fatalf("参数缺 %s：%v", c.arg, args)
			}
		})
	}
}

func TestBuildAssetWhereStillRejectsBadSyntax(t *testing.T) {
	for _, q := range []string{`title="未闭合`, `text=`} {
		if _, _, err := BuildAssetWhere(q); err == nil {
			t.Fatalf("残缺语法 %q 应报错", q)
		}
	}
}

func TestLooksLikeAssetDSL(t *testing.T) {
	cases := map[string]bool{
		"meituan":                  false,
		"美团 招聘":                    false,
		`"美团 招聘"`:                  false,
		`text="meituan"`:           true,
		`status_code="200" && a=1`: true,
		`host="a.com" || b=2`:      true,
		`port>=80`:                 true,
		`title!=x`:                 true,
		`a=b`:                      true,
	}
	for q, want := range cases {
		if got := looksLikeAssetDSL(q); got != want {
			t.Fatalf("looksLikeAssetDSL(%q) = %v，期望 %v", q, got, want)
		}
	}
}

func TestExtractSearchTerm(t *testing.T) {
	cases := map[string]string{
		"":                          "",
		"meituan":                   "meituan",
		`text="meituan"`:            "meituan",
		`host="a.com"`:              "a.com",
		`text="美团" && port="443"`:   "美团",
		`status_code="200"`:         "",
		`port="443" && state="x"`:   "",
	}
	for q, want := range cases {
		if got := ExtractSearchTerm(q); got != want {
			t.Fatalf("ExtractSearchTerm(%q) = %q，期望 %q", q, got, want)
		}
	}
}

// record 视图的 q 口径：裸词走 r.* 的 ILIKE，DSL 串走编译（条件经 join 引用 s.*），
// 残缺 DSL 报错而不是静默当纯文本。
func TestBuildRecordWhereSplitsDSLAndPlain(t *testing.T) {
	a := &AssetRepo{}

	w, err := a.buildRecordWhere(AssetQuery{Q: "meituan"})
	if err != nil {
		t.Fatalf("裸词不应报错: %v", err)
	}
	if !strings.Contains(w.String(), "r.value ILIKE") {
		t.Fatalf("裸词应走 r.* ILIKE：%s", w.String())
	}

	w, err = a.buildRecordWhere(AssetQuery{Q: `text="meituan"`})
	if err != nil {
		t.Fatalf("DSL 不应报错: %v", err)
	}
	if !strings.Contains(w.String(), "s.host ILIKE") {
		t.Fatalf("DSL text 应编译出 s.* 条件：%s", w.String())
	}

	if _, err := a.buildRecordWhere(AssetQuery{Q: `title="未闭合`}); err == nil {
		t.Fatalf("残缺 DSL 应报错")
	}
}

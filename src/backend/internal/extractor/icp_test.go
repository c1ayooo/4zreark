package extractor

import (
	"reflect"
	"strings"
	"testing"
)

func TestExtractICPNumbers(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"普通备案", `© 2026 美团 京ICP备2021038876号`, []string{"京ICP备2021038876号"}},
		{"许可证与后缀", `粤ICP证022187号 | 沪ICP备 14006631号-2`, []string{"粤ICP证022187号", "沪ICP备14006631号-2"}},
		{"去重保序", "京ICP备10000001号 粤ICP备20000002号 京ICP备10000001号", []string{"京ICP备10000001号", "粤ICP备20000002号"}},
		{"空正文", "", nil},
		{"非备案不误报", "仅ICP三个字母 iPhone 15", nil},
	}
	for _, c := range cases {
		got := ExtractICPNumbers(c.body)
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestExtractICPNumbersLargeBody(t *testing.T) {
	// 页面尾部常见的备案区不应因正文长而漏检
	body := strings.Repeat("<div>noise</div>", 5000) + `<a href="https://beian.miit.gov.cn">浙ICP备12027602号-3</a>`
	got := ExtractICPNumbers(body)
	if len(got) != 1 || got[0] != "浙ICP备12027602号-3" {
		t.Fatalf("got %v", got)
	}
}

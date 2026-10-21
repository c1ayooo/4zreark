package service

import "testing"

// takeoverTemplateID 决定漏洞去重键：同一服务重复命中不应刷出重复漏洞。
func TestTakeoverTemplateID(t *testing.T) {
	cases := map[string]string{
		"github-pages": "takeover/github-pages",
		"GitHub Pages": "takeover/github-pages",
		"heroku/edge":  "takeover/heroku-edge",
		"aws s3":       "takeover/aws-s3",
		"":             "takeover/dangling-cname",
	}
	for in, want := range cases {
		if got := takeoverTemplateID(in); got != want {
			t.Errorf("takeoverTemplateID(%q) = %q，期望 %q", in, got, want)
		}
	}
}

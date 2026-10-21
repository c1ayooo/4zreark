package cloudassets

import "testing"

func TestExtractCNAME(t *testing.T) {
	cases := []struct {
		cname    string
		provider string
		kind     string
		name     string
		ok       bool
	}{
		{"mybucket.s3.amazonaws.com", "aws", "bucket", "mybucket", true},
		{"d111111abcdef8.cloudfront.net", "aws", "distribution", "d111111abcdef8", true},
		{"acct.blob.core.windows.net", "azure", "storage_account", "acct", true},
		{"static.oss-cn-hangzhou.aliyuncs.com", "alicloud", "bucket", "static", true},
		{"assets-1250000000.cos.ap-guangzhou.myqcloud.com", "tencent", "bucket", "assets-1250000000", true},
		{"www.example.com", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		got, ok := ExtractCNAME(c.cname)
		if ok != c.ok {
			t.Fatalf("ExtractCNAME(%q) ok=%v，期望 %v", c.cname, ok, c.ok)
		}
		if !ok {
			continue
		}
		if got.Provider != c.provider || got.Kind != c.kind || got.Name != c.name {
			t.Fatalf("ExtractCNAME(%q)=%+v，期望 %s/%s/%s", c.cname, got, c.provider, c.kind, c.name)
		}
	}
}

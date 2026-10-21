package takeover

import "testing"

// T12：reconkit 指纹表要覆盖宿主原有样例 + 自身多出的 Gitee/Azure Blob。
func TestDetectMergedSamples(t *testing.T) {
	cases := []struct {
		name string
		c    Candidate
		want string
	}{
		{
			name: "GitHub Pages 特征页",
			c:    Candidate{Subdomain: "a.example.com", CNAME: "foo.github.io", TargetStatus: 404, TargetBody: "There isn't a GitHub Pages site here"},
			want: "github_pages",
		},
		{
			name: "Gitee Pages 特征页",
			c:    Candidate{Subdomain: "b.example.com", CNAME: "foo.gitee.io", TargetStatus: 404, TargetBody: "Gitee Pages 服务未开启"},
			want: "gitee_pages",
		},
		{
			name: "Azure Blob 悬挂 CNAME",
			c:    Candidate{Subdomain: "c.example.com", CNAME: "acct.blob.core.windows.net", TargetNXDomain: true},
			want: "azure_blob",
		},
		{
			name: "S3 NoSuchBucket",
			c:    Candidate{Subdomain: "d.example.com", CNAME: "bucket.s3.amazonaws.com", TargetStatus: 404, TargetBody: "NoSuchBucket"},
			want: "aws_s3",
		},
		{
			name: "未命中指纹",
			c:    Candidate{Subdomain: "e.example.com", CNAME: "www.example.com", TargetStatus: 200, TargetBody: "ok"},
			want: "",
		},
	}

	for _, tc := range cases {
		f := Detect(tc.c)
		got := ""
		if f != nil {
			got = f.Service
		}
		if got != tc.want {
			t.Fatalf("%s: Detect=%q，期望 %q（finding=%+v）", tc.name, got, tc.want, f)
		}
	}
}

func TestFingerprintsCopy(t *testing.T) {
	fps := Fingerprints()
	if len(fps) == 0 {
		t.Fatal("指纹表为空")
	}
	fps[0].Service = "mutated"
	if Fingerprints()[0].Service == "mutated" {
		t.Fatal("Fingerprints 应返回副本")
	}
}

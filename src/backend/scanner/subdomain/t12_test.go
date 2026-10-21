package subdomain

import "testing"

// T12：三处 CDN 判定收敛到 cdnmatch 后，旧样例仍应得到同一结论。
func TestT12CDNClassifierSingleSource(t *testing.T) {
	s := &DomainScanner{}

	if ok, provider := s.detectCDN([]string{"static.cloudflare.net"}, nil); !ok || provider != "Cloudflare" {
		t.Fatalf("Cloudflare CNAME 判定不符: ok=%v provider=%q", ok, provider)
	}
	if ok, provider := s.detectCDN([]string{"d111.cloudfront.net"}, nil); !ok || provider != "CloudFront" {
		t.Fatalf("CloudFront CNAME 判定不符: ok=%v provider=%q", ok, provider)
	}
	if ok, provider := s.detectCDN(nil, []string{"104.16.5.5"}); !ok || provider != "Cloudflare" {
		t.Fatalf("Cloudflare IP 判定不符: ok=%v provider=%q", ok, provider)
	}
	if ok, provider := s.detectCDN([]string{"www.example.com"}, []string{"192.0.2.10"}); ok || provider != "" {
		t.Fatalf("非 CDN 应返回 false/空: ok=%v provider=%q", ok, provider)
	}

	d := &CDNDetector{}
	if ok, provider := d.IsCDNIP("104.16.1.1"); !ok || provider != "Cloudflare" {
		t.Fatalf("IsCDNIP 判定不符: ok=%v provider=%q", ok, provider)
	}
}

// T12：reconkit 的 Gitee/Azure Blob 指纹已并入宿主表，原有条目仍在。
func TestT12TakeoverTableMerged(t *testing.T) {
	fps := getDefaultFingerprints()
	if len(fps) == 0 {
		t.Fatal("指纹表为空")
	}

	hasCNAME := func(want string) bool {
		for _, fp := range fps {
			for _, cn := range fp.CNames {
				if cn == want {
					return true
				}
			}
		}
		return false
	}
	for _, suffix := range []string{".gitee.io", ".blob.core.windows.net", ".worksites.net"} {
		if !hasCNAME(suffix) {
			t.Fatalf("合并后的指纹表缺少 %s", suffix)
		}
	}
}

package enterprise

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/scanner/enscan"
)

// fakeENSQuerier 固定响应的查询桩。
type fakeENSQuerier struct {
	available bool
	result    *enscan.ENScanResult
	err       error
	lastOpts  *enscan.ENScanQueryOptions
}

func (f *fakeENSQuerier) IsAvailable() bool { return f.available }

func (f *fakeENSQuerier) QueryCompany(ctx context.Context, name string, opts *enscan.ENScanQueryOptions) (*enscan.ENScanResult, error) {
	f.lastOpts = opts
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func fakeENResult() *enscan.ENScanResult {
	return &enscan.ENScanResult{
		ICPs: []enscan.ICPInfo{
			{Domain: "mi.com", ICP: "京ICP备12345号", SiteName: "小米官网", CompanyName: "小米科技"},
			{Domain: "", ICP: "空域名应跳过"},
		},
		Apps: []enscan.AppInfo{
			{Name: "小米商城", Market: "七麦", Package: "com.xiaomi.shop"},
			{Name: ""},
		},
		WxApps:  []enscan.WxAppInfo{{Name: "小米商城小程序", AppID: "wx123"}},
		Wechats: []enscan.WechatInfo{{Name: "小米", WechatID: "xiaomi"}},
		Weibos:  []enscan.WeiboInfo{{Name: "小米公司", URL: "weibo.com/xiaomi"}},
	}
}

func TestENScanProviderSearchAndDetail(t *testing.T) {
	fake := &fakeENSQuerier{available: true, result: fakeENResult()}
	p := &ENScanProvider{client: fake}

	refs, err := p.Search(context.Background(), "小米科技", 5)
	if err != nil {
		t.Fatalf("Search 失败: %v", err)
	}
	if len(refs) != 1 || refs[0].ExtID != "小米科技" || refs[0].Name != "小米科技" {
		t.Fatalf("Search 应返回单条 ext_id=企业名的引用, got %+v", refs)
	}
	if fake.lastOpts == nil || len(fake.lastOpts.Fields) != 1 || fake.lastOpts.Fields[0] != "icp" {
		t.Fatalf("Search 存在性探测应只用 icp 字段, got %+v", fake.lastOpts)
	}

	detail, err := p.Detail(context.Background(), "小米科技")
	if err != nil {
		t.Fatalf("Detail 失败: %v", err)
	}
	if len(detail.Domains) != 1 || detail.Domains[0].Domain != "mi.com" {
		t.Fatalf("Detail 域名 = %+v（空域名应被跳过）", detail.Domains)
	}
	if detail.Domains[0].ICP != "京ICP备12345号" {
		t.Errorf("ICP 号 = %q", detail.Domains[0].ICP)
	}
}

func TestENScanProviderSearchErrorPropagates(t *testing.T) {
	fake := &fakeENSQuerier{available: true, err: context.DeadlineExceeded}
	p := &ENScanProvider{client: fake}
	if _, err := p.Search(context.Background(), "x", 1); err == nil {
		t.Fatal("查询错误应上抛，让调用方记 warning")
	}
}

func TestENScanProviderDigitalAssets(t *testing.T) {
	fake := &fakeENSQuerier{available: true, result: fakeENResult()}
	p := &ENScanProvider{client: fake}

	hits, more, err := p.DigitalAssets(context.Background(), "小米科技", 1, 100)
	if err != nil {
		t.Fatalf("DigitalAssets 失败: %v", err)
	}
	if more {
		t.Fatal("enscan 无分页，more 应为 false")
	}

	kinds := map[string]int{}
	for _, h := range hits {
		kinds[h.Kind]++
		if h.EntityName != "小米科技" || h.Company != "小米科技" {
			t.Errorf("归属企业未回填: %+v", h)
		}
	}
	// app/miniapp/official_account/newmedia 各 1 条；空名条目被跳过。
	if kinds["app"] != 1 || kinds["miniapp"] != 1 || kinds["official_account"] != 1 || kinds["newmedia"] != 1 {
		t.Fatalf("kind 分布不符: %+v（共 %d 条）", kinds, len(hits))
	}

	byKind := map[string]string{}
	for _, h := range hits {
		byKind[h.Kind] = h.Platform
	}
	if byKind["newmedia"] != "微博" || byKind["miniapp"] != "微信小程序" || byKind["official_account"] != "微信公众号" {
		t.Fatalf("平台名不符: %+v", byKind)
	}

	// 第二页应为空（无分页协议）。
	hits2, _, err := p.DigitalAssets(context.Background(), "小米科技", 2, 10)
	if err != nil || len(hits2) != 0 {
		t.Fatalf("page=2 应返回空且不报错: %v %v", hits2, err)
	}

	// size 截断。
	hits3, _, _ := p.DigitalAssets(context.Background(), "小米科技", 1, 2)
	if len(hits3) != 2 {
		t.Fatalf("size 截断失效: %d", len(hits3))
	}
}

func TestENScanProviderBranchesInvestmentsUnsupported(t *testing.T) {
	p := &ENScanProvider{client: &fakeENSQuerier{available: true}}
	if _, _, err := p.Branches(context.Background(), "x", 1, 10); err == nil {
		t.Fatal("Branches 应明确报不支持（BFS 依赖错误信号记日志）")
	}
	if _, _, err := p.Investments(context.Background(), "x", 1, 10); err == nil {
		t.Fatal("Investments 应明确报不支持")
	}
}

func TestNewENScanProviderRequiresBinary(t *testing.T) {
	// 本机 tools/linux/enscan 存在时应构造成功；缺失时应返回会话缺失类错误。
	p, err := NewENScanProvider()
	if err != nil {
		if !IsSessionMissing(err) {
			t.Fatalf("二进制缺失应返回 SessionMissing 类错误, got %v", err)
		}
		t.Log("enscan 二进制不可用（CI 环境）:", err)
		return
	}
	if p.Name() != "enscan" {
		t.Fatalf("Name = %q", p.Name())
	}
}

func TestENScanProviderImplementsDigitalAssets(t *testing.T) {
	p := &ENScanProvider{client: &fakeENSQuerier{available: true}}
	var _ Provider = p
	if _, ok := interface{}(p).(DigitalAssetsProvider); !ok {
		t.Fatal("ENScanProvider 必须满足 DigitalAssetsProvider（数字采集靠类型断言探测）")
	}
}

package test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
)

// ENScan 数字资产采集 live 校准（ENSCAN_LIVE=1 且 enscan 二进制 + config.yaml
// Cookie 就绪时跑）：验证 Provider 全链路与真实字段形状，为解析别名表校准。
// 无 Cookie 时上游拒绝，本测试只断言「明确报错/空结果」，不断言数据内容。
func TestENScanProviderLive(t *testing.T) {
	if os.Getenv("ENSCAN_LIVE") == "" {
		t.Skip("跳过：未设置 ENSCAN_LIVE")
	}
	p, err := enterprise.NewENScanProvider()
	if err != nil {
		t.Skip("跳过：" + err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	keyword := os.Getenv("ENSCAN_LIVE_COMPANY")
	if keyword == "" {
		keyword = "小米科技有限责任公司"
	}

	refs, err := p.Search(ctx, keyword, 1)
	if err != nil {
		t.Logf("检索失败（无 Cookie 时预期）: %v", err)
		return
	}
	if len(refs) == 0 {
		t.Fatal("Search 应至少返回一条引用")
	}

	hits, _, err := p.DigitalAssets(ctx, refs[0].ExtID, 1, 100)
	if err != nil {
		t.Logf("数字资产拉取失败（无 Cookie 时预期）: %v", err)
		return
	}
	kinds := map[string]int{}
	for _, h := range hits {
		kinds[h.Kind]++
		t.Logf("[%s] %s @%s", h.Kind, h.Name, h.Platform)
	}
	t.Logf("共 %d 条数字资产: %+v", len(hits), kinds)

	domains, _, err := p.Domains(ctx, refs[0].ExtID, 1, 50)
	if err != nil {
		t.Logf("ICP 拉取失败（无 Cookie 时预期）: %v", err)
		return
	}
	for _, d := range domains {
		t.Logf("[icp] %s (%s) %s", d.Domain, d.Site, d.ICP)
	}
}

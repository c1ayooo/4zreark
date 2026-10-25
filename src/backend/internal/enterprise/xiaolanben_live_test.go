package enterprise

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestXiaolanbenDigitalLive 实测小蓝本登录 + 搜索 + 数字资产采集
// （需 XLB_USER / XLB_PASS 环境变量；本机需有 chrome）。
// 同时输出详情页 companyDetail 的字段形状图，供 parseXlbDigitalAssets 归类表 live 校准。
func TestXiaolanbenDigitalLive(t *testing.T) {
	user, pass := os.Getenv("XLB_USER"), os.Getenv("XLB_PASS")
	if user == "" || pass == "" {
		t.Skip("未设置 XLB_USER / XLB_PASS")
	}
	// XLB_EID 直接指定企业（校准指定公司形状用）；否则按关键词搜索取第一家。
	keyword, eid := os.Getenv("XLB_KEYWORD"), os.Getenv("XLB_EID")
	pAny, err := NewXiaolanbenProvider(user, pass, "")
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}
	p := pAny.(*xiaolanbenProvider)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	if eid == "" {
		if keyword == "" {
			keyword = "腾讯"
		}
		// 登录在首次查询时惰性触发（浏览器签名通道）。
		refs, err := p.Search(ctx, keyword, 3)
		if err != nil {
			t.Fatalf("搜索（含登录）失败: %v", err)
		}
		t.Logf("登录+搜索 OK：token 长度 %d，返回 %d 条", len(p.token), len(refs))
		for _, r := range refs {
			t.Logf("  企业: %s | eid=%s", r.Name, r.ExtID)
		}
		if len(refs) == 0 {
			t.Fatal("搜索无结果，无法继续")
		}
		eid = refs[0].ExtID
	} else {
		t.Logf("指定 eid=%s", eid)
	}

	hits, more, err := p.DigitalAssets(ctx, eid, 1, 100)
	if err != nil {
		t.Fatalf("数字资产拉取失败: %v", err)
	}
	t.Logf("数字资产 %d 条（more=%v）", len(hits), more)
	for i, h := range hits {
		if i >= 30 {
			t.Logf("  ... 其余 %d 条略", len(hits)-30)
			break
		}
		t.Logf("  [%s] %s | 平台=%s | 归属=%s | 证据=%s", h.Kind, h.Name, h.Platform, h.EntityName, h.Evidence)
	}

	// companyDetail 字段形状图（只输出键名/类型/长度，不输出值），
	// 与 parseXlbDigitalAssets 的 classifyXlbKey 对照，发现漏归类的键在这里看。
	page, err := p.xlbSignPage(ctx)
	if err != nil {
		t.Fatalf("签名页不可用: %v", err)
	}
	if err := page.Navigate("https://sou.xiaolanben.com/company/" + eid); err != nil {
		t.Fatalf("详情页导航失败: %v", err)
	}
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond)
	res, err := page.Eval(`() => {
		const cd = (window.__INITIAL_STATE__||{}).companyDetail||{};
		const out = {};
		for (const k of Object.keys(cd)) {
			const v = cd[k];
			if (Array.isArray(v)) {
				out[k] = 'array(' + v.length + ')' + (v.length && typeof v[0]==='object' && v[0] ? '{' + Object.keys(v[0]).join(',') + '}' : '');
			} else if (v && typeof v === 'object') {
				out[k] = 'obj{' + Object.keys(v).slice(0,15).join(',') + '}';
			} else {
				out[k] = typeof v;
			}
		}
		return JSON.stringify(out);
	}`)
	if err != nil {
		t.Logf("形状探测失败: %v", err)
	} else {
		t.Logf("companyDetail 字段形状: %s", res.Value.String())
	}
}

// TestXiaolanbenTabProbe 抓取企业详情页各 tab（APP/小程序/公众号/新媒体）触发的 XHR 接口，
// 供固化为 provider 的数字资产接口（需 XLB_USER / XLB_PASS / XLB_EID）。
func TestXiaolanbenTabProbe(t *testing.T) {
	user, pass, eid := os.Getenv("XLB_USER"), os.Getenv("XLB_PASS"), os.Getenv("XLB_EID")
	if user == "" || pass == "" || eid == "" {
		t.Skip("未设置 XLB_USER / XLB_PASS / XLB_EID")
	}
	pAny, err := NewXiaolanbenProvider(user, pass, "")
	if err != nil {
		t.Fatalf("构造 provider 失败: %v", err)
	}
	p := pAny.(*xiaolanbenProvider)
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()

	page, err := p.xlbSignPage(ctx)
	if err != nil {
		t.Fatalf("签名页不可用: %v", err)
	}
	if err := page.Navigate("https://sou.xiaolanben.com/company/" + eid); err != nil {
		t.Fatalf("详情页导航失败: %v", err)
	}
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond)

	res, err := page.Eval(`() => new Promise((resolve) => {
		const urls = [];
		const origOpen = XMLHttpRequest.prototype.open;
		XMLHttpRequest.prototype.open = function(m, u) {
			try { urls.push(m + ' ' + String(u)); } catch (e) {}
			return origOpen.apply(this, arguments);
		};
		const texts = ['APP', '应用', '小程序', '公众号', '新媒体', '产品信息', '微博'];
		const clicked = [];
		const els = [...document.querySelectorAll('div,span,li,button,a')]
			.filter(e => {
				const t = (e.innerText || '').trim();
				return t && t.length <= 8 && texts.some(x => t.includes(x)) && e.children.length <= 1;
			});
		els.slice(0, 30).forEach(e => { clicked.push((e.innerText||'').trim()); try { e.click(); } catch (x) {} });
		setTimeout(() => resolve(JSON.stringify({ clicked: clicked, xhrs: [...new Set(urls)] })), 8000);
	})`)
	if err != nil {
		t.Fatalf("tab 探测失败: %v", err)
	}
	t.Logf("探测结果: %s", res.Value.String())
}

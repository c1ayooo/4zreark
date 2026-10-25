package enterprise

import (
	"os"
	"testing"
	"time"
)

// TestQRLoginLive 实测各源扫码登录的 Begin/Poll（需本机 chrome，QR_LIVE=1 门控）。
// 校准点：登录页可达、二维码定位截图成功、poll 返回 waiting。
// confirmed 路径（真实扫码）由用户首次扫码时验证。
func TestQRLoginLive(t *testing.T) {
	if os.Getenv("QR_LIVE") == "" {
		t.Skip("未设置 QR_LIVE=1")
	}
	for _, provider := range []string{"tyc", "aqc", "qcc"} {
		if _, ok := QRLoginConfigs[provider]; !ok {
			continue
		}
		res, err := QRLogin.Begin(provider, "")
		if err != nil {
			t.Logf("[%s] FAIL: %v", provider, err)
			continue
		}
		t.Logf("[%s] OK: session=%s qr=%d bytes login=%s", provider, res.SessionID, len(res.QRImage), QRLoginConfigs[provider].LoginURL)
		status, cookie, _, err := QRLogin.Poll(provider, res.SessionID)
		t.Logf("[%s] poll → status=%s cookie_len=%d err=%v", provider, status, len(cookie), err)
		QRLogin.Cancel(provider, res.SessionID)
	}
}

// TestQRLoginPollFresh 验证 waiting 轮询返回最新二维码（QR_FRESH=1 门控）。
func TestQRLoginPollFresh(t *testing.T) {
	if os.Getenv("QR_FRESH") == "" {
		t.Skip("未设置 QR_FRESH=1")
	}
	provider := os.Getenv("QR_FRESH_PROVIDER")
	if provider == "" {
		provider = "aqc"
	}
	res, err := QRLogin.Begin(provider, "")
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	defer QRLogin.Cancel(provider, res.SessionID)
	imgs := map[string]bool{}
	for i := 0; i < 3; i++ {
		time.Sleep(3 * time.Second)
		status, cookie, img, err := QRLogin.Poll(provider, res.SessionID)
		if err != nil {
			t.Fatalf("poll err: %v", err)
		}
		imgs[img] = true
		t.Logf("poll#%d status=%s cookie=%d img_len=%d", i+1, status, len(cookie), len(img))
	}
	t.Logf("不同图片数: %d（>1 说明二维码在轮询中自动刷新）", len(imgs))
}

// TestQRLoginProbeDOM 探测登录页 DOM 里的二维码候选元素（选择器校准用；QR_PROBE=1 门控）。
func TestQRLoginProbeDOM(t *testing.T) {
	if os.Getenv("QR_PROBE") == "" {
		t.Skip("未设置 QR_PROBE=1")
	}
	provider := os.Getenv("QR_PROBE_PROVIDER")
	if provider == "" {
		provider = "tyc"
	}
	if _, ok := QRLoginConfigs[provider]; !ok {
		t.Fatalf("未知 provider %s", provider)
	}
	res, err := QRLogin.Begin(provider, "")
	if err != nil {
		t.Fatalf("[%s] Begin 失败: %v", provider, err)
	}
	defer QRLogin.Cancel(provider, res.SessionID)

	QRLogin.mu.Lock()
	s := QRLogin.items[res.SessionID]
	QRLogin.mu.Unlock()
	if s == nil {
		t.Fatal("会话不存在")
	}
	out, err := s.Page.Eval(`() => JSON.stringify({
		url: location.href,
		title: document.title,
		imgs: [...document.querySelectorAll('img')].map(i => ({
			src: (i.getAttribute('src')||'').slice(0,80),
			cls: i.className && String(i.className).slice(0,40),
			w: i.naturalWidth, h: i.naturalHeight, vis: i.offsetWidth + 'x' + i.offsetHeight
		})).filter(x => x.vis !== '0x0').slice(0, 20),
		iframes: [...document.querySelectorAll('iframe')].map(f => ({src: (f.getAttribute('src')||'').slice(0,100)})),
		canvases: [...document.querySelectorAll('canvas')].length
	})`)
	if err != nil {
		t.Fatalf("DOM 探测失败: %v", err)
	}
	t.Logf("[%s] DOM: %s", provider, out.Value.String())
}

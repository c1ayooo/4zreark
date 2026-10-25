package enterprise

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/browser"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// 平台内扫码登录（无头浏览器托管形态）：服务端 rod 打开上游登录页 → 截取二维码
// 推给平台 UI → 用户手机扫码确认 → 服务端经 CDP 捕获登录成功（URL 跳走 / 成功 Cookie
// 出现）→ 抓全量 Cookie 拼串返回，由调用方落 datasource_sessions。
// 复用小蓝本通道的浏览器基建（FindChrome / headless=old 防风控）。

// QRLoginConfig 每源扫码登录配置。选择器/判据经 2026-10-26 live 校准固化（派单 20261026-03）。
type QRLoginConfig struct {
	LoginURL      string   // 登录页地址
	QRAliases     []string // 二维码候选选择器（合并一次查询；img/canvas/iframe 均可，截图按元素盒）
	SuccessCookie string   // 出现即视为登录成功的 Cookie 名（空 = 仅靠 URL 判据）
	LoginMarker   string   // URL 含此子串表示仍在登录页（跳走即成功）
	ScanHint      string   // 扫码用哪个 APP 的提示
}

// QRLoginConfigs 已接入扫码登录的数据源。
// 校准记录：tyc QR 解码为 m.tianyancha.com/xcxcode/login（canvas）；
// qcc QR 解码为 qichacha.com/qrcode_login（canvas；QCCSESSID 匿名也有，成功只认 URL 离开 /weblogin）；
// aqc 登录走百度 passport（img.tang-pass-qrcode-img 138x138，成功认 BDUSS）。
var QRLoginConfigs = map[string]QRLoginConfig{
	"tyc": {
		LoginURL:      "https://www.tianyancha.com/login",
		QRAliases:     []string{"canvas", "img.qrcode", "img[src*='qrcode']", "iframe[src*='open.weixin.qq.com']"},
		SuccessCookie: "auth_token",
		LoginMarker:   "login",
		ScanHint:      "天眼查 APP / 微信小程序",
	},
	"aqc": {
		LoginURL:      "https://passport.baidu.com/v2/?login&u=https%3A%2F%2Faiqicha.baidu.com%2F",
		QRAliases:     []string{"img.tang-pass-qrcode-img", "img[src*='qrcode']", "canvas"},
		SuccessCookie: "BDUSS",
		LoginMarker:   "passport.baidu.com",
		ScanHint:      "百度 APP / 爱企查 APP",
	},
	"qcc": {
		LoginURL:      "https://www.qcc.com/web/user/login",
		QRAliases:     []string{"canvas", "img[src*='qrcode']"},
		SuccessCookie: "",
		LoginMarker:   "weblogin",
		ScanHint:      "微信 / 企查查 APP",
	},
}

// qrSessionTTL 单次扫码会话存活时长（上游二维码一般 1-5 分钟失效）。
const qrSessionTTL = 5 * time.Minute

// qrSession 一次扫码登录的浏览器会话。
type qrSession struct {
	Provider string
	Browser  *rod.Browser
	Page     *rod.Page
	Started  time.Time
}

// QRSessionManager 扫码会话管理（进程级单例）。
type QRSessionManager struct {
	mu    sync.Mutex
	items map[string]*qrSession
}

// QRLogin 进程级扫码会话管理器。
var QRLogin = &QRSessionManager{items: map[string]*qrSession{}}

// QRBeginResult Begin 的返回：会话 ID + 二维码 dataURL + 扫码提示。
type QRBeginResult struct {
	SessionID string `json:"session_id"`
	QRImage   string `json:"qr_image"` // data:image/png;base64,…
	ExpiresAt string `json:"expires_at"`
	ScanHint  string `json:"scan_hint"`
}

// Begin 打开登录页并截取二维码。同源旧会话先关闭（每源同时只留一个）。
func (m *QRSessionManager) Begin(provider, proxyURL string) (*QRBeginResult, error) {
	cfg, ok := QRLoginConfigs[provider]
	if !ok {
		return nil, fmt.Errorf("数据源 %s 暂不支持扫码登录（当前支持：tyc/aqc/qcc）", provider)
	}
	bin := browser.FindChrome()
	if bin == "" {
		return nil, fmt.Errorf("未找到 chrome/chromium，扫码登录不可用；可改用手动粘贴 Cookie")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// 关掉同源旧会话
	for id, s := range m.items {
		if s.Provider == provider {
			s.closeLocked()
			delete(m.items, id)
		}
	}

	l := launcher.New().Bin(bin).Set("no-sandbox").Set("disable-gpu").
		Set("ignore-certificate-errors").Set("disable-blink-features", "AutomationControlled").
		Set("headless", "old")
	if strings.TrimSpace(proxyURL) != "" {
		l = l.Proxy(proxyURL)
	} else {
		l = l.Set("no-proxy-server") // 平台进程可能被注入 HTTP(S)_PROXY，浏览器继承后会超时
	}
	u, err := l.Launch()
	if err != nil {
		return nil, fmt.Errorf("浏览器启动失败: %w", err)
	}
	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		return nil, fmt.Errorf("浏览器连接失败: %w", err)
	}
	page, err := b.Page(proto.TargetCreateTarget{URL: cfg.LoginURL})
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("登录页打开失败: %w", err)
	}
	// 全局操作超时：rod 的 Elements/Cookies 等是等待型查询，不设超时会永远阻塞。
	page = page.Timeout(45 * time.Second)
	if err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{UserAgent: xlbUA}); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("设置 UA 失败: %w", err)
	}
	if err := page.WaitLoad(); err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("登录页加载失败: %w", err)
	}

	// 等二维码渲染（微信 OAuth 类是 iframe，稍慢；Elements 自带等待）
	qrEl, err := m.findQR(page, cfg.QRAliases)
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	png, err := qrEl.Screenshot(proto.PageCaptureScreenshotFormatPng, 0)
	if err != nil {
		_ = b.Close()
		return nil, fmt.Errorf("二维码截图失败: %w", err)
	}

	id, err := randomQRToken()
	if err != nil {
		_ = b.Close()
		return nil, err
	}
	s := &qrSession{Provider: provider, Browser: b, Page: page, Started: time.Now()}
	m.items[id] = s
	expiry := time.Now().Add(qrSessionTTL)
	time.AfterFunc(qrSessionTTL, func() { m.expire(id) })

	return &QRBeginResult{
		SessionID: id,
		QRImage:   "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		ExpiresAt: expiry.Format(time.RFC3339),
		ScanHint:  cfg.ScanHint,
	}, nil
}

// QRStatus 扫码会话状态。
// waiting：继续轮询；confirmed：登录成功（Cookie 已返回）；expired：会话/二维码过期；error：失败。
func (m *QRSessionManager) Poll(provider, sessionID string) (status, cookie string, err error) {
	m.mu.Lock()
	s, ok := m.items[sessionID]
	if !ok {
		m.mu.Unlock()
		return "expired", "", nil
	}
	if s.Provider != provider {
		m.mu.Unlock()
		return "error", "", fmt.Errorf("会话与数据源不匹配")
	}
	if time.Since(s.Started) > qrSessionTTL {
		s.closeLocked()
		delete(m.items, sessionID)
		m.mu.Unlock()
		return "expired", "", nil
	}
	cfg := QRLoginConfigs[provider]
	info, ierr := s.Page.Info()
	// 当前页 Cookie：登录成功后发生跳转，当前页的适用 Cookie 同时覆盖
	// 上游会话与父域会话（如 BDUSS），比按登录 URL 过滤更完整。
	cookies, cerr := s.Page.Cookies(nil)
	m.mu.Unlock()

	if ierr != nil || cerr != nil {
		m.expire(sessionID)
		return "expired", "", nil
	}

	cookieMap := map[string]string{}
	for _, c := range cookies {
		cookieMap[c.Name] = c.Value
	}
	// 判据一：成功 Cookie 出现；判据二（兜底）：页面从登录页跳走。
	urlLeft := cfg.LoginMarker != "" && info != nil && !strings.Contains(info.URL, cfg.LoginMarker)
	if (cfg.SuccessCookie != "" && cookieMap[cfg.SuccessCookie] != "") || urlLeft {
		var parts []string
		for _, c := range cookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		m.expire(sessionID)
		return "confirmed", strings.Join(parts, "; "), nil
	}
	return "waiting", "", nil
}

// Cancel 关闭并移除扫码会话。
func (m *QRSessionManager) Cancel(provider, sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.items[sessionID]
	if !ok || s.Provider != provider {
		return false
	}
	s.closeLocked()
	delete(m.items, sessionID)
	return true
}

func (m *QRSessionManager) expire(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.items[sessionID]; ok {
		s.closeLocked()
		delete(m.items, sessionID)
	}
}

// findQR 合并选择器一次性查询（Elements 自带等待，受页面超时约束），
// 返回可见且尺寸合理的二维码元素。
func (m *QRSessionManager) findQR(page *rod.Page, aliases []string) (*rod.Element, error) {
	els, err := page.Elements(strings.Join(aliases, ", "))
	if err != nil {
		return nil, fmt.Errorf("登录页未找到二维码（上游可能改版或触发验证）；请改用手动粘贴 Cookie")
	}
	for _, el := range els {
		shape, serr := el.Shape()
		if serr != nil || shape == nil || len(shape.Quads) == 0 {
			continue
		}
		// Quad: [左上x,左上y, 右上x,右上y, 右下x,右下y, 左下x,左下y]
		q := shape.Quads[0]
		w := q[2] - q[0]
		h := q[7] - q[1]
		// 二维码典型 80-400px；太小是图标，太大是整页
		if w >= 80 && w <= 420 && h >= 80 && h <= 420 {
			return el, nil
		}
	}
	return nil, fmt.Errorf("登录页二维码尺寸异常（上游可能改版）；请改用手动粘贴 Cookie")
}

func (s *qrSession) closeLocked() {
	if s.Page != nil {
		_ = s.Page.Close()
	}
	if s.Browser != nil {
		_ = s.Browser.Close()
	}
}

func randomQRToken() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "qr" + hex.EncodeToString(b), nil
}

// QRLoginSupported 数据源是否支持扫码（设置页展示用）。
func QRLoginSupported(provider string) bool {
	_, ok := QRLoginConfigs[provider]
	return ok
}

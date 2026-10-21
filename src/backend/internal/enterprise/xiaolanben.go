package enterprise

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

// xiaolanbenProvider 小蓝本（xiaolanben.com 获客系统）适配器。
// 认证：账号密码登录走 usercenter-gateway /api/v2/web/login，username/password
// 均按「RSA-PKCS1v15(base64(明文))」双层加密（对照前端 Dr.encrypt：O→UTF8字节流,
// V→base64编码, i→RSA 公钥加密，公钥 e=0x10001, n=8b4b…772）。
// 登录接口不强制 md 验签（md=undefined 即可），返回 token（30 天有效）+ login-id（HttpOnly）。
// 业务接口（bluebook 网关）服务端强校验 h_sign 动态签名（绑定时间戳+会话密钥，
// 混淆于前端 webpack 闭包），纯服务端 HTTP 无法复现——由 Go 内嵌无头 Chrome
// （xiaolanben_browser.go，rod）承载登录态与签名：登录接口 token 种 cookie 后，
// 页面内 XHR 由前端 hook 自动注入合法 h_sign。
type xiaolanbenProvider struct {
	c        *webClient
	username string
	password string
	proxyURL string
	token    string
	userID   string
	loginID  string
}

// xlbBase 用户中心网关前缀（登录接口）。
const xlbBase = "https://web.xiaolanben.com/api.xiaolanben.com"

// xlbRSAN 小蓝本登录加密公钥模数（hex），取自前端登录 bundle me()。
const xlbRSAN = "8b4b2b43c0510e47ccd94fde841a9b200ba371bf1e0b9b9e5d23cba68e33f6d6b51951d9fd00b740132357c45e9b039346240c0f344f793ea6634507c5c9fa1ffc9c2e7288e2a7341995d446f9d5d5fea772aa2195a7c093441646a3531e6a28f9d647165d47262ed6c6814d3f81ae442dd11029553f0d2158f34e596016ec85"

// xlbUA 浏览器 UA（上游按 UA 风控，必须真实 Chrome UA）。
const xlbUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

func NewXiaolanbenProvider(username, password, proxyURL string) (Provider, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, SessionMissing("小蓝本会话未配置：请在企业数据源中填写账号与密码")
	}
	// 构造时不调上游登录接口（避免每次工具调用触发上游限流/风控），
	// token 在首次查询时惰性获取（xlbSignPage → p.ensureLoggedIn）。
	// 凭据错误会在首次查询时报「登录失败」，不会在配置/测试环节产生额外上游调用。
	p := &xiaolanbenProvider{username: username, password: password, proxyURL: proxyURL}
	return p, nil
}

func (p *xiaolanbenProvider) Name() string { return "xiaolanben" }

// encryptXLB 前端加密链路：RSA-PKCS1v15(base64(utf8(明文)))，输出 hex。
func encryptXLB(plain string) (string, error) {
	n := new(big.Int)
	if _, ok := n.SetString(xlbRSAN, 16); !ok {
		return "", fmt.Errorf("小蓝本公钥模数解析失败")
	}
	e := 0x10001
	b64 := base64.StdEncoding.EncodeToString([]byte(plain))
	k := (n.BitLen() + 7) / 8
	data := []byte(b64)
	if len(data) > k-11 {
		return "", fmt.Errorf("小蓝本加密明文过长")
	}
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x02
	ps := em[2 : k-len(data)-1]
	seed := make([]byte, len(ps))
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	for i := range ps {
		ps[i] = seed[i]
		for ps[i] == 0 {
			r := make([]byte, 1)
			if _, err := rand.Read(r); err != nil {
				return "", err
			}
			ps[i] = r[0]
		}
	}
	em[k-len(data)-1] = 0x00
	copy(em[k-len(data):], data)
	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, big.NewInt(int64(e)), n)
	out := c.Bytes()
	if len(out) < k {
		pad := make([]byte, k-len(out))
		out = append(pad, out...)
	}
	return hex.EncodeToString(out), nil
}

// login 调用 usercenter-gateway /api/v2/web/login，校验凭据并持有 token + login-id。
// webClient 惰性创建（构造时不建，避免无谓对象）。
func (p *xiaolanbenProvider) login(ctx context.Context, username, password string) error {
	if p.c == nil {
		c, err := newWebClient(xlbBase, p.proxyURL, 30*time.Second)
		if err != nil {
			return err
		}
		c.headers["Referer"] = "https://www.xiaolanben.com/login"
		c.headers["Origin"] = "https://www.xiaolanben.com"
		p.c = c
	}
	ue, err := encryptXLB(username)
	if err != nil {
		return err
	}
	pe, err := encryptXLB(password)
	if err != nil {
		return err
	}
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, ue, pe)
	qs := "?big_app_id=35&app_id=2026&plat=4&md=undefined&channel=xlb-pc-none"
	uri := xlbBase + "/usercenter-gateway/api/v2/web/login" + qs
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, strings.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range p.c.headers {
		if strings.EqualFold(k, "Cookie") {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	resp, err := p.c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, webBodyLimit))
	raw := string(data)
	// 从 Set-Cookie 提取 login-id（业务接口会话标识，HttpOnly）
	for _, c := range resp.Cookies() {
		if c.Name == "login-id" && c.Value != "" {
			p.loginID = c.Value
		}
	}
	if strings.Contains(raw, `"errors"`) {
		msg := gjson.Get(raw, "errors.0.message").String()
		if msg == "" {
			msg = raw
		}
		return fmt.Errorf("小蓝本登录失败：%s", strings.TrimSpace(msg))
	}
	token := gjson.Get(raw, "token").String()
	if token == "" {
		return fmt.Errorf("小蓝本登录失败：响应无 token")
	}
	p.token = token
	p.userID = gjson.Get(raw, "userId").String()
	return nil
}

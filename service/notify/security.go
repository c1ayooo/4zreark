package notify

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// 自定义 Webhook 的 SSRF 防护：默认只允许公网地址，避免把通知发到
// 127.0.0.1 / 内网 / 云元数据地址。内部部署可用 ZRE_NOTIFY_ALLOW_PRIVATE=1 放行。
func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("webhook 地址无效")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook 只支持 http/https")
	}
	if os.Getenv("ZRE_NOTIFY_ALLOW_PRIVATE") == "1" {
		return nil
	}
	host := u.Hostname()
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return fmt.Errorf("webhook 域名解析失败: %w", err)
		}
		for _, a := range resolved {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return fmt.Errorf("webhook 域名没有可用地址")
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("webhook 地址指向内网/保留地址，已拒绝（如为内部服务请设置 ZRE_NOTIFY_ALLOW_PRIVATE=1）")
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

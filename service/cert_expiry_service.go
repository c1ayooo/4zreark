package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/notify"
)

// CertExpiryService 证书到期检测循环：每天扫一遍 sites.cert_not_after，
// 7 天内到期发 critical、30 天内发 warning。提醒按站点去重（24 小时内
// 不重复发），事件照落（cert_expiry），前端时间线与 IM 渠道都能看到。
type CertExpiryService struct {
	notify *notify.NotifyManager
	stopCh chan struct{}
	stopMu sync.Mutex
}

// NewCertExpiryService 创建证书到期检测服务。
func NewCertExpiryService() *CertExpiryService {
	return &CertExpiryService{
		notify: notify.GetGlobalManager(),
		stopCh: make(chan struct{}),
	}
}

// Start 启动每日检测循环。启动延迟 11 分钟（错开 discovery 5 分钟 / site watch 7 分钟）。
func (s *CertExpiryService) Start() {
	go func() {
		select {
		case <-time.After(11 * time.Minute):
		case <-s.stopCh:
			return
		}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			checked, alerted, err := s.RunOnce(ctx)
			cancel()
			if err != nil {
				log.Printf("[CertExpiry] 检测失败: %v", err)
			} else if alerted > 0 {
				log.Printf("[CertExpiry] 本轮完成: 扫描 %d 个到期证书，发送 %d 条提醒", checked, alerted)
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()
}

// Stop 停止循环。
func (s *CertExpiryService) Stop() {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

// RunOnce 执行一轮检测，返回（扫描数, 发送提醒数）。
func (s *CertExpiryService) RunOnce(ctx context.Context) (int, int, error) {
	assets := repo.NewAssetRepo()
	sites, err := assets.ListExpiringCerts(ctx, certExpiryWarnDays, 500)
	if err != nil {
		return 0, 0, err
	}
	alerted := 0
	for _, site := range sites {
		select {
		case <-ctx.Done():
			return len(sites), alerted, ctx.Err()
		default:
		}
		// 去重：同站点 24 小时内提醒过就跳过（事件与通知都不再发）。
		if last, err := assets.LastCertExpiryEventAt(ctx, site.SiteID); err == nil && last != nil &&
			time.Since(*last) < 24*time.Hour {
			continue
		}

		level, subject := certExpiryLevel(site.DaysLeft)
		after := map[string]any{
			"days_left":  site.DaysLeft,
			"not_after":  site.CertNotAfter.Format(time.RFC3339),
			"alert_path": "24h",
		}
		if err := assets.InsertEvent(ctx, site.ProjectID, site.SiteID, nil, "cert_expiry",
			subject, map[string]any{}, after); err != nil {
			log.Printf("[CertExpiry] 站点 %d 写入到期事件失败: %v", site.SiteID, err)
			continue
		}

		content := fmt.Sprintf("**资产**: %s\n**证书到期**: %s（剩余 %d 天）\n请及时续期，避免入口不可用。",
			site.Value, site.CertNotAfter.Format("2006-01-02"), site.DaysLeft)
		s.notify.NotifyAssetChangeWithLevel(level, subject, content, map[string]interface{}{
			"link":    fmt.Sprintf("/assets/%d", site.SiteID),
			"site_id": site.SiteID,
		})
		alerted++
	}
	return len(sites), alerted, nil
}

// certExpiryLevel 按剩余天数定级别与事件标题：<=7 天（含已过期）critical，
// <=30 天 warning。
func certExpiryLevel(daysLeft int) (notify.NotifyLevel, string) {
	if daysLeft <= 0 {
		return notify.NotifyLevelCritical, "证书已过期"
	}
	if daysLeft <= certExpiryCriticalDays {
		return notify.NotifyLevelCritical, fmt.Sprintf("证书即将到期（剩余 %d 天）", daysLeft)
	}
	return notify.NotifyLevelWarning, fmt.Sprintf("证书到期提醒（剩余 %d 天）", daysLeft)
}

const (
	certExpiryCriticalDays = 7
	certExpiryWarnDays     = 30
)

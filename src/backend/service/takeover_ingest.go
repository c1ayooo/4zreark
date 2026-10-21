package service

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service/pipeline"
)

// ingestTakeover 把一次子域名接管命中接入资产域与漏洞域。
//
// 接管检测此前只往 scan_results 写一条结果：资产页看不到变更，
// 漏洞列表也不会出现，复核流更无从处理。这里补两条边：
//
//	asset_events  找到对应站点时写一条 takeover 事件（站点不存在则跳过）
//	vulnerabilities  以 template_id=takeover/<service> 幂等落库（status=new，待复核）
//
// 漏洞用唯一索引 (workspace_id, template_id, target) 去重：同一域名同一服务
// 重复扫描只会命中已有记录，不会刷出成堆重复漏洞。
func IngestTakeover(ctx context.Context, task *models.Task, r pipeline.TakeoverResult) {
	if task == nil || !r.Vulnerable {
		return
	}
	host := strings.TrimSpace(r.Domain)
	if host == "" {
		return
	}
	assets := repo.NewAssetRepo()
	if siteID, _, err := assets.SiteIDByHostAny(ctx, host); err == nil && siteID > 0 {
		_ = assets.InsertEvent(ctx, task.ProjectID, siteID, nil, "takeover", "发现子域名接管风险",
			nil, map[string]any{
				"domain":   host,
				"cname":    r.CNAME,
				"provider": r.Service,
				"reason":   r.Reason,
			})
	}

	vuln := &models.Vulnerability{
		WorkspaceID: task.WorkspaceID,
		TaskID:      task.ID,
		Name:        "子域名接管：" + host,
		Description: takeoverDescription(r),
		Severity:    models.VulnSeverityHigh,
		Type:        "subdomain_takeover",
		TemplateID:  takeoverTemplateID(r.Service),
		Target:      host,
		Evidence:    takeoverEvidence(r),
		Solution:    "删除指向已释放服务的 DNS 记录，或在对应云服务上重新认领该域名；确认前不要把域名对外暴露。",
		Scanner:     "takeover_scanner",
		Tags:        []string{"takeover", "dns"},
		CreatedAt:   time.Now(),
	}
	if r.Service != "" {
		vuln.Tags = append(vuln.Tags, strings.ToLower(r.Service))
	}
	if err := NewVulnService().CreateVulnerability(vuln); err != nil {
		// 重复命中走唯一索引，属于正常现象；其余错误只记日志，不影响扫描主流程。
		if !strings.Contains(err.Error(), "已存在") {
			log.Printf("[Takeover] 站点 %s 写入漏洞失败: %v", host, err)
		}
		return
	}
	log.Printf("[Takeover] %s 已沉淀为待复核漏洞（service=%s）", host, r.Service)
}

func takeoverTemplateID(service string) string {
	svc := strings.ToLower(strings.TrimSpace(service))
	if svc == "" {
		return "takeover/dangling-cname"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ".", "-")
	return "takeover/" + replacer.Replace(svc)
}

func takeoverDescription(r pipeline.TakeoverResult) string {
	desc := "子域名 " + r.Domain + " 的 CNAME 指向了一个可被第三方认领的服务"
	if r.Service != "" {
		desc += "（" + r.Service + "）"
	}
	desc += "，攻击者可在该服务上创建同名资源并接管此子域名。"
	if r.Reason != "" {
		desc += "\n判定依据：" + r.Reason
	}
	return desc
}

func takeoverEvidence(r pipeline.TakeoverResult) string {
	parts := []string{
		"subdomain: " + r.Domain,
		"cname: " + r.CNAME,
		"provider: " + r.Service,
		"fingerprints: " + strings.Join(r.Fingerprints, ", "),
		"reason: " + r.Reason,
	}
	return fmt.Sprintf("%s", strings.Join(parts, "\n"))
}

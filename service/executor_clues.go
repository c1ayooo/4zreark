package service

import (
	"context"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/cdnorigin"
	"github.com/c1ayooo/4zreark/internal/recon/cloudassets"
	"github.com/c1ayooo/4zreark/internal/recon/legacyhunter"
	"github.com/c1ayooo/4zreark/internal/recon/saasdetect"
	"github.com/c1ayooo/4zreark/models"
)

// T7：存量线索任务。
//
//	Wayback     历史快照 -> 遗留/EOL 框架端点 + 备份后缀线索
//	CDN 源站    crt.sh SAN + DNS 历史 -> 逐 IP 过 cdnmatch，区分边缘与源站
//	云资源      CNAME -> bucket / distribution / storage account
//	SaaS        域名命中内置 SaaS 规则表
//
// 四类能力互相独立：任一失败只记日志，不拖累其他能力；没有历史记录属于
// 正常空态（Wayback 返回空数组），任务照常完成。

func (e *TaskExecutor) executeClueHunt(parent context.Context, task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing clue hunt for task: %s", task.ID.Hex())
	if len(task.Targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	e.registerRunningTask(task.ID.Hex(), cancel, nil)
	defer e.unregisterRunningTask(task.ID.Hex())

	results := e.runClueHunt(ctx, task)
	e.saveResults(task, results)
	if ctx.Err() != nil {
		return
	}
	if err := e.flushResults(ctx, task.ID.Hex()); err != nil {
		e.failTask(task, jobID, "扫描结果上传失败: "+err.Error())
		return
	}
	e.completeTask(task, jobID, len(results))
	log.Printf("[TaskExecutor] Clue hunt %s finished with %d clue(s)", task.ID.Hex(), len(results))
}

func (e *TaskExecutor) runClueHunt(ctx context.Context, task *models.Task) []models.ScanResult {
	matcher, err := saasdetect.LoadBuiltin()
	if err != nil {
		log.Printf("[TaskExecutor] 加载 SaaS 规则失败，跳过该维度: %v", err)
		matcher = nil
	}

	timeout := time.Duration(task.Config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	probeClient := &http.Client{Timeout: 10 * time.Second}

	results := make([]models.ScanResult, 0)
	total := len(task.Targets)
	for i, raw := range task.Targets {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		domain := baseDomain(raw)
		if domain == "" {
			continue
		}

		targetCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		results = append(results, e.collectClues(targetCtx, task, domain, matcher, probeClient, timeout)...)
		cancel()

		if total > 0 {
			e.updateProgress(task, int(float64(i+1)/float64(total)*100))
		}
	}
	return results
}

func (e *TaskExecutor) collectClues(ctx context.Context, task *models.Task, domain string, matcher *saasdetect.Matcher, probeClient *http.Client, timeout time.Duration) []models.ScanResult {
	out := make([]models.ScanResult, 0, 8)

	// ① SaaS 识别（纯规则，无网络）
	if matcher != nil {
		if m, ok := matcher.Match(domain); ok {
			out = append(out, clueResult(task, domain, "saas", m.ID,
				m.Name+"（"+m.Category+"）", "saas-rules", map[string]interface{}{
					"service_id":   m.ID,
					"service_name": m.Name,
					"label":        m.Label,
					"category":     m.Category,
				}))
		}
	}

	// ② 云资源：CNAME -> 云厂 bucket / distribution / storage account
	if cname, err := net.LookupCNAME(domain); err == nil && cname != "" {
		canonical := strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(canonical, domain) {
			if res, ok := cloudassets.ExtractCNAME(cname); ok {
				out = append(out, clueResult(task, domain, "cloud_asset", res.Name,
					cname, "dns-cname", map[string]interface{}{
						"provider":      res.Provider,
						"resource_kind": res.Kind,
						"cname":         cname,
					}))
			}
		}
	}

	// ③ CDN 源站候选：crt.sh SAN + DNS 历史，逐 IP 过 cdnmatch
	if origins, err := cdnorigin.Find(ctx, domain, cdnorigin.Options{Timeout: timeout}); err != nil {
		log.Printf("[TaskExecutor] CDN origin lookup failed for %s: %v", domain, err)
	} else {
		for _, o := range origins {
			detail := "CDN 边缘节点"
			if !o.IsCDN {
				detail = "源站候选"
			}
			out = append(out, clueResult(task, domain, "cdn_origin", o.IP,
				detail, "crt.sh+dns", map[string]interface{}{
					"ip":       o.IP,
					"is_cdn":   o.IsCDN,
					"evidence": o.Sources,
				}))
		}
	}

	// ④ Wayback 历史端点 + 遗留框架 / 备份后缀
	entries, err := legacyhunter.QueryCDX(ctx, domain, legacyhunter.CDXOptions{Limit: 500, Timeout: timeout})
	if err != nil {
		log.Printf("[TaskExecutor] Wayback CDX failed for %s: %v", domain, err)
		return out
	}
	if len(entries) == 0 {
		return out // 无历史记录是正常空态
	}

	hunter := legacyhunter.New(legacyhunter.Options{
		Domain:       domain,
		MaxEndpoints: 200,
		MaxProbes:    50,
		HTTPClient:   probeClient,
		Timeout:      timeout,
	})
	findings, err := hunter.Run(ctx, entries)
	if err != nil {
		log.Printf("[TaskExecutor] legacy hunter failed for %s: %v", domain, err)
		return out
	}
	if findings == nil {
		return out
	}
	for _, fw := range findings.Frameworks {
		out = append(out, clueResult(task, domain, "legacy_framework", fw.URL,
			fw.Name+"："+fw.Desc, "wayback", map[string]interface{}{
				"framework": fw.Name,
				"cve":       fw.CVE,
				"severity":  fw.Severity,
				"priority":  fw.Priority,
			}))
	}
	for _, ep := range findings.Endpoints {
		out = append(out, clueResult(task, domain, "legacy_endpoint", ep.Path,
			"历史端点（当前不可达）", "wayback", map[string]interface{}{
				"backup_hits": ep.BackupHits,
				"priority":    ep.Priority,
			}))
	}
	return out
}

func clueResult(task *models.Task, domain, kind, value, detail, source string, extra map[string]interface{}) models.ScanResult {
	data := map[string]interface{}{
		"kind":   kind,
		"domain": domain,
		"value":  value,
		"detail": detail,
		"source": source,
	}
	for k, v := range extra {
		data[k] = v
	}
	return models.ScanResult{
		TaskID:      task.ID,
		WorkspaceID: task.WorkspaceID,
		Type:        models.ResultTypeClue,
		Tags:        []string{"clue", kind},
		Project:     task.Name,
		Source:      source,
		Data:        data,
		CreatedAt:   time.Now(),
	}
}

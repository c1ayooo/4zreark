package service

import (
	"strings"

	"github.com/c1ayooo/4zreark/models"
)

// IngestVulnerabilitiesFromResults 把流水线扫描产生的漏洞命中
// （scan_results 里 type=vuln 的条目）同步进 vulnerabilities 复核队列——
// 漏洞页读的是后者，缺了这道流转用户在前端看不到任何扫描发现的漏洞。
// 重复（同模板同目标）静默忽略：任务重跑/多引擎重复发现不产生重复工单。
// 逐条独立处理，单条失败不影响其余。
func IngestVulnerabilitiesFromResults(task *models.Task, results []*models.ScanResult) (int, error) {
	svc := NewVulnService()
	ingested := 0
	var firstErr error
	for _, r := range results {
		if r == nil || r.Type != models.ResultTypeVuln {
			continue
		}
		name, _ := r.Data["name"].(string)
		target, _ := r.Data["target"].(string)
		if name == "" || target == "" {
			continue
		}
		sevStr, _ := r.Data["severity"].(string)
		vuln := &models.Vulnerability{
			WorkspaceID: task.WorkspaceID,
			TaskID:      task.ID,
			Name:        name,
			Description: stringField(r.Data, "description"),
			Severity:    models.VulnSeverity(strings.ToLower(sevStr)),
			Type:        stringField(r.Data, "vuln_type"),
			TemplateID:  stringField(r.Data, "vuln_id"),
			Target:      target,
			Evidence:    stringField(r.Data, "evidence"),
			Solution:    stringField(r.Data, "remediation"),
			Scanner:     r.Source,
		}
		if v, ok := r.Data["vuln_type"].(string); ok && v != "" {
			vuln.Type = v
		} else if strings.Contains(r.Source, "js") {
			vuln.Type = "js_secret"
		} else {
			vuln.Type = "nuclei"
		}
		if ref, ok := r.Data["reference"].(string); ok && strings.TrimSpace(ref) != "" {
			vuln.References = strings.Split(ref, ",")
		}
		if err := svc.CreateVulnerability(vuln); err != nil {
			if strings.Contains(err.Error(), "已存在") {
				continue // 重复发现：静默
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		ingested++
	}
	return ingested, firstErr
}

func stringField(data map[string]interface{}, key string) string {
	v, _ := data[key].(string)
	return strings.TrimSpace(v)
}

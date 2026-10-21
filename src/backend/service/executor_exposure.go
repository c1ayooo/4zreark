package service

import (
	"context"
	"log"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/exposure"
	"github.com/c1ayooo/4zreark/internal/recon/svcid"
	"github.com/c1ayooo/4zreark/models"
)

// T5：两类新任务。
//
//	service_identify（含前端历史值 service_detect）：
//	    对目标端口做真实协议握手（fingerprintx），替代端口号猜服务名。
//	exposure_scan：
//	    先识别协议，再对支持的服务做无凭据暴露面探测（Redis/ES/FTP 等）。
//
// 两者都是独立任务类型：不和流水线的 fingerprint 阶段混在一起，
// 因为它们不需要爬虫/目录扫描，也不产出漏洞，结果分别落 service / exposure。

// defaultProbePorts 是暴露面探测的默认端口集合：
// 覆盖常见匿名暴露服务，不做全端口扫描（成本不可控）。
var defaultProbePorts = []int{
	21, 22, 23, 25, 80, 110, 139, 143, 389, 443,
	445, 636, 873, 1433, 1521, 2181, 2375, 3306, 3389, 5432,
	5601, 5672, 5900, 6379, 6443, 7001, 8080, 8443, 8848, 9000,
	9092, 9200, 9300, 10250, 11211, 27017,
}

// parsePortSpec 解析任务里的 port_range：
// 空值/quick/top100 取默认暴露面端口；支持 "80,443,8000-8010"。
// 非法段落直接跳过，不因为一个笔误让整个任务失败。
func parsePortSpec(spec string) []int {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "quick" || spec == "top100" || spec == "default" {
		out := make([]int, len(defaultProbePorts))
		copy(out, defaultProbePorts)
		return out
	}
	seen := map[int]bool{}
	out := make([]int, 0, 32)
	add := func(p int) {
		if p < 1 || p > 65535 || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a > b {
				continue
			}
			for p := a; p <= b && len(out) < 4096; p++ {
				add(p)
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil {
			add(p)
		}
	}
	sort.Ints(out)
	return out
}

// splitTarget 把任务目标拆成 host + 可选端口。
// 支持 "https://example.com:8443/path"、"example.com:8080"、"10.0.0.1"。
func splitTarget(raw string) (string, int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			port := 0
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			}
			return u.Hostname(), port
		}
	}
	// 去掉没有 scheme 时的路径部分
	if i := strings.IndexAny(raw, "/?#"); i >= 0 {
		raw = raw[:i]
	}
	if host, portStr, err := net.SplitHostPort(raw); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			return host, p
		}
		return host, 0
	}
	return raw, 0
}

// exposureTargetsFromServices 只保留有暴露面探测实现的服务。
// 未知协议（unknown/http/ssh 等）不进入暴露面阶段。
func exposureTargetsFromServices(host string, svcs []svcid.Service) []exposure.Target {
	out := make([]exposure.Target, 0, len(svcs))
	for _, s := range svcs {
		if s.Port <= 0 || !exposure.Supported(s.Protocol) {
			continue
		}
		out = append(out, exposure.Target{Host: host, Port: s.Port, Service: s.Protocol})
	}
	return out
}

func (e *TaskExecutor) probeOptions(task *models.Task) (time.Duration, int) {
	timeout := time.Duration(task.Config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	concurrency := task.Config.Threads
	if concurrency <= 0 {
		concurrency = 32
	}
	return timeout, concurrency
}

// runServiceIdentify 对每个目标做协议识别，返回可直接落库的结果。
func (e *TaskExecutor) runServiceIdentify(ctx context.Context, task *models.Task) []models.ScanResult {
	timeout, concurrency := e.probeOptions(task)
	basePorts := parsePortSpec(task.Config.PortRange)
	results := make([]models.ScanResult, 0)
	total := len(task.Targets)

	for i, raw := range task.Targets {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		host, portHint := splitTarget(raw)
		if host == "" {
			continue
		}
		ports := basePorts
		if portHint > 0 {
			ports = []int{portHint}
		}

		scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		svcs := svcid.Scan(scanCtx, host, ports, svcid.Options{Timeout: timeout, Concurrency: concurrency})
		cancel()

		for _, svc := range svcs {
			if svc.Protocol == "" || strings.EqualFold(svc.Protocol, "unknown") {
				continue
			}
			results = append(results, models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeService,
				Tags:        []string{svc.Protocol},
				Project:     task.Name,
				Source:      "主动扫描",
				Data: map[string]interface{}{
					"target":   raw,
					"host":     host,
					"port":     svc.Port,
					"protocol": svc.Protocol,
					"tls":      svc.TLS,
					"version":  svc.Version,
					"banner":   svc.Banner,
				},
				CreatedAt: time.Now(),
			})
		}
		if total > 0 {
			e.updateProgress(task, int(float64(i+1)/float64(total)*100))
		}
	}
	return results
}

// runExposureScan 先识别服务，再做无凭据暴露面探测。
func (e *TaskExecutor) runExposureScan(ctx context.Context, task *models.Task) []models.ScanResult {
	timeout, concurrency := e.probeOptions(task)
	basePorts := parsePortSpec(task.Config.PortRange)
	results := make([]models.ScanResult, 0)
	total := len(task.Targets)

	for i, raw := range task.Targets {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		host, portHint := splitTarget(raw)
		if host == "" {
			continue
		}
		ports := basePorts
		if portHint > 0 {
			ports = []int{portHint}
		}

		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		svcs := svcid.Scan(scanCtx, host, ports, svcid.Options{Timeout: timeout, Concurrency: concurrency})
		targets := exposureTargetsFromServices(host, svcs)
		findings := exposure.Scan(scanCtx, targets, exposure.Options{Timeout: timeout, Concurrency: concurrency})
		cancel()

		for _, f := range findings {
			results = append(results, models.ScanResult{
				TaskID:      task.ID,
				WorkspaceID: task.WorkspaceID,
				Type:        models.ResultTypeExposure,
				Tags:        []string{"exposure", f.Service},
				Project:     task.Name,
				Source:      "主动扫描",
				Data: map[string]interface{}{
					"target":  raw,
					"host":    f.Host,
					"port":    f.Port,
					"service": f.Service,
					"finding": f.Finding,
					"detail":  f.Detail,
				},
				CreatedAt: time.Now(),
			})
		}
		if total > 0 {
			e.updateProgress(task, int(float64(i+1)/float64(total)*100))
		}
	}
	return results
}

func (e *TaskExecutor) executeServiceIdentify(parent context.Context, task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing service identify for task: %s", task.ID.Hex())
	if len(task.Targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	e.registerRunningTask(task.ID.Hex(), cancel, nil)
	defer e.unregisterRunningTask(task.ID.Hex())

	results := e.runServiceIdentify(ctx, task)
	e.saveResults(task, results)
	if ctx.Err() != nil {
		return
	}
	if err := e.flushResults(ctx, task.ID.Hex()); err != nil {
		e.failTask(task, jobID, "扫描结果上传失败: "+err.Error())
		return
	}
	e.completeTask(task, jobID, len(results))
}

func (e *TaskExecutor) executeExposureScan(parent context.Context, task *models.Task, jobID int64) {
	log.Printf("[TaskExecutor] Executing exposure scan for task: %s", task.ID.Hex())
	if len(task.Targets) == 0 {
		e.failTask(task, jobID, "没有目标")
		return
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	e.registerRunningTask(task.ID.Hex(), cancel, nil)
	defer e.unregisterRunningTask(task.ID.Hex())

	results := e.runExposureScan(ctx, task)
	e.saveResults(task, results)
	if ctx.Err() != nil {
		return
	}
	if err := e.flushResults(ctx, task.ID.Hex()); err != nil {
		e.failTask(task, jobID, "扫描结果上传失败: "+err.Error())
		return
	}
	e.completeTask(task, jobID, len(results))
	if len(results) == 0 {
		log.Printf("[TaskExecutor] Exposure scan %s finished without findings on %v", task.ID.Hex(), task.Targets)
	}
}
